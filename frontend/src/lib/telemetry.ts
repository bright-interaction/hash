// Phase 8.3: signer-side telemetry client.
//
// IntersectionObserver per [data-block-id] block → block.viewed with
// dwell_ms when the block leaves the viewport.
// Scroll → page.scroll at most once per 2 seconds.
// Click on [data-block-id] → interaction.click with tag.
// Pageview → session.start on mount, session.end on beforeunload (via
// navigator.sendBeacon so the request survives navigation).
//
// All events buffer in memory and flush every 5 seconds with fetch(). On
// beforeunload we ship the remainder via sendBeacon. Failed flushes are
// silently dropped: telemetry is best-effort and should never break the
// signing flow.

type Event = {
  kind:
    | 'session.start'
    | 'session.end'
    | 'block.viewed'
    | 'page.scroll'
    | 'interaction.click';
  block_id?: string;
  payload?: Record<string, unknown>;
};

const FLUSH_INTERVAL_MS = 5000;
const SCROLL_THROTTLE_MS = 2000;
const VIEW_THRESHOLD = 0.5;
const MAX_BUFFER = 150;

/**
 * Start instrumentation for a signer page. Returns a stop() function the
 * caller invokes during cleanup; calling stop() flushes any buffered events
 * via sendBeacon, removes listeners, and disconnects the observer.
 *
 * No-ops outside a browser (SSR), so it is safe to call from onMount.
 */
export function startTelemetry(token: string): () => void {
  if (typeof window === 'undefined') {
    return () => {};
  }

  const endpoint = `/sign/${token}/telemetry`;
  const buffer: Event[] = [];
  const sessionStart = Date.now();
  const dwellMap = new Map<Element, number>();
  let flushTimer: number | null = null;
  let lastScrollEmit = 0;
  let stopped = false;

  function push(ev: Event) {
    if (buffer.length >= MAX_BUFFER) {
      // Drop oldest event rather than blocking; we'd rather lose history
      // than freeze the signer page on a slow network.
      buffer.shift();
    }
    buffer.push(ev);
  }

  async function flush() {
    if (buffer.length === 0) return;
    const events = buffer.splice(0, buffer.length);
    try {
      await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events }),
        keepalive: true
      });
    } catch {
      // best-effort, no retry
    }
  }

  function flushOnUnload() {
    push({
      kind: 'session.end',
      payload: { duration_ms: Date.now() - sessionStart }
    });
    if (buffer.length === 0) return;
    try {
      navigator.sendBeacon(
        endpoint,
        new Blob([JSON.stringify({ events: buffer })], { type: 'application/json' })
      );
    } catch {
      // ignore; the page is going away anyway
    }
    buffer.length = 0;
  }

  // session.start, observer + listeners, periodic flush.
  push({ kind: 'session.start' });

  const observer = new IntersectionObserver(
    (entries) => {
      const now = Date.now();
      for (const entry of entries) {
        const el = entry.target;
        const blockId =
          el instanceof HTMLElement ? el.dataset.blockId : undefined;
        if (!blockId) continue;
        if (entry.isIntersecting && entry.intersectionRatio >= VIEW_THRESHOLD) {
          dwellMap.set(el, now);
        } else if (dwellMap.has(el)) {
          const since = dwellMap.get(el) ?? now;
          dwellMap.delete(el);
          push({
            kind: 'block.viewed',
            block_id: blockId,
            payload: { dwell_ms: Math.max(0, now - since) }
          });
        }
      }
    },
    { threshold: [0, VIEW_THRESHOLD, 1] }
  );

  // Defer the observer hookup one microtask so the SvelteKit-rendered HTML
  // has time to mount in the DOM. The signer page injects documentHTML
  // into a container via {@html}; by the time startTelemetry runs in
  // onMount, the markup is present.
  queueMicrotask(() => {
    if (stopped) return;
    document
      .querySelectorAll<HTMLElement>('[data-block-id]')
      .forEach((el) => observer.observe(el));
  });

  const onScroll = () => {
    const now = Date.now();
    if (now - lastScrollEmit < SCROLL_THROTTLE_MS) return;
    lastScrollEmit = now;
    const max = document.documentElement.scrollHeight - window.innerHeight;
    push({
      kind: 'page.scroll',
      payload: {
        scroll_y: window.scrollY,
        scroll_pct: max > 0 ? Math.min(1, window.scrollY / max) : 0
      }
    });
  };

  const onClick = (e: MouseEvent) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    const blockEl = target.closest('[data-block-id]') as HTMLElement | null;
    if (!blockEl?.dataset.blockId) return;
    push({
      kind: 'interaction.click',
      block_id: blockEl.dataset.blockId,
      payload: { tag: target.tagName.toLowerCase() }
    });
  };

  window.addEventListener('scroll', onScroll, { passive: true });
  document.addEventListener('click', onClick);
  window.addEventListener('beforeunload', flushOnUnload);

  flushTimer = window.setInterval(flush, FLUSH_INTERVAL_MS);

  return () => {
    if (stopped) return;
    stopped = true;
    if (flushTimer !== null) {
      clearInterval(flushTimer);
      flushTimer = null;
    }
    observer.disconnect();
    window.removeEventListener('scroll', onScroll);
    document.removeEventListener('click', onClick);
    window.removeEventListener('beforeunload', flushOnUnload);
    flushOnUnload();
  };
}
