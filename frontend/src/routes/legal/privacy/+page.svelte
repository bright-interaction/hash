<svelte:head><title>Privacy Policy · Hash</title></svelte:head>

<p class="page-eyebrow">Legal</p>
<h1>Privacy Policy</h1>
<p class="text-text-muted text-sm mb-2">Last updated: 2026-05-10</p>

<div class="draft-banner">
  <strong>Draft for Swedish-counsel review.</strong> This page describes the actual data practices of
  Hash as operated by Bright Interaction AB. Final wording will be reviewed before paid launch.
</div>

<h2>1. Who we are</h2>
<p>
  Bright Interaction AB ("we", "us", "Hash") is a Swedish company that operates the Hash
  e-signing platform. We are the controller for the personal data we process about you in your
  capacity as a customer or visitor of <code>brightinteraction.com</code>.
</p>
<p>
  When you use Hash to send documents for signature, you (the customer) are the controller of the
  signers' personal data; Bright Interaction is the processor. The Data Processing Agreement (
  <a href="/legal/dpa">/legal/dpa</a>) governs that relationship.
</p>

<h2>2. What we collect</h2>
<h3>From customers (account holders)</h3>
<ul>
  <li>Identity claims from your OIDC provider: email, name, subject identifier;</li>
  <li>API keys you mint (we store the SHA-256 hash, never the plaintext);</li>
  <li>Document and template metadata (names, recipients, status, audit events);</li>
  <li>Server logs (request method, path, status, IP, user-agent), retained 30 days.</li>
</ul>
<h3>From signers (recipients)</h3>
<ul>
  <li>Email and name as supplied by the sender;</li>
  <li>IP and user-agent at view, sign, and decline events (used in the audit certificate);</li>
  <li>The signature image you adopt (typed name + chosen calligraphy font), which is rendered into the
    final PDF along with a SHA-256 hash binding it to that document.</li>
</ul>

<h2>3. Where we host</h2>
<p>
  All Hash infrastructure runs on <strong>Hetzner Online GmbH</strong> in Falkenstein, Germany.
  No data leaves the European Union for any operational purpose. Email delivery uses a self-hosted
  Postal instance on the same infrastructure. There is no Google Analytics, no US-cloud third-party
  trackers, and no AI vendor receiving your document contents.
</p>

<h2>4. Lawful basis</h2>
<ul>
  <li><strong>Account holders:</strong> performance of the contract (Article 6(1)(b) GDPR);</li>
  <li><strong>Signers:</strong> legitimate interest of the sender to execute a contract; the audit
    log is necessary to prove the signature event later;</li>
  <li><strong>Marketing visitors:</strong> consent for any optional analytics, performance of pre-
    contractual measures otherwise.</li>
</ul>

<h2>5. Retention</h2>
<ul>
  <li>Active documents and their audit certificates: as long as you remain a customer;</li>
  <li>After account deletion: 7 years from the document's signed date (typical commercial-contract
    statute of limitations under Swedish law) unless you request earlier deletion;</li>
  <li>Server logs: 30 days;</li>
  <li>Webhook delivery records: 90 days.</li>
</ul>

<h2>6. Your rights</h2>
<p>
  You can request access, correction, deletion, restriction, portability, or to object to processing.
  Email <code>tom@brightinteraction.com</code> with your request. We respond within 30 days.
  You also have the right to lodge a complaint with the Swedish IMY (Integritetsskyddsmyndigheten).
</p>

<h2>7. Sub-processors</h2>
<ul>
  <li><strong>Hetzner Online GmbH</strong> - infrastructure hosting (Falkenstein, DE);</li>
  <li><strong>Cloudflare</strong> - DNS and DDoS protection only; document content never traverses
    Cloudflare;</li>
  <li><strong>The QTSP you select</strong> for QES-tier signatures (Idura, Signicat, or Scrive).
    Configured per-customer; not used unless you enable QES.</li>
</ul>

<h2>8. Cookies</h2>
<p>
  The Hash app sets a single session cookie (<code>HttpOnly</code>, <code>Secure</code>,
  <code>SameSite=Strict</code>) that contains only an HMAC-signed reference to your authenticated
  session. The marketing site <code>brightinteraction.com</code> uses our own
  <a href="https://cookieproof.brightinteraction.com">CookieProof</a> consent platform.
</p>

<h2>9. Updates</h2>
<p>
  We will email account holders when we materially change this policy. The "last updated" date at the
  top reflects the most recent change.
</p>

<h2>Contact</h2>
<p>
  Bright Interaction AB, Stockholm, Sweden. Privacy questions: <code>tom@brightinteraction.com</code>.
</p>
