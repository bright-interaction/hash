// Canonical block tree <-> ProseMirror state transformer.
//
// The canonical shape lives at internal/blocks/schema.go on the Go side
// and frontend/src/lib/api/client.ts on this side. ProseMirror state is
// what TipTap uses internally. This module bridges the two so the editor
// can load any block tree (including agent-generated ones) and round-trip
// faithfully when the user edits and saves.
//
// We intentionally keep the canonical tree as the source of truth: agents
// posting to /api/v1/documents/{id}/blocks never need to understand
// ProseMirror, and the Go renderer at sign time uses the canonical form,
// not a ProseMirror-formatted string.

import type { Block, BlockTree } from '$lib/api/client';

// ── Canonical -> ProseMirror ─────────────────────────────────────────────

export function toProseMirror(tree: BlockTree | undefined): {
  type: 'doc';
  content: Array<Record<string, unknown>>;
} {
  const blocks = tree?.blocks ?? [];
  const content = blocks.map(blockToPMNode).filter(Boolean) as Array<Record<string, unknown>>;
  return { type: 'doc', content: content.length > 0 ? content : [emptyParagraph()] };
}

function emptyParagraph() {
  return { type: 'paragraph', content: [] };
}

function blockToPMNode(b: Block): Record<string, unknown> | null {
  switch (b.type) {
    case 'heading':
      return {
        type: 'heading',
        attrs: { level: (b.attrs?.level as number) ?? 1, blockId: b.id },
        content: textRun(b.text)
      };
    case 'paragraph':
      return {
        type: 'paragraph',
        attrs: { blockId: b.id },
        content: textRun(b.text)
      };
    case 'bullet_list':
      return {
        type: 'bulletList',
        attrs: { blockId: b.id },
        content: (b.content ?? []).map(listItemToPM)
      };
    case 'ordered_list':
      return {
        type: 'orderedList',
        attrs: { blockId: b.id },
        content: (b.content ?? []).map(listItemToPM)
      };
    case 'divider':
      return { type: 'horizontalRule', attrs: { blockId: b.id } };
    case 'page_break':
      return { type: 'pageBreak', attrs: { blockId: b.id } };
    case 'signature_field':
      return {
        type: 'signatureField',
        attrs: {
          blockId: b.id,
          recipientRole: (b.attrs?.recipient_role as string) ?? 'signer',
          label: (b.attrs?.label as string) ?? '',
          required: (b.attrs?.required as boolean) ?? true
        }
      };
    case 'dynamic_variable':
      return {
        type: 'dynamicVariable',
        attrs: {
          blockId: b.id,
          name: (b.attrs?.name as string) ?? '',
          fallback: (b.attrs?.default as string) ?? ''
        }
      };
    case 'table':
      return {
        type: 'tableBlock',
        attrs: {
          blockId: b.id,
          columns: (b.attrs?.columns as string[]) ?? [],
          rows: b.rows ?? []
        }
      };
    case 'quote':
      return {
        type: 'blockquote',
        attrs: { blockId: b.id },
        content: [{ type: 'paragraph', content: textRun(b.text) }]
      };
    case 'code':
      return {
        type: 'codeBlock',
        attrs: { blockId: b.id, language: (b.attrs?.language as string) ?? '' },
        content: textRun(b.text)
      };
  }
  // Unknown block type: render as a paragraph so content survives.
  return {
    type: 'paragraph',
    attrs: { blockId: b.id },
    content: textRun(b.text ?? `[unsupported: ${b.type}]`)
  };
}

function listItemToPM(li: Block): Record<string, unknown> {
  return {
    type: 'listItem',
    attrs: { blockId: li.id },
    content: [{ type: 'paragraph', content: textRun(li.text) }]
  };
}

function textRun(s: string | undefined): Array<Record<string, unknown>> {
  if (!s) return [];
  return [{ type: 'text', text: s }];
}

// ── ProseMirror -> Canonical ─────────────────────────────────────────────

export function fromProseMirror(doc: Record<string, unknown>): BlockTree {
  const content = (doc.content ?? []) as Array<Record<string, unknown>>;
  return {
    version: 1,
    blocks: content.map(pmNodeToBlock).filter(Boolean) as Block[]
  };
}

function pmNodeToBlock(n: Record<string, unknown>): Block | null {
  const attrs = (n.attrs ?? {}) as Record<string, unknown>;
  const blockId = (attrs.blockId as string) || generateBlockID();
  const text = nodeText(n);

  switch (n.type) {
    case 'heading':
      return {
        id: blockId,
        type: 'heading',
        attrs: { level: (attrs.level as number) ?? 1 },
        text
      };
    case 'paragraph':
      return { id: blockId, type: 'paragraph', text };
    case 'bulletList':
      return {
        id: blockId,
        type: 'bullet_list',
        content: ((n.content ?? []) as Array<Record<string, unknown>>).map(pmListItemToBlock)
      };
    case 'orderedList':
      return {
        id: blockId,
        type: 'ordered_list',
        content: ((n.content ?? []) as Array<Record<string, unknown>>).map(pmListItemToBlock)
      };
    case 'horizontalRule':
      return { id: blockId, type: 'divider' };
    case 'pageBreak':
      return { id: blockId, type: 'page_break' };
    case 'signatureField':
      return {
        id: blockId,
        type: 'signature_field',
        attrs: {
          recipient_role: (attrs.recipientRole as string) ?? 'signer',
          label: (attrs.label as string) ?? '',
          required: (attrs.required as boolean) ?? true
        }
      };
    case 'dynamicVariable':
      return {
        id: blockId,
        type: 'dynamic_variable',
        attrs: {
          name: (attrs.name as string) ?? '',
          default: (attrs.fallback as string) ?? ''
        }
      };
    case 'tableBlock':
      return {
        id: blockId,
        type: 'table',
        attrs: { columns: (attrs.columns as string[]) ?? [] },
        rows: (attrs.rows as string[][]) ?? []
      };
    case 'blockquote':
      return { id: blockId, type: 'quote', text };
    case 'codeBlock':
      return {
        id: blockId,
        type: 'code',
        attrs: { language: (attrs.language as string) ?? '' },
        text
      };
  }
  return null;
}

function pmListItemToBlock(n: Record<string, unknown>): Block {
  const attrs = (n.attrs ?? {}) as Record<string, unknown>;
  return {
    id: (attrs.blockId as string) || generateBlockID(),
    type: 'list_item',
    text: nodeText(n)
  };
}

function nodeText(n: Record<string, unknown>): string {
  const content = (n.content ?? []) as Array<Record<string, unknown>>;
  let out = '';
  for (const child of content) {
    if (child.type === 'text' && typeof child.text === 'string') {
      out += child.text;
    } else if (child.content) {
      out += nodeText(child);
    }
  }
  return out;
}

function generateBlockID(): string {
  // 8-byte hex matches the Go side's blk_<16hex> shape.
  const buf = new Uint8Array(8);
  crypto.getRandomValues(buf);
  return 'blk_' + Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
}
