import { Node } from '@tiptap/core';

// ── signature_field ──────────────────────────────────────────────────────
//
// Atomic inline-block node: not editable as text, displays as a chip in
// the editor. ProseMirror's "selectable + atom" combo lets the user click
// the chip to select it (then Backspace to delete) but typing inside is a
// no-op. Recipient role is bound at author time and resolved to the actual
// signer at sign time.
export const SignatureField = Node.create({
  name: 'signatureField',
  group: 'block',
  atom: true,
  selectable: true,
  draggable: true,

  addAttributes() {
    return {
      blockId: { default: '' },
      recipientRole: { default: 'signer' },
      label: { default: '' },
      required: { default: true }
    };
  },

  parseHTML() {
    return [{ tag: 'div[data-hash-node="signature_field"]' }];
  },

  renderHTML({ HTMLAttributes, node }) {
    const role = node.attrs.recipientRole || 'signer';
    const label = node.attrs.label || 'Signature';
    return [
      'div',
      {
        ...HTMLAttributes,
        'data-hash-node': 'signature_field',
        'data-block-id': node.attrs.blockId,
        'data-recipient-role': role,
        class: 'hash-sig-chip'
      },
      `✍ ${label} @${role}`
    ];
  }
});

// ── dynamic_variable ─────────────────────────────────────────────────────
//
// Block atomic chip rendering as `{{name}}`. The canonical v1 schema models a
// dynamic_variable as a top-level block, so making this an inline atom would
// place it inside a paragraph and the canonical serializer could not preserve
// it losslessly.
export const DynamicVariable = Node.create({
  name: 'dynamicVariable',
  group: 'block',
  atom: true,
  selectable: true,

  addAttributes() {
    return {
      blockId: { default: '' },
      name: { default: '' },
      fallback: { default: '' }
    };
  },

  parseHTML() {
    return [{ tag: 'span[data-hash-node="dynamic_variable"]' }];
  },

  renderHTML({ HTMLAttributes, node }) {
    const name = node.attrs.name || 'var';
    return [
      'span',
      {
        ...HTMLAttributes,
        'data-hash-node': 'dynamic_variable',
        'data-block-id': node.attrs.blockId,
        'data-var-name': name,
        class: 'hash-var-chip'
      },
      `{{${name}}}`
    ];
  }
});

// ── opaque canonical block ───────────────────────────────────────────────
//
// Some API/MCP-authored canonical blocks do not yet have a visual editing UI
// (notably conditional, callout, and raw_html). Preserve their exact JSON in a
// selectable block atom instead of converting them to placeholder paragraphs.
// Users can move/delete the atom; editing its internals remains API/MCP-only.
export const OpaqueBlock = Node.create({
  name: 'opaqueBlock',
  group: 'block',
  atom: true,
  selectable: true,
  draggable: true,

  addAttributes() {
    return { blockJSON: { default: '' } };
  },

  parseHTML() {
    return [{ tag: 'div[data-hash-node="opaque_block"]' }];
  },

  renderHTML({ node }) {
    let label = 'preserved block';
    try {
      const block = JSON.parse(String(node.attrs.blockJSON || '{}')) as { type?: string };
      if (block.type) label = `${block.type} block · preserved`;
    } catch {
      label = 'invalid preserved block';
    }
    return [
      'div',
      { 'data-hash-node': 'opaque_block', class: 'hash-opaque-chip' },
      `◇ ${label}`
    ];
  }
});

// ── page_break ───────────────────────────────────────────────────────────
//
// Renders as a labeled horizontal-rule chip in the editor, becomes a
// CSS-print page-break in the final PDF.
export const PageBreak = Node.create({
  name: 'pageBreak',
  group: 'block',
  atom: true,
  selectable: true,
  draggable: true,

  addAttributes() {
    return { blockId: { default: '' } };
  },

  parseHTML() {
    return [{ tag: 'div[data-hash-node="page_break"]' }];
  },

  renderHTML({ HTMLAttributes, node }) {
    return [
      'div',
      {
        ...HTMLAttributes,
        'data-hash-node': 'page_break',
        'data-block-id': node.attrs.blockId,
        class: 'hash-pagebreak-chip'
      },
      '·  ·  ·  page break  ·  ·  ·'
    ];
  }
});

// ── table ────────────────────────────────────────────────────────────────
//
// A structured table block (services line-items, delivery timeline, etc).
// Modelled as an atom so ProseMirror does not try to edit cells as inline
// text; the grid is edited through a modal in Editor.svelte and stored in
// the node's `columns` (string[]) + `rows` (string[][]) attrs, which map
// straight onto the Go canonical TypeTable (attrs.columns + rows). Cells may
// contain {{variable}} tokens, substituted at render time. The nodeView
// renders a live preview plus a "Redigera" button that opens the editor.
function escapeTableHTML(s: string): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export const TableBlock = Node.create({
  name: 'tableBlock',
  group: 'block',
  atom: true,
  selectable: true,
  draggable: true,

  addAttributes() {
    return {
      blockId: { default: '' },
      columns: { default: [] as string[] },
      rows: { default: [] as string[][] }
    };
  },

  parseHTML() {
    return [{ tag: 'div[data-hash-node="table_block"]' }];
  },

  renderHTML({ HTMLAttributes, node }) {
    // Static DOM spec for clipboard/getHTML; the live editor uses the nodeView.
    const cols = (node.attrs.columns || []) as string[];
    const rows = (node.attrs.rows || []) as string[][];
    return [
      'div',
      {
        ...HTMLAttributes,
        'data-hash-node': 'table_block',
        'data-block-id': node.attrs.blockId,
        class: 'hash-table-block'
      },
      [
        'table',
        {},
        ['thead', {}, ['tr', {}, ...cols.map((c) => ['th', {}, String(c)])]],
        ['tbody', {}, ...rows.map((row) => ['tr', {}, ...row.map((cell) => ['td', {}, String(cell)])])]
      ]
    ];
  },

  addNodeView() {
    return ({ node, getPos, editor }) => {
      let current = node;
      const dom = document.createElement('div');
      dom.className = 'hash-table-block';
      dom.setAttribute('data-hash-node', 'table_block');

      const paint = (n: typeof node) => {
        const cols = (n.attrs.columns || []) as string[];
        const rows = (n.attrs.rows || []) as string[][];
        const head = `<thead><tr>${cols
          .map((c) => `<th>${escapeTableHTML(c) || '&nbsp;'}</th>`)
          .join('')}</tr></thead>`;
        const body = `<tbody>${rows
          .map(
            (row) =>
              `<tr>${row.map((cell) => `<td>${escapeTableHTML(cell) || '&nbsp;'}</td>`).join('')}</tr>`
          )
          .join('')}</tbody>`;
        dom.innerHTML =
          `<div class="hash-table-bar">` +
          `<span class="hash-table-tag">&#9638; Tabell · ${cols.length} kol × ${rows.length} rad</span>` +
          `<button type="button" data-act="edit" class="hash-table-btn">Redigera</button>` +
          `</div>` +
          `<table>${head}${body}</table>`;
      };
      paint(current);

      dom.addEventListener('mousedown', (e) => {
        const t = e.target as HTMLElement;
        if (t?.dataset?.act === 'edit') {
          e.preventDefault();
          e.stopPropagation();
          const pos = typeof getPos === 'function' ? getPos() : undefined;
          if (typeof pos === 'number') {
            editor.commands.setNodeSelection(pos);
            dom.dispatchEvent(
              new CustomEvent('hash-edit-table', {
                bubbles: true,
                detail: { pos, columns: current.attrs.columns, rows: current.attrs.rows }
              })
            );
          }
        }
      });

      return {
        dom,
        update: (updated) => {
          if (updated.type.name !== 'tableBlock') return false;
          current = updated;
          paint(updated);
          return true;
        },
        stopEvent: (e) => (e.target as HTMLElement)?.dataset?.act === 'edit',
        ignoreMutation: () => true
      };
    };
  }
});

// ── BlockId attribute extension ──────────────────────────────────────────
//
// Attaches a `blockId` attribute to the standard StarterKit nodes
// (heading, paragraph, bulletList, orderedList, listItem, blockquote,
// codeBlock, horizontalRule) so the canonical-tree round-trip preserves
// the same id every save. Without this, edits would mint fresh ids on
// every save and break event-trail correlation.
export const BLOCK_ID_NODE_TYPES = [
  'heading',
  'paragraph',
  'bulletList',
  'orderedList',
  'listItem',
  'blockquote',
  'codeBlock',
  'horizontalRule'
] as const;

export const BlockIDExtension = Node.create({
  name: 'blockIdExtension',
  addGlobalAttributes() {
    return [
      {
        types: [...BLOCK_ID_NODE_TYPES],
        attributes: {
          blockId: {
            default: '',
            parseHTML: (el: HTMLElement) => el.getAttribute('data-block-id') ?? '',
            renderHTML: (attrs: Record<string, unknown>) =>
              attrs.blockId ? { 'data-block-id': String(attrs.blockId) } : {}
          }
        }
      }
    ];
  }
});
