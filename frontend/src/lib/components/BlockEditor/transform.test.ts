import { describe, expect, test } from 'bun:test';

import type { BlockTree } from '$lib/api/client';
import { BLOCK_ID_NODE_TYPES } from './nodes';
import { fromProseMirror, isCanonicalSignatureRole, toProseMirror } from './transform';

describe('canonical block editor round-trip', () => {
  test('preserves a top-level dynamic variable atom', () => {
    const tree: BlockTree = {
      version: 1,
      blocks: [
        {
          id: 'price-variable',
          type: 'dynamic_variable',
          attrs: { name: 'price', default: '0' }
        }
      ]
    };
    const editor = toProseMirror(tree);
    expect(editor.content[0]?.type).toBe('dynamicVariable');
    expect(fromProseMirror(editor)).toEqual(tree);
  });

  test('preserves conditional expression and nested legal content exactly', () => {
    const tree: BlockTree = {
      version: 1,
      blocks: [
        {
          id: 'high-value-clause',
          type: 'conditional',
          attrs: { expression: 'var(amount) > 10000' },
          content: [
            { id: 'clause', type: 'paragraph', text: 'Enhanced approval applies.' },
            {
              id: 'approver-signature',
              type: 'signature_field',
              attrs: { recipient_role: 'approver', required: true }
            }
          ]
        }
      ]
    };
    const editor = toProseMirror(tree);
    expect(editor.content[0]?.type).toBe('opaqueBlock');
    expect(fromProseMirror(editor)).toEqual(tree);
  });

  test('preserves unsupported visual blocks instead of making placeholder paragraphs', () => {
    const tree: BlockTree = {
      version: 1,
      blocks: [{ id: 'raw', type: 'raw_html', text: '<p>Approved static markup</p>' }]
    };
    const editor = toProseMirror(tree);
    expect(editor.content[0]?.type).toBe('opaqueBlock');
    expect(fromProseMirror(editor)).toEqual(tree);
  });

  test('preserves a quote with nested canonical blocks exactly', () => {
    const tree: BlockTree = {
      version: 1,
      blocks: [
        {
          id: 'quote-container',
          type: 'quote',
          content: [
            { id: 'quoted-heading', type: 'heading', attrs: { level: 3 }, text: 'Terms' },
            { id: 'quoted-copy', type: 'paragraph', text: 'Nested legal copy.' }
          ]
        }
      ]
    };

    const editor = toProseMirror(tree);
    expect(editor.content[0]?.type).toBe('opaqueBlock');
    expect(fromProseMirror(editor)).toEqual(tree);
  });

  test('preserves nested list-item content and its block identities exactly', () => {
    const tree: BlockTree = {
      version: 1,
      blocks: [
        {
          id: 'requirements',
          type: 'ordered_list',
          content: [
            {
              id: 'structured-item',
              type: 'list_item',
              content: [
                { id: 'item-copy', type: 'paragraph', text: 'Approval requires:' },
                {
                  id: 'nested-list',
                  type: 'bullet_list',
                  content: [{ id: 'nested-item', type: 'list_item', text: 'Identity evidence' }]
                }
              ]
            }
          ]
        }
      ]
    };

    const editor = toProseMirror(tree);
    expect(editor.content[0]?.type).toBe('opaqueBlock');
    expect(fromProseMirror(editor)).toEqual(tree);
  });

  test('serializes newly authored multi-block quotes without flattening their child ids', () => {
    const canonical = fromProseMirror({
      type: 'doc',
      content: [
        {
          type: 'blockquote',
          attrs: { blockId: 'quote' },
          content: [
            {
              type: 'paragraph',
              attrs: { blockId: 'quote-intro' },
              content: [{ type: 'text', text: 'Important:' }]
            },
            {
              type: 'paragraph',
              attrs: { blockId: 'quote-detail' },
              content: [{ type: 'text', text: 'Keep this separate.' }]
            }
          ]
        }
      ]
    });

    expect(canonical).toEqual({
      version: 1,
      blocks: [
        {
          id: 'quote',
          type: 'quote',
          content: [
            { id: 'quote-intro', type: 'paragraph', text: 'Important:' },
            { id: 'quote-detail', type: 'paragraph', text: 'Keep this separate.' }
          ]
        }
      ]
    });
    expect(fromProseMirror(toProseMirror(canonical))).toEqual(canonical);
  });

  test('serializes newly authored nested lists without flattening nested items', () => {
    const canonical = fromProseMirror({
      type: 'doc',
      content: [
        {
          type: 'bulletList',
          attrs: { blockId: 'outer-list' },
          content: [
            {
              type: 'listItem',
              attrs: { blockId: 'outer-item' },
              content: [
                {
                  type: 'paragraph',
                  attrs: { blockId: 'outer-copy' },
                  content: [{ type: 'text', text: 'Evidence' }]
                },
                {
                  type: 'orderedList',
                  attrs: { blockId: 'inner-list' },
                  content: [
                    {
                      type: 'listItem',
                      attrs: { blockId: 'inner-item' },
                      content: [
                        {
                          type: 'paragraph',
                          attrs: { blockId: '' },
                          content: [{ type: 'text', text: 'Photo ID' }]
                        }
                      ]
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    });

    expect(canonical).toEqual({
      version: 1,
      blocks: [
        {
          id: 'outer-list',
          type: 'bullet_list',
          content: [
            {
              id: 'outer-item',
              type: 'list_item',
              content: [
                { id: 'outer-copy', type: 'paragraph', text: 'Evidence' },
                {
                  id: 'inner-list',
                  type: 'ordered_list',
                  content: [{ id: 'inner-item', type: 'list_item', text: 'Photo ID' }]
                }
              ]
            }
          ]
        }
      ]
    });
    expect(fromProseMirror(toProseMirror(canonical))).toEqual(canonical);
  });

  test('keeps divider ids in both the transformer and TipTap node schema', () => {
    const tree: BlockTree = {
      version: 1,
      blocks: [{ id: 'section-divider', type: 'divider' }]
    };

    const editor = toProseMirror(tree);
    expect(editor.content[0]).toEqual({
      type: 'horizontalRule',
      attrs: { blockId: 'section-divider' }
    });
    expect(BLOCK_ID_NODE_TYPES).toContain('horizontalRule');
    expect(fromProseMirror(editor)).toEqual(tree);
  });

  test('accepts canonical custom signer roles without rewriting them', () => {
    for (const role of ['signer', 'approver', 'client_counsel', 'sales-partner-2']) {
      expect(isCanonicalSignatureRole(role)).toBe(true);
      const tree: BlockTree = {
        version: 1,
        blocks: [
          {
            id: `signature-${role}`,
            type: 'signature_field',
            attrs: { recipient_role: role, label: 'Sign', required: true }
          }
        ]
      };
      expect(fromProseMirror(toProseMirror(tree))).toEqual(tree);
    }
  });

  test('rejects invalid or non-signing recipient roles instead of inventing a replacement', () => {
    for (const role of ['', 'Client', 'client role', 'viewer', 'cc', `a${'b'.repeat(64)}`]) {
      expect(isCanonicalSignatureRole(role)).toBe(false);
    }

    expect(() =>
      fromProseMirror({
        type: 'doc',
        content: [
          {
            type: 'signatureField',
            attrs: { blockId: 'signature-invalid', recipientRole: 'Client role' }
          }
        ]
      })
    ).toThrow('invalid canonical recipient role');

    expect(() =>
      toProseMirror({
        version: 1,
        blocks: [{ id: 'signature-missing-role', type: 'signature_field', attrs: {} }]
      })
    ).toThrow('invalid canonical recipient role');
  });

  test('fails closed on an editor node the serializer does not understand', () => {
    expect(() => fromProseMirror({ type: 'doc', content: [{ type: 'mysteryNode' }] })).toThrow(
      'unsupported editor node'
    );
  });
});
