import { describe, expect, test } from 'bun:test';

const component = await Bun.file(new URL('./A13Notice.svelte', import.meta.url)).text();

describe('Article 13 notice evidence copy', () => {
  test('renders every data-subject request string from server-authored copy', () => {
    for (const field of [
      'submit_request_label',
      'kind_label',
      'dsr_access_label',
      'dsr_rectification_label',
      'dsr_erasure_label',
      'dsr_restriction_label',
      'dsr_portability_label',
      'dsr_objection_label',
      'note_label',
      'note_placeholder',
      'send_request_label',
      'request_received',
    ]) {
      expect(component).toContain(`privacy.copy.${field}`);
    }
    expect(component).not.toContain("$t('a13.");
    expect(component).not.toContain('get(t)');
  });
});
