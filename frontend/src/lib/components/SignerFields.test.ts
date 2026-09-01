import { describe, expect, test } from 'bun:test';

const component = await Bun.file(new URL('./SignerFields.svelte', import.meta.url)).text();

describe('block signer field persistence', () => {
  test('keeps signing closed until the field list and every edit are server-confirmed', () => {
    expect(component).toContain('if (!fieldsLoaded) return false;');
    expect(component).toContain('if (loadError || saveError || saving) return false;');
    expect(component).toContain('draftValue !== persistedValue');
    expect(component).toContain('persisted[f.id] = value;');
    expect(component).toContain('persisted[f.id] = confirmedValue;');
  });

  test('fails closed on unsuccessful or malformed load and save responses', () => {
    expect(component).toContain('throw new Error(await responseError(res));');
    expect(component).toContain("throw new Error('The server did not return a valid field list.');");
    expect(component).toContain("throw new Error('The server did not confirm the saved fields.');");
    expect(component).not.toContain('treat\n        // as zero-fields');
    expect(component).toContain('role="alert"');
  });

  test('reverts failed edits and preserves the Article 13 acknowledgement header', () => {
    expect(component).toContain('buf[f.id] = persisted[f.id] ?? emptyValue(f);');
    expect(component).toContain('headers: signerNoticeHeaders(noticeDigest, true)');
  });
});
