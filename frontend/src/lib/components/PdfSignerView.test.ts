import { describe, expect, test } from 'bun:test';

const component = await Bun.file(new URL('./PdfSignerView.svelte', import.meta.url)).text();

describe('PDF signer field persistence', () => {
  test('keeps the signing gate closed until fields and edits are server-confirmed', () => {
    expect(component).toContain('if (!fieldsLoaded) return false;');
    expect(component).toContain('if (Object.keys(saveErrors).length > 0) return false;');
    expect(component).toContain('draftValue !== persistedValue');
    expect(component).toContain('saving[f.id]');
    expect(component).toContain('persisted[f.id] = value;');
    expect(component).toContain('disabled={signed || !recomputeFilled()}');
    expect(component).toContain('if (recomputeFilled()) onSignatureClick?.();');
  });

  test('fails closed when an autosave response is unsuccessful or malformed', () => {
    const responseCheck = component.indexOf('if (!res.ok)');
    const confirmationCheck = component.indexOf('if (!updated)');
    const persistedUpdate = component.indexOf('persisted[f.id] = confirmedValue;');

    expect(responseCheck).toBeGreaterThan(-1);
    expect(confirmationCheck).toBeGreaterThan(responseCheck);
    expect(persistedUpdate).toBeGreaterThan(confirmationCheck);
    expect(component).toContain('throw new Error(await responseError(res));');
    expect(component).toContain("throw new Error('The server did not confirm the saved field.');");
  });

  test('reverts failed edits and exposes a visible field-specific error', () => {
    const revert = component.indexOf('buf[f.id] = previousValue;');
    const visibleError = component.indexOf('Could not save {fieldName(fieldID)}: {message}');

    expect(revert).toBeGreaterThan(-1);
    expect(visibleError).toBeGreaterThan(revert);
    expect(component).toContain('saveErrors[f.id] = errorMessage(e);');
    expect(component).toContain('role="alert"');
  });

  test('preserves the acknowledged Article 13 notice on field writes', () => {
    expect(component).toContain('headers: signerNoticeHeaders(noticeDigest, true)');
  });
});
