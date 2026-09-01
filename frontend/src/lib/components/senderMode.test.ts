import { describe, expect, test } from 'bun:test';

import {
  ceremonyModeCopy,
  hasCeremonyParticipant,
  recipientRoleOptions,
} from './senderMode';

describe('sender ceremony mode', () => {
  test('uses acknowledgement-specific operator copy without signature claims', () => {
    const acknowledgement = ceremonyModeCopy(false);
    expect(acknowledgement.sendAction).toBe('Send for acknowledgement');
    expect(acknowledgement.editableDescription).toContain('review and acknowledge');
    expect(acknowledgement.editableDescription).toContain('no signature will be requested');
    expect(acknowledgement.defaultLanguageHelp).toContain('currently English');
    expect(acknowledgement.completedPDF).toBe('Completed PDF');
    expect(acknowledgement.auditCertificate).toBe('Acknowledgement audit certificate');

    const signature = ceremonyModeCopy(true);
    expect(signature.sendAction).toBe('Send for signature');
    expect(signature.completedPDF).toBe('Signed PDF');
  });

  test('acknowledgement eligibility accepts response roles but rejects viewer and cc', () => {
    expect(hasCeremonyParticipant(false, ['approver'], [])).toBe(true);
    expect(hasCeremonyParticipant(false, ['customer_reviewer'], [])).toBe(true);
    expect(hasCeremonyParticipant(false, ['viewer', 'cc'], [])).toBe(false);
  });

  test('signature eligibility follows the document signature roles', () => {
    expect(hasCeremonyParticipant(true, ['signer'], [])).toBe(true);
    expect(hasCeremonyParticipant(true, ['approver'], [])).toBe(false);
    expect(hasCeremonyParticipant(true, ['customer_signer'], ['customer_signer'])).toBe(true);
    expect(hasCeremonyParticipant(true, ['signer'], ['customer_signer'])).toBe(false);
  });

  test('adds canonical custom signing roles without exposing informational roles', () => {
    expect(
      recipientRoleOptions([
        { role: ' Customer_Signer ' },
        { role: 'customer_signer' },
        { role: 'approver' },
        { role: 'viewer' },
        { role: 'cc' },
      ]),
    ).toEqual([
      { value: 'signer', label: 'Signer' },
      { value: 'approver', label: 'Approver' },
      { value: 'customer_signer', label: 'Customer Signer' },
    ]);
  });

  test('document page passes the persisted ceremony mode into SenderPanel', async () => {
    const panel = await Bun.file(new URL('./SenderPanel.svelte', import.meta.url)).text();
    const documentPage = await Bun.file(
      new URL('../../routes/documents/[id]/+page.svelte', import.meta.url),
    ).text();

    expect(panel).toContain('requiresSignature = true');
    expect(documentPage).toContain('requiresSignature={doc.requires_signature !== false}');
  });
});
