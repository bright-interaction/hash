export interface CeremonyCopy {
  sectionTitle: string;
  defaultLanguageHelp: string;
  recipientLanguageHelp: string;
  editableDescription: string;
  liveDescription: string;
  completedDescription: string;
  emptyRecipients: string;
  sendAction: string;
  sendingAction: string;
  missingParticipant: string;
  completedPDF: string;
  auditCertificate: string;
  linksTitle: string;
  linksDescription: string;
  lawfulBasisLabel: string;
}

const signatureCopy: CeremonyCopy = {
  sectionTitle: 'Recipients & signing',
  defaultLanguageHelp:
    'New recipients’ lifecycle emails use this language. The legal/signing page is currently English pending reviewed localization.',
  recipientLanguageHelp:
    'Lifecycle email language. The legal/signing page is currently English pending reviewed localization.',
  editableDescription:
    'Add the people who must sign this document, then send it for signature. Each required signer gets a single-use magic link by email.',
  liveDescription:
    'This document is out for signature. You can send a reminder or void it. Recipients are locked while signing is in progress.',
  completedDescription:
    'Every required signer has completed. Download the signed PDF and the tamper-evident audit certificate below.',
  emptyRecipients: 'Add at least one required signer to send this document.',
  sendAction: 'Send for signature',
  sendingAction: 'Sending...',
  missingParticipant: 'Add a required signer to enable sending.',
  completedPDF: 'Signed PDF',
  auditCertificate: 'Audit certificate',
  linksTitle: 'Signing links sent',
  linksDescription:
    'Each required signer was emailed a single-use link. Copy a link here only if you want to deliver it yourself; Hash stores it hashed and cannot show it again.',
  lawfulBasisLabel: 'Signer-data lawful basis',
};

const acknowledgementCopy: CeremonyCopy = {
  sectionTitle: 'Recipients & acknowledgement',
  defaultLanguageHelp:
    'Acknowledgement emails and the legal acknowledgement page are currently English pending reviewed localization.',
  recipientLanguageHelp:
    'Acknowledgement emails and the legal acknowledgement page are currently English pending reviewed localization.',
  editableDescription:
    'Add the people who must review and acknowledge this document, then send it for acknowledgement. Each required recipient gets a single-use magic link by email; no signature will be requested.',
  liveDescription:
    'This document is out for acknowledgement. You can send a reminder or void it. Recipients are locked while acknowledgement is in progress.',
  completedDescription:
    'Every required recipient has acknowledged the document. Download the completed PDF and the tamper-evident acknowledgement audit certificate below.',
  emptyRecipients: 'Add at least one acknowledging recipient to send this document.',
  sendAction: 'Send for acknowledgement',
  sendingAction: 'Sending...',
  missingParticipant: 'Add at least one acknowledging recipient to enable sending.',
  completedPDF: 'Completed PDF',
  auditCertificate: 'Acknowledgement audit certificate',
  linksTitle: 'Acknowledgement links sent',
  linksDescription:
    'Each required recipient was emailed a single-use acknowledgement link. Copy a link here only if you want to deliver it yourself; Hash stores it hashed and cannot show it again.',
  lawfulBasisLabel: 'Acknowledgement-data lawful basis',
};

export function ceremonyModeCopy(requiresSignature: boolean): CeremonyCopy {
  return requiresSignature ? signatureCopy : acknowledgementCopy;
}

export function isSupportedResponseRole(role: string): boolean {
  const canonical = role.trim().toLowerCase();
  return canonical !== '' && canonical !== 'viewer' && canonical !== 'cc';
}

export function hasCeremonyParticipant(
  requiresSignature: boolean,
  recipientRoles: string[],
  requiredSignatureRoles: string[],
): boolean {
  const supported = recipientRoles.filter(isSupportedResponseRole);
  if (!requiresSignature) return supported.length > 0;

  const required = [...new Set(requiredSignatureRoles.filter(isSupportedResponseRole))];
  if (required.length > 0) {
    return required.every((role) => supported.includes(role));
  }
  return supported.includes('signer');
}

export interface RecipientRoleOption {
  value: string;
  label: string;
}

function roleLabel(role: string): string {
  return role
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part[0].toUpperCase() + part.slice(1))
    .join(' ');
}

export function recipientRoleOptions(
  signatureFields: { role: string }[],
): RecipientRoleOption[] {
  const options: RecipientRoleOption[] = [
    { value: 'signer', label: 'Signer' },
    { value: 'approver', label: 'Approver' },
  ];
  const seen = new Set(options.map((option) => option.value));

  for (const field of signatureFields) {
    const role = field.role.trim().toLowerCase();
    if (!isSupportedResponseRole(role) || seen.has(role)) continue;
    seen.add(role);
    options.push({ value: role, label: roleLabel(role) });
  }
  return options;
}
