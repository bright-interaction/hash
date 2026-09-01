// The signer mutation contract carries the exact server-authored Article 13
// notice digest on every response. The digest is evidence metadata, not a
// bearer credential; the magic-link token remains confined to the URL.
export const SIGNER_NOTICE_DIGEST_HEADER = 'X-Hash-Notice-Digest';

const sha256Hex = /^[0-9a-f]{64}$/;

export function signerNoticeHeaders(noticeDigest: string, json = false): Record<string, string> {
  if (!sha256Hex.test(noticeDigest)) {
    throw new Error('The current privacy notice acknowledgement is unavailable.');
  }
  return {
    ...(json ? { 'Content-Type': 'application/json' } : {}),
    [SIGNER_NOTICE_DIGEST_HEADER]: noticeDigest,
  };
}
