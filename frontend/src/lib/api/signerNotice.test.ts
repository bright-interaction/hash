import { describe, expect, test } from 'bun:test';

import { SIGNER_NOTICE_DIGEST_HEADER, signerNoticeHeaders } from './signerNotice';

describe('signer Article 13 response headers', () => {
  test('carries the exact lowercase SHA-256 notice digest', () => {
    const digest = 'ab'.repeat(32);
    expect(signerNoticeHeaders(digest)).toEqual({
      [SIGNER_NOTICE_DIGEST_HEADER]: digest,
    });
    expect(signerNoticeHeaders(digest, true)).toEqual({
      'Content-Type': 'application/json',
      [SIGNER_NOTICE_DIGEST_HEADER]: digest,
    });
  });

  test('fails closed for missing, stale-format, or normalized digests', () => {
    for (const digest of ['', 'abc', 'AB'.repeat(32), ` ${'ab'.repeat(32)}`]) {
      expect(() => signerNoticeHeaders(digest)).toThrow(
        'The current privacy notice acknowledgement is unavailable.',
      );
    }
  });
});
