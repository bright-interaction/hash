// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import "strings"

import "testing"

func TestBuildMIME_StripsHeaderInjection(t *testing.T) {
	// A malicious document name lands in the Subject; CRLF must not inject a
	// new header (Bcc) or break out of the header block.
	msg := Message{
		To:      "victim@example.com\r\nBcc: attacker@evil.example",
		Subject: "Contract\r\nBcc: attacker@evil.example",
		HTML:    "<p>hi</p>",
		Text:    "hi",
		ReplyTo: "sender@example.com",
	}
	out, err := buildMIME("Hash <esign@brightinteraction.com>", msg)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	headerBlock := out
	if i := strings.Index(out, "\r\n\r\n"); i >= 0 {
		headerBlock = out[:i]
	}
	// Security property: the CRLF strip means the injected "Bcc:" text can only
	// survive concatenated INSIDE another header's value (harmless), never as
	// its own header LINE. Assert no header line starts with Bcc:.
	for _, line := range strings.Split(headerBlock, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Errorf("CRLF injection created a Bcc header line: %q", line)
		}
	}
	if !strings.Contains(headerBlock, "Reply-To: sender@example.com") {
		t.Errorf("Reply-To not emitted:\n%s", headerBlock)
	}
}

func TestBuildMIME_EncodesNonASCIISubject(t *testing.T) {
	msg := Message{To: "a@b.com", Subject: "Avtal foer signering aaeoe: åäö", HTML: "<p>x</p>", Text: "x"}
	out, err := buildMIME("Hash <esign@brightinteraction.com>", msg)
	if err != nil {
		t.Fatalf("buildMIME: %v", err)
	}
	// RFC 2047 encoded-word marker; the raw 8-bit bytes must not appear bare.
	if !strings.Contains(out, "=?utf-8?") {
		t.Errorf("non-ASCII subject was not RFC 2047 encoded:\n%s", out)
	}
}
