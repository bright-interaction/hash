// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"strings"
	"testing"
)

func TestRecipientCommentEmailReturnsThroughNoticeGatedSignerPage(t *testing.T) {
	_, htmlBody, textBody, err := Render(KindNewComment, TemplateContext{
		DocumentName: "Agreement", RecipientName: "Sender", DeclineReason: "Please review",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{htmlBody, textBody} {
		if !strings.Contains(body, "current privacy notice") {
			t.Fatalf("recipient comment instructions omit the notice gate: %q", body)
		}
		if strings.Contains(body, "/a/comment") || strings.Contains(body, "Reply link") {
			t.Fatalf("recipient comment email exposes retired reply mutation: %q", body)
		}
	}
}
