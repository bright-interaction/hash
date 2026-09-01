// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"os"
	"strings"
	"testing"
)

// Every participant mutation authenticates once before beginning its
// transaction, then must rebind that evidence to the row-locked sent_at before
// its first state write. This contract test prevents a future refactor from
// silently reopening the lookup-to-lock resend race on one entrypoint.
func TestParticipantMutationsRevalidateNoticeAfterDocumentLock(t *testing.T) {
	raw, err := os.ReadFile("flow.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	tests := []struct {
		method        string
		firstMutation string
	}{
		{method: "Sign", firstMutation: "q.SetRecipientStatus("},
		{method: "Accept", firstMutation: "q.SetRecipientStatus("},
		{method: "Decline", firstMutation: "q.SetRecipientStatus("},
		{method: "RequestChanges", firstMutation: "q.CreateChangeRequest("},
		{method: "SignerComment", firstMutation: "q.CreateComment("},
		{method: "MarkViewed", firstMutation: "q.SetRecipientStatus("},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			body := engineMethodSource(t, source, tt.method)
			lock := strings.Index(body, "GetDocumentForUpdate(")
			revalidate := strings.Index(body, "ValidateLockedNoticeEvidence(")
			mutation := strings.Index(body, tt.firstMutation)
			if lock < 0 || revalidate <= lock || mutation <= revalidate {
				t.Fatalf("lock/revalidation/mutation order is unsafe: lock=%d revalidate=%d mutation=%d", lock, revalidate, mutation)
			}
		})
	}
}

func engineMethodSource(t *testing.T, source, method string) string {
	t.Helper()
	startMarker := "func (e *Engine) " + method + "("
	start := strings.Index(source, startMarker)
	if start < 0 {
		t.Fatalf("missing Engine.%s", method)
	}
	rest := source[start+len(startMarker):]
	end := strings.Index(rest, "\nfunc ")
	if end < 0 {
		return source[start:]
	}
	return source[start : start+len(startMarker)+end]
}
