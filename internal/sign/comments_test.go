// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestCommentStateGateClosesBeforeEvidenceCapture(t *testing.T) {
	for _, status := range []string{"sent", "in_progress", "changes_requested"} {
		if err := checkDocumentCommentable(&generated.Document{Status: status}); err != nil {
			t.Errorf("active status %q rejected comments: %v", status, err)
		}
	}
	for _, status := range []string{"draft", "sealing", "finalizing", "completed", "declined", "voided", "expired"} {
		if err := checkDocumentCommentable(&generated.Document{Status: status}); !errors.Is(err, ErrDocumentNotCommentable) {
			t.Errorf("closed status %q returned %v, want ErrDocumentNotCommentable", status, err)
		}
	}
	if err := checkDocumentCommentable(nil); !errors.Is(err, ErrDocumentNotCommentable) {
		t.Errorf("nil document returned %v, want ErrDocumentNotCommentable", err)
	}
}
