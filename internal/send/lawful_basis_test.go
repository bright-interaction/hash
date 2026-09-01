// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestValidateLawfulBasisRequiresExplicitSupportedChoice(t *testing.T) {
	if err := ValidateLawfulBasis("contract"); err != nil {
		t.Fatalf("supported contract basis rejected: %v", err)
	}
	for _, value := range []string{"", " ", "unknown", "CONTRACT", "contract,consent", "consent", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"} {
		if err := ValidateLawfulBasis(value); !errors.Is(err, ErrLawfulBasisUnconfirmed) {
			t.Errorf("basis %q error = %v, want ErrLawfulBasisUnconfirmed", value, err)
		}
	}
}

func TestRequireConfirmedLawfulBasisDoesNotTreatDatabaseDefaultAsInstruction(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), LawfulBasis: "contract"}
	if err := requireConfirmedLawfulBasis(doc, nil); !errors.Is(err, ErrLawfulBasisUnconfirmed) {
		t.Fatalf("unconfirmed default error = %v, want ErrLawfulBasisUnconfirmed", err)
	}
	confirmation := &generated.DocumentLawfulBasisConfirmation{
		DocumentID: doc.ID, OrgID: doc.OrgID, LawfulBasis: "contract",
		ConfirmedAt:    pgtype.Timestamptz{Time: time.Now(), Valid: true},
		ControllerName: "Customer AB", ControllerContact: "sender@customer.example",
	}
	if err := requireConfirmedLawfulBasis(doc, confirmation); err != nil {
		t.Fatalf("explicit confirmation rejected: %v", err)
	}
	confirmation.LawfulBasis = "unknown"
	doc.LawfulBasis = "unknown"
	if err := requireConfirmedLawfulBasis(doc, confirmation); !errors.Is(err, ErrLawfulBasisUnconfirmed) {
		t.Fatalf("unsupported confirmed value error = %v, want ErrLawfulBasisUnconfirmed", err)
	}
}

func TestRequireValidSignerDisclosureUsesFrozenControllerAndRealDocumentName(t *testing.T) {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Name: "Customer agreement", LawfulBasis: "contract"}
	confirmation := &generated.DocumentLawfulBasisConfirmation{
		DocumentID: doc.ID, OrgID: doc.OrgID, LawfulBasis: "contract",
		ConfirmedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
		ControllerName:    "Customer AB",
		ControllerContact: "contracts@customer.example",
	}
	if err := requireValidSignerDisclosure(doc, confirmation); err != nil {
		t.Fatalf("valid signer disclosure rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*generated.Document, *generated.DocumentLawfulBasisConfirmation)
	}{
		{name: "document control character", mutate: func(doc *generated.Document, _ *generated.DocumentLawfulBasisConfirmation) {
			doc.Name = "Agreement\nInjected"
		}},
		{name: "overlong document", mutate: func(doc *generated.Document, _ *generated.DocumentLawfulBasisConfirmation) {
			doc.Name = strings.Repeat("x", 1900)
		}},
		{name: "overlong controller", mutate: func(_ *generated.Document, confirmation *generated.DocumentLawfulBasisConfirmation) {
			confirmation.ControllerName = strings.Repeat("x", 201)
		}},
		{name: "invalid controller contact", mutate: func(_ *generated.Document, confirmation *generated.DocumentLawfulBasisConfirmation) {
			confirmation.ControllerContact = "not-an-email"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateDoc := *doc
			candidateConfirmation := *confirmation
			test.mutate(&candidateDoc, &candidateConfirmation)
			if err := requireValidSignerDisclosure(&candidateDoc, &candidateConfirmation); !errors.Is(err, ErrInvalidSignerDisclosure) {
				t.Fatalf("requireValidSignerDisclosure() error = %v, want ErrInvalidSignerDisclosure", err)
			}
		})
	}
}
