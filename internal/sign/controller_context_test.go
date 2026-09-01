// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type controllerLookupTestDB struct {
	recipient    *generated.GetRecipientByTokenHashRow
	document     *generated.Document
	confirmation *generated.DocumentLawfulBasisConfirmation
	org          *generated.Org
	orgErr       error

	documentLookupOrgID uuid.UUID
	controllerLookupID  uuid.UUID
}

func (db *controllerLookupTestDB) Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("unexpected Exec")
}

func (db *controllerLookupTestDB) Query(context.Context, string, ...interface{}) (pgx.Rows, error) {
	return nil, errors.New("unexpected Query")
}

func (db *controllerLookupTestDB) QueryRow(_ context.Context, query string, args ...interface{}) pgx.Row {
	switch {
	case strings.Contains(query, "-- name: GetRecipientByTokenHash"):
		return controllerLookupTestRow{values: map[int]interface{}{
			0:  db.recipient.ID,
			1:  db.recipient.DocumentID,
			2:  db.recipient.Role,
			3:  db.recipient.Email,
			4:  db.recipient.Name,
			6:  db.recipient.Status,
			14: db.recipient.Locale,
			15: db.recipient.DocOrgID,
			16: db.recipient.DocStatus,
		}}
	case strings.Contains(query, "-- name: GetDocument "):
		if len(args) == 2 {
			db.documentLookupOrgID, _ = args[1].(uuid.UUID)
		}
		return controllerLookupTestRow{values: map[int]interface{}{
			0:  db.document.ID,
			1:  db.document.OrgID,
			3:  db.document.Name,
			4:  db.document.Status,
			6:  db.document.SourceKind,
			30: db.document.LawfulBasis,
		}}
	case strings.Contains(query, "-- name: GetDocumentLawfulBasisConfirmation"):
		if db.confirmation == nil {
			return controllerLookupTestRow{err: pgx.ErrNoRows}
		}
		return controllerLookupTestRow{values: map[int]interface{}{
			0: db.confirmation.DocumentID,
			1: db.confirmation.OrgID,
			2: db.confirmation.LawfulBasis,
			3: db.confirmation.ConfirmedAt,
			4: db.confirmation.ConfirmedBy,
			5: db.confirmation.Via,
			6: db.confirmation.ControllerName,
			7: db.confirmation.ControllerContact,
		}}
	case strings.Contains(query, "-- name: GetOrg "):
		if len(args) == 1 {
			db.controllerLookupID, _ = args[0].(uuid.UUID)
		}
		if db.orgErr != nil {
			return controllerLookupTestRow{err: db.orgErr}
		}
		return controllerLookupTestRow{values: map[int]interface{}{
			0: db.org.ID,
			1: db.org.Name,
			2: db.org.Plan,
		}}
	default:
		return controllerLookupTestRow{err: fmt.Errorf("unexpected QueryRow: %s", query)}
	}
}

type controllerLookupTestRow struct {
	values map[int]interface{}
	err    error
}

func (row controllerLookupTestRow) Scan(dest ...interface{}) error {
	if row.err != nil {
		return row.err
	}
	for _, target := range dest {
		value := reflect.ValueOf(target)
		if value.Kind() != reflect.Ptr || value.IsNil() {
			return errors.New("scan target is not a non-nil pointer")
		}
		value.Elem().Set(reflect.Zero(value.Elem().Type()))
	}
	for index, source := range row.values {
		if index < 0 || index >= len(dest) {
			return fmt.Errorf("scan index %d is out of range", index)
		}
		target := reflect.ValueOf(dest[index]).Elem()
		value := reflect.ValueOf(source)
		if !value.Type().AssignableTo(target.Type()) {
			return fmt.Errorf("cannot assign %s to %s at scan index %d", value.Type(), target.Type(), index)
		}
		target.Set(value)
	}
	return nil
}

func newControllerLookupEngine(documentOrgID uuid.UUID, controllerName string) (*Engine, *controllerLookupTestDB) {
	documentID := uuid.New()
	db := &controllerLookupTestDB{
		recipient: &generated.GetRecipientByTokenHashRow{
			ID:         uuid.New(),
			DocumentID: documentID,
			Role:       "signer",
			Email:      "signer@example.test",
			Name:       "Signer",
			Status:     "sent",
			Locale:     "en",
			DocOrgID:   documentOrgID,
			DocStatus:  "sent",
		},
		document: &generated.Document{
			ID:          documentID,
			OrgID:       documentOrgID,
			Name:        "Customer agreement",
			Status:      "sent",
			SourceKind:  "blocks",
			LawfulBasis: "contract",
		},
		confirmation: &generated.DocumentLawfulBasisConfirmation{
			DocumentID:        documentID,
			OrgID:             documentOrgID,
			LawfulBasis:       "contract",
			ConfirmedAt:       pgtype.Timestamptz{Time: time.Now(), Valid: true},
			Via:               "rest",
			ControllerName:    controllerName,
			ControllerContact: "sender@customer.example",
		},
		org: &generated.Org{ID: documentOrgID, Name: controllerName, Plan: "pro"},
	}
	return &Engine{Queries: generated.New(db), OrgName: "Bright Interaction AB"}, db
}

func TestLookupByTokenLoadsControllerFromEachDocumentOrganization(t *testing.T) {
	for _, controllerName := range []string{"Customer Alpha AB", "Customer Beta Oy"} {
		t.Run(controllerName, func(t *testing.T) {
			documentOrgID := uuid.New()
			engine, db := newControllerLookupEngine(documentOrgID, controllerName)

			rc, err := engine.LookupByToken(context.Background(), []byte("token-hash"))
			if err != nil {
				t.Fatal(err)
			}
			if rc.ControllerOrg == nil || rc.ControllerOrg.ID != documentOrgID || rc.ControllerOrg.Name != controllerName {
				t.Fatalf("controller org = %+v, want %s %q", rc.ControllerOrg, documentOrgID, controllerName)
			}
			if db.documentLookupOrgID != documentOrgID || db.controllerLookupID != rc.Document.OrgID {
				t.Fatalf("document/controller lookups used %s/%s, want document org %s", db.documentLookupOrgID, db.controllerLookupID, documentOrgID)
			}
			if rc.ControllerOrg.Name == engine.OrgName {
				t.Fatalf("document controller incorrectly fell back to instance operator %q", engine.OrgName)
			}
		})
	}
}

func TestLookupByTokenFailsClosedWhenDocumentControllerUnavailable(t *testing.T) {
	documentOrgID := uuid.New()
	tests := []struct {
		name      string
		configure func(*controllerLookupTestDB)
	}{
		{
			name: "organization missing",
			configure: func(db *controllerLookupTestDB) {
				db.orgErr = pgx.ErrNoRows
			},
		},
		{
			name: "organization name blank",
			configure: func(db *controllerLookupTestDB) {
				db.org.Name = "  "
			},
		},
		{
			name: "organization identity mismatched",
			configure: func(db *controllerLookupTestDB) {
				db.org.ID = uuid.New()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, db := newControllerLookupEngine(documentOrgID, "Customer Alpha AB")
			test.configure(db)
			if _, err := engine.LookupByToken(context.Background(), []byte("token-hash")); !errors.Is(err, ErrSignerControllerUnavailable) {
				t.Fatalf("LookupByToken error = %v, want ErrSignerControllerUnavailable", err)
			}
		})
	}
}

func TestLookupByTokenFailsClosedWithoutExplicitLawfulBasisConfirmation(t *testing.T) {
	documentOrgID := uuid.New()
	tests := []struct {
		name      string
		configure func(*controllerLookupTestDB)
	}{
		{
			name: "database default is unconfirmed",
			configure: func(db *controllerLookupTestDB) {
				db.confirmation = nil
			},
		},
		{
			name: "unsupported stored value",
			configure: func(db *controllerLookupTestDB) {
				db.document.LawfulBasis = "unknown"
				db.confirmation.LawfulBasis = "unknown"
			},
		},
		{
			name: "confirmation belongs to another organization",
			configure: func(db *controllerLookupTestDB) {
				db.confirmation.OrgID = uuid.New()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			engine, db := newControllerLookupEngine(documentOrgID, "Customer Alpha AB")
			test.configure(db)
			if _, err := engine.LookupByToken(context.Background(), []byte("token-hash")); !errors.Is(err, ErrSignerLawfulBasisUnavailable) {
				t.Fatalf("LookupByToken error = %v, want ErrSignerLawfulBasisUnavailable", err)
			}
		})
	}
}
