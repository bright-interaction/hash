// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestPrepareSignerFieldValuesValidatesWholeBatchBeforeMutation(t *testing.T) {
	required := &generated.DocumentField{ID: uuid.New(), Type: "text", Required: true}
	optional := &generated.DocumentField{ID: uuid.New(), Type: "checkbox"}
	dropdown := &generated.DocumentField{ID: uuid.New(), Type: "dropdown", OptionsJson: json.RawMessage(`{"choices":["One","Two"]}`)}
	date := &generated.DocumentField{ID: uuid.New(), Type: "date"}
	initial := &generated.DocumentField{ID: uuid.New(), Type: "initial"}
	signature := &generated.DocumentField{ID: uuid.New(), Type: "signature"}
	allowed := []*generated.DocumentField{required, optional, dropdown, date, initial, signature}

	prepared, validationErr := prepareSignerFieldValues(allowed, []submitFieldValueInput{
		{FieldID: required.ID.String(), Value: "  agreed  "},
		{FieldID: optional.ID.String(), Value: " true "},
		{FieldID: dropdown.ID.String(), Value: " Two "},
		{FieldID: date.ID.String(), Value: " 2026-08-31 "},
		{FieldID: initial.ID.String(), Value: " ÅÖ "},
	})
	if validationErr != nil || len(prepared) != 5 || prepared[0].value != "agreed" || prepared[1].value != "true" ||
		prepared[2].value != "Two" || prepared[3].value != "2026-08-31" || prepared[4].value != "ÅÖ" {
		t.Fatalf("valid batch = %#v, %#v", prepared, validationErr)
	}

	cases := []struct {
		name   string
		values []submitFieldValueInput
		status int
	}{
		{"duplicate", []submitFieldValueInput{{FieldID: required.ID.String(), Value: "x"}, {FieldID: required.ID.String(), Value: "y"}}, http.StatusBadRequest},
		{"unassigned later in batch", []submitFieldValueInput{{FieldID: required.ID.String(), Value: "x"}, {FieldID: uuid.NewString(), Value: "y"}}, http.StatusForbidden},
		{"signature later in batch", []submitFieldValueInput{{FieldID: required.ID.String(), Value: "x"}, {FieldID: signature.ID.String(), Value: "fake"}}, http.StatusBadRequest},
		{"required blank later in batch", []submitFieldValueInput{{FieldID: optional.ID.String(), Value: "false"}, {FieldID: required.ID.String(), Value: "  "}}, http.StatusBadRequest},
		{"oversized text", []submitFieldValueInput{{FieldID: required.ID.String(), Value: strings.Repeat("x", maxSignerFieldValueBytes+1)}}, http.StatusBadRequest},
		{"invalid checkbox", []submitFieldValueInput{{FieldID: optional.ID.String(), Value: "yes"}}, http.StatusBadRequest},
		{"invalid date", []submitFieldValueInput{{FieldID: date.ID.String(), Value: "31/08/2026"}}, http.StatusBadRequest},
		{"overlong initials", []submitFieldValueInput{{FieldID: initial.ID.String(), Value: "TOOLONG"}}, http.StatusBadRequest},
		{"dropdown injection", []submitFieldValueInput{{FieldID: dropdown.ID.String(), Value: "Three"}}, http.StatusBadRequest},
		{"control character", []submitFieldValueInput{{FieldID: required.ID.String(), Value: "line\nbreak"}}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, gotErr := prepareSignerFieldValues(allowed, tc.values)
			if got != nil || gotErr == nil || gotErr.status != tc.status {
				t.Fatalf("prepared/error = %#v/%#v, want nil/status %d", got, gotErr, tc.status)
			}
		})
	}
}

func TestRecipientCanFillFieldsRejectsCapturedResponse(t *testing.T) {
	for _, status := range []string{"pending", "sent", "viewed"} {
		if !recipientCanFillFields(status) {
			t.Fatalf("active recipient status %q rejected", status)
		}
	}
	for _, status := range []string{"signed", "accepted", "declined", "bounced", ""} {
		if recipientCanFillFields(status) {
			t.Fatalf("terminal/ineligible recipient status %q accepted", status)
		}
	}
}
