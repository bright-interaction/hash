// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package recipients owns the canonical validation and normalization rules for
// recipient identity and routing data. Authoring surfaces and the send engine
// share these rules so malformed legacy rows can never reach a magic link or
// outbound email.
package recipients

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/i18n"
)

const (
	MaxEmailBytes = 254
	MaxNameRunes  = 200
	MaxNameBytes  = 800
	MaxOrderIndex = 1000
)

var (
	rolePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	// Upstream CRMs and Google commonly persist regional language tags such as
	// sv-SE or en_US, while Hash's reviewed message catalog is keyed by base
	// language. Accept only an ASCII language-tag shape and deliberately reduce
	// it to a shipped base locale; an unknown base still fails closed.
	regionalLocalePattern = regexp.MustCompile(`^[A-Za-z]{2,8}(?:[-_][A-Za-z0-9]{1,8})+$`)
)

// Values is the complete persisted recipient identity and routing record.
type Values struct {
	Email      string
	Name       string
	Role       string
	OrderIndex int32
	Locale     string
}

// ValidationError identifies the rejected field without including its value,
// which may contain recipient PII.
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid recipient %s: %s", e.Field, e.Reason)
}

// Normalize trims canonical text boundaries, lower-cases the enumerated
// routing values, and validates all fields. Callers must persist the returned
// value rather than the untrusted input.
func Normalize(in Values) (Values, error) {
	out := in
	out.Email = strings.TrimSpace(in.Email)
	out.Name = strings.TrimSpace(in.Name)
	out.Role = strings.ToLower(strings.TrimSpace(in.Role))
	out.Locale = strings.ToLower(strings.TrimSpace(in.Locale))
	if !i18n.Has(out.Locale) && regionalLocalePattern.MatchString(strings.TrimSpace(in.Locale)) {
		if separator := strings.IndexAny(out.Locale, "-_"); separator > 0 {
			base := out.Locale[:separator]
			if i18n.Has(base) {
				out.Locale = base
			}
		}
	}

	if out.Email == "" {
		return Values{}, invalid("email", "is required")
	}
	if !utf8.ValidString(out.Email) {
		return Values{}, invalid("email", "must be valid UTF-8")
	}
	if len(out.Email) > MaxEmailBytes {
		return Values{}, invalid("email", "is too long")
	}
	for _, r := range out.Email {
		if unicode.IsControl(r) {
			return Values{}, invalid("email", "must not contain control characters")
		}
	}
	addr, err := mail.ParseAddress(out.Email)
	if err != nil || addr.Name != "" || addr.Address != out.Email {
		return Values{}, invalid("email", "must be a simple email address without a display name")
	}

	if out.Name == "" {
		return Values{}, invalid("name", "is required")
	}
	if !utf8.ValidString(out.Name) {
		return Values{}, invalid("name", "must be valid UTF-8")
	}
	if len(out.Name) > MaxNameBytes || utf8.RuneCountInString(out.Name) > MaxNameRunes {
		return Values{}, invalid("name", "is too long")
	}
	for _, r := range out.Name {
		if unicode.IsControl(r) {
			return Values{}, invalid("name", "must not contain control characters")
		}
	}

	if !rolePattern.MatchString(out.Role) {
		return Values{}, invalid("role", "must be 1-64 lowercase letters, digits, underscore, or hyphen and start with a letter")
	}
	if out.OrderIndex < 0 || out.OrderIndex > MaxOrderIndex {
		return Values{}, invalid("order_index", "must be between 0 and 1000")
	}
	if out.Locale == "" || !i18n.Has(out.Locale) {
		return Values{}, invalid("locale", "is not supported")
	}
	return out, nil
}

// ValidatePersisted applies the same validation but also requires the stored
// value to already be canonical. Send-time callers cannot safely repair legal
// ceremony data in memory, so a legacy row needing normalization must be
// corrected while the document is still a draft.
func ValidatePersisted(in Values) error {
	out, err := Normalize(in)
	if err != nil {
		return err
	}
	switch {
	case out.Email != in.Email:
		return invalid("email", "is not normalized")
	case out.Name != in.Name:
		return invalid("name", "is not normalized")
	case out.Role != in.Role:
		return invalid("role", "is not normalized")
	case out.Locale != in.Locale:
		return invalid("locale", "is not normalized")
	default:
		return nil
	}
}

// HasTerminalResponse reports whether a recipient completed the document's
// response ceremony. Signature-mode recipients finish as signed;
// acknowledgement-mode recipients finish as accepted. Keep this shared so
// privacy gates do not accidentally make one completed ceremony permanently
// unreadable by recognizing only the other mode.
func HasTerminalResponse(status string) bool {
	return status == "signed" || status == "accepted"
}

// CanRespond reports whether role is a canonical participant role supported
// by the current signature/acknowledgement lifecycle. Informational cc/viewer
// delivery has no complete invite/response state machine in this release, so
// authoring surfaces must not create those unsendable recipients.
func CanRespond(role string) bool {
	return rolePattern.MatchString(role) && role != "cc" && role != "viewer"
}

// ValidateResponseRole returns the same field-scoped error shape as Normalize
// so REST and MCP authoring surfaces can reject unsupported routing roles
// consistently after normalization.
func ValidateResponseRole(role string) error {
	if !CanRespond(role) {
		return invalid("role", "must be a signing or acknowledgement role; cc and viewer delivery is unavailable")
	}
	return nil
}

func invalid(field, reason string) error {
	return &ValidationError{Field: field, Reason: reason}
}
