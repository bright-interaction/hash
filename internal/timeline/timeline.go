// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package timeline implements Phase 8.8: audit-event timeline + per-org
// activity feed read surface. The events table from week 1 already
// captures every state-changing action (sends, opens, views, signs,
// declines, expirations, reminders, webhook dispatches, MCP writes); this
// package shapes them for human consumption.
//
// Grouping: consecutive events from the same actor + kind family within
// 5 minutes collapse into a single Entry with an Occurrences count, so a
// signer who clicks five times doesn't fill the page.
//
// Inline diffs: when a `document.updated` entry's payload references a
// version (and the caller asks for diffs), the timeline can resolve the
// next-prior version via the Phase 8.1 versions.Engine and embed the
// block-level change list inline.
//
// CSV export: a stable column layout so legal exports stay grep-friendly
// across schema bumps. PDF export defers to Phase 10.2 (full PDF/A-3
// evidence package).
package timeline

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// Entry is one logical event in the timeline. Multiple raw events from
// the same actor + kind within 5 minutes collapse into one Entry with
// Occurrences > 1; the earliest CreatedAt becomes the entry's timestamp.
type Entry struct {
	ID           string          `json:"id"`
	DocumentID   string          `json:"document_id"`
	Kind         string          `json:"kind"`
	ActorUserID  string          `json:"actor_user_id,omitempty"`
	ActorEmail   string          `json:"actor_email,omitempty"`
	RecipientID  string          `json:"recipient_id,omitempty"`
	IP           string          `json:"ip,omitempty"`
	UserAgent    string          `json:"user_agent,omitempty"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	CreatedAt    string          `json:"created_at"`
	Occurrences  int             `json:"occurrences"`
	GroupedKinds []string        `json:"grouped_kinds,omitempty"`
	DiffChanges  any             `json:"diff_changes,omitempty"`
}

// GroupWindow is the consecutive-events-collapse window. 5 minutes
// follows the original plan; tweak in one place if usability feedback
// warrants.
const GroupWindow = 5 * time.Minute

// Filter narrows the raw event scan. Empty fields mean "no filter".
type Filter struct {
	Kinds []string
	Since *time.Time
	Until *time.Time
	Limit int32
}

// Effective normalizes the filter for sqlc. Empty slices become nil so
// the SQL ANY() guard falls through to "match all".
func (f Filter) Effective() (kinds []string, since, until pgtypeTS, limit int32) {
	if len(f.Kinds) > 0 {
		kinds = f.Kinds
	}
	if f.Since != nil {
		since.set(*f.Since)
	}
	if f.Until != nil {
		until.set(*f.Until)
	}
	limit = f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	return
}

// pgtypeTS is a tiny wrapper to keep callers from importing pgtype just
// for an optional timestamptz. Zero value is "not set" (sqlc treats it
// as NULL via the := IS NULL guard).
type pgtypeTS struct {
	t     time.Time
	valid bool
}

func (p *pgtypeTS) set(t time.Time) { p.t = t; p.valid = true }
func (p pgtypeTS) Valid() bool      { return p.valid }
func (p pgtypeTS) Time() time.Time  { return p.t }

// FromEvent converts a raw event row into an Entry (no grouping yet).
// Callers feed a slice of these through Group to collapse runs.
func FromEvent(e *generated.Event) Entry {
	out := Entry{
		ID:          e.ID.String(),
		Kind:        e.Kind,
		Payload:     e.PayloadJson,
		Occurrences: 1,
	}
	if e.DocumentID.Valid {
		out.DocumentID = uuid.UUID(e.DocumentID.Bytes).String()
	}
	if e.ActorUserID.Valid {
		out.ActorUserID = uuid.UUID(e.ActorUserID.Bytes).String()
	}
	if e.RecipientID.Valid {
		out.RecipientID = uuid.UUID(e.RecipientID.Bytes).String()
	}
	if e.Ip != nil && e.Ip.IsValid() {
		out.IP = e.Ip.String()
	}
	out.UserAgent = e.Ua.String
	out.CreatedAt = e.CreatedAt.Time.UTC().Format(time.RFC3339)
	return out
}

// Group collapses consecutive same-actor + same-kind entries within
// GroupWindow into a single Entry whose Occurrences count reflects the
// run length. Input slice is assumed to be sorted by CreatedAt DESC (the
// list endpoints already do this); Group walks it newest-first and
// emits the same order out.
func Group(entries []Entry) []Entry {
	if len(entries) == 0 {
		return entries
	}
	out := make([]Entry, 0, len(entries))
	cur := entries[0]
	curT := mustParseTS(cur.CreatedAt)
	for i := 1; i < len(entries); i++ {
		e := entries[i]
		eT := mustParseTS(e.CreatedAt)
		if e.ActorUserID == cur.ActorUserID &&
			sameKindFamily(e.Kind, cur.Kind) &&
			(curT.Sub(eT) <= GroupWindow) {
			cur.Occurrences++
			cur.GroupedKinds = appendIfMissing(cur.GroupedKinds, e.Kind)
			// keep cur's timestamp as the newest; advance curT to the
			// oldest so the window slides as far as the run extends
			curT = eT
			continue
		}
		out = append(out, cur)
		cur = e
		curT = eT
	}
	out = append(out, cur)
	return out
}

// sameKindFamily decides whether two event kinds collapse into the same
// run. We group strictly when kinds match. Future tuning: group
// document.viewed + document.opened (a click that follows an email open)
// when feedback says it's noise.
func sameKindFamily(a, b string) bool {
	return a == b
}

func appendIfMissing(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func mustParseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// AttachDiffs walks `entries` and, for each `document.updated` event,
// fetches the two surrounding versions from the supplied lookup and
// embeds the block-level diff inline. The lookup signature is kept
// generic so callers can wire versions.Engine or a fake in tests.
//
// nextVersionNoFor(t) returns the version_no of the version snapshotted
// AT or RIGHT AFTER the event timestamp. The diff is computed between
// that version's predecessor and itself, mirroring what a human would
// expect ("show me what changed in this edit").
type VersionDiffLookup func(docID string, eventTime time.Time) (changes any, present bool, err error)

func AttachDiffs(entries []Entry, lookup VersionDiffLookup) ([]Entry, error) {
	if lookup == nil {
		return entries, nil
	}
	out := make([]Entry, len(entries))
	copy(out, entries)
	for i, e := range out {
		if e.Kind != "document.updated" || e.DocumentID == "" {
			continue
		}
		t := mustParseTS(e.CreatedAt)
		changes, present, err := lookup(e.DocumentID, t)
		if err != nil {
			return out, fmt.Errorf("diff lookup for %s: %w", e.ID, err)
		}
		if !present {
			continue
		}
		out[i].DiffChanges = changes
	}
	return out, nil
}

// AttachActorEmails resolves actor_user_id -> email so the timeline UI
// can display human names without an N+1 fetch in the frontend. The
// resolver signature mirrors the same shape we use elsewhere; tests can
// supply a static map.
type ActorEmailLookup func(actorIDs []string) (map[string]string, error)

func AttachActorEmails(entries []Entry, lookup ActorEmailLookup) ([]Entry, error) {
	if lookup == nil {
		return entries, nil
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, e := range entries {
		if e.ActorUserID == "" || seen[e.ActorUserID] {
			continue
		}
		seen[e.ActorUserID] = true
		ids = append(ids, e.ActorUserID)
	}
	if len(ids) == 0 {
		return entries, nil
	}
	emails, err := lookup(ids)
	if err != nil {
		return entries, fmt.Errorf("actor email lookup: %w", err)
	}
	out := make([]Entry, len(entries))
	copy(out, entries)
	for i, e := range out {
		if email, ok := emails[e.ActorUserID]; ok {
			out[i].ActorEmail = email
		}
	}
	return out, nil
}

// SortByTimeDesc is a defensive sort callers can use if they doubt the
// source order (e.g. a merged stream from two queries).
func SortByTimeDesc(entries []Entry) {
	sort.SliceStable(entries, func(i, j int) bool {
		return mustParseTS(entries[i].CreatedAt).After(mustParseTS(entries[j].CreatedAt))
	})
}

// ExportCSV streams the timeline as a stable-column CSV: timestamp,
// kind, actor_email, actor_user_id, document_id, recipient_id, ip,
// user_agent, payload. Designed for legal exports so the column order
// must NOT change across releases without a schema-style bump.
func ExportCSV(w io.Writer, entries []Entry) error {
	if w == nil {
		return errors.New("nil writer")
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{
		"timestamp", "kind", "actor_email", "actor_user_id",
		"document_id", "recipient_id", "ip", "user_agent",
		"occurrences", "payload_json",
	}); err != nil {
		return err
	}
	for _, e := range entries {
		if err := cw.Write([]string{
			csvSafe(e.CreatedAt),
			csvSafe(e.Kind),
			csvSafe(e.ActorEmail),
			csvSafe(e.ActorUserID),
			csvSafe(e.DocumentID),
			csvSafe(e.RecipientID),
			csvSafe(e.IP),
			csvSafe(e.UserAgent),
			fmt.Sprintf("%d", e.Occurrences),
			csvSafe(string(e.Payload)),
		}); err != nil {
			return err
		}
	}
	return nil
}

// csvSafe neutralises CSV formula injection: a cell beginning with =, +, -, @,
// tab, or CR is interpreted as a live formula by Excel/Sheets. Signer-supplied
// values (User-Agent, typed names in the payload) reach this legal export, so
// any such cell gets a leading apostrophe (the OWASP-recommended neutraliser).
// The stable column order/contract is unchanged; only hostile cells are quoted.
func csvSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
