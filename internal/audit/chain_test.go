package audit

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
)

func baseInput() HashInput {
	return HashInput{
		OrgID:     uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Kind:      "document.created",
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(),
		Payload:   []byte(`{"a":1}`),
	}
}

func TestChainHash_GenesisFixedLength(t *testing.T) {
	if got := ChainHashRecord(baseInput()); len(got) != 32 {
		t.Errorf("hash must be 32 bytes, got %d", len(got))
	}
}

func TestChainHash_KindChangeBreaksHash(t *testing.T) {
	a := ChainHashRecord(baseInput())
	in := baseInput()
	in.Kind = "document.updated"
	if bytes.Equal(a, ChainHashRecord(in)) {
		t.Error("hash must change when kind changes")
	}
}

func TestChainHash_PayloadChangeBreaksHash(t *testing.T) {
	a := ChainHashRecord(baseInput())
	in := baseInput()
	in.Payload = []byte(`{"a":2}`)
	if bytes.Equal(a, ChainHashRecord(in)) {
		t.Error("hash must change when payload changes")
	}
}

func TestChainHash_PrevChangeBreaksHash(t *testing.T) {
	in1 := baseInput()
	in1.Prev = make([]byte, 32)
	in2 := baseInput()
	in2.Prev = make([]byte, 32)
	in2.Prev[0] = 0x01
	if bytes.Equal(ChainHashRecord(in1), ChainHashRecord(in2)) {
		t.Error("hash must change when prev_hash changes")
	}
}

func TestChainHash_ForensicFieldsBound(t *testing.T) {
	// Editing ip, ua, actor, created_at, or document/recipient must change the
	// hash so those columns can't be tampered without detection.
	base := baseInput()
	a := ChainHashRecord(base)

	mutators := map[string]func(*HashInput){
		"ip":         func(h *HashInput) { h.IP = "1.2.3.4" },
		"ua":         func(h *HashInput) { h.UA = "curl/8" },
		"actor":      func(h *HashInput) { h.ActorID = uuid.MustParse("00000000-0000-0000-0000-0000000000aa") },
		"document":   func(h *HashInput) { h.DocID = uuid.MustParse("00000000-0000-0000-0000-0000000000bb") },
		"recipient":  func(h *HashInput) { h.RecID = uuid.MustParse("00000000-0000-0000-0000-0000000000cc") },
		"created_at": func(h *HashInput) { h.CreatedAt = h.CreatedAt.Add(time.Second) },
		"org":        func(h *HashInput) { h.OrgID = uuid.MustParse("00000000-0000-0000-0000-0000000000dd") },
	}
	for name, mut := range mutators {
		in := baseInput()
		mut(&in)
		if bytes.Equal(a, ChainHashRecord(in)) {
			t.Errorf("hash must change when %s changes", name)
		}
	}
}

func TestChainHash_LengthDelimitedNoBleed(t *testing.T) {
	// Length-prefixing must keep ("ab","c") distinct from ("a","bc") for any
	// adjacent variable fields (kind/ip here).
	a := baseInput()
	a.Kind = "ab"
	a.IP = "c"
	b := baseInput()
	b.Kind = "a"
	b.IP = "bc"
	if bytes.Equal(ChainHashRecord(a), ChainHashRecord(b)) {
		t.Error("missing length delimiter; adjacent fields collide")
	}
}

func TestChainHashHex_RoundTrip(t *testing.T) {
	if hx := ChainHashRecordHex(baseInput()); len(hx) != 64 {
		t.Errorf("hex length %d, want 64", len(hx))
	}
}
