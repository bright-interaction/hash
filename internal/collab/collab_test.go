package collab

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakePeer is a test-only Peer that captures every Send in a slice.
// Concurrency-safe so the hub's broadcast goroutine can drive it.
type fakePeer struct {
	id          string
	userID      uuid.UUID
	displayName string
	mu          sync.Mutex
	frames      [][]byte
}

func newFakePeer(name string) *fakePeer {
	return &fakePeer{
		id:          name,
		userID:      uuid.New(),
		displayName: name,
	}
}

func (p *fakePeer) ID() string          { return p.id }
func (p *fakePeer) UserID() uuid.UUID   { return p.userID }
func (p *fakePeer) DisplayName() string { return p.displayName }

func (p *fakePeer) Send(_ context.Context, frame []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	copy := append([]byte(nil), frame...)
	p.frames = append(p.frames, copy)
	return nil
}

func (p *fakePeer) Received() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]byte, len(p.frames))
	for i, f := range p.frames {
		out[i] = append([]byte(nil), f...)
	}
	return out
}

func TestHub_JoinReturnsEmptyStateOnFirstPeer(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Second
	docID := uuid.New()
	orgID := uuid.New()
	peer := newFakePeer("alice")
	res, err := h.Join(context.Background(), docID, orgID, peer)
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if len(res.InitialState) != 0 {
		t.Errorf("expected empty initial state, got %d bytes", len(res.InitialState))
	}
	if res.Room.PeerCount() != 1 {
		t.Errorf("expected peer count 1, got %d", res.Room.PeerCount())
	}
}

func TestHub_BroadcastsUpdatesToOtherPeers(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour // don't fight the test on a flush
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	bob := newFakePeer("bob")
	carol := newFakePeer("carol")
	aRes, _ := h.Join(context.Background(), docID, orgID, alice)
	_, _ = h.Join(context.Background(), docID, orgID, bob)
	_, _ = h.Join(context.Background(), docID, orgID, carol)
	defer h.Leave(context.Background(), docID, alice.ID())
	defer h.Leave(context.Background(), docID, bob.ID())
	defer h.Leave(context.Background(), docID, carol.ID())

	// Alice sends a sync_update frame: [0x00 sync, 0x02 update, <bytes>]
	updateBytes := []byte{0x11, 0x22, 0x33}
	frame := append([]byte{MessageSync, SyncUpdate}, updateBytes...)
	if err := aRes.Room.HandleFrame(context.Background(), alice, frame); err != nil {
		t.Fatalf("handle: %v", err)
	}
	// Alice should not receive her own frame.
	if got := alice.Received(); len(got) != 0 {
		t.Errorf("alice should not see her own broadcast, got %d frames", len(got))
	}
	// Bob + Carol each receive the same frame.
	for _, p := range []*fakePeer{bob, carol} {
		got := p.Received()
		if len(got) != 1 {
			t.Errorf("%s: expected 1 frame, got %d", p.id, len(got))
			continue
		}
		if !bytesEqual(got[0], frame) {
			t.Errorf("%s: frame mismatch", p.id)
		}
	}
	// State log should contain the update bytes (header is stripped).
	if aRes.Room.StateLen() != len(updateBytes) {
		t.Errorf("state len = %d, want %d", aRes.Room.StateLen(), len(updateBytes))
	}
}

func TestHub_SyncStep1RespondsWithSyncStep2(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	res, _ := h.Join(context.Background(), docID, orgID, alice)

	// Seed the room with some state by sending an update first.
	seed := []byte{0xAA, 0xBB}
	updateFrame := append([]byte{MessageSync, SyncUpdate}, seed...)
	_ = res.Room.HandleFrame(context.Background(), alice, updateFrame)

	// Now alice asks for state via sync_step1; she should get a
	// sync_step2 frame carrying the seed bytes.
	bob := newFakePeer("bob")
	bRes, _ := h.Join(context.Background(), docID, orgID, bob)
	step1 := []byte{MessageSync, SyncStep1, 0x00}
	if err := bRes.Room.HandleFrame(context.Background(), bob, step1); err != nil {
		t.Fatalf("handle step1: %v", err)
	}
	got := bob.Received()
	if len(got) == 0 {
		t.Fatal("bob never got a sync_step2 response")
	}
	resp := got[0]
	if len(resp) < 2 || resp[0] != MessageSync || resp[1] != SyncStep2 {
		t.Errorf("response not sync_step2: %v", resp)
	}
	if !bytesEqual(resp[2:], seed) {
		t.Errorf("step2 payload = %v, want %v", resp[2:], seed)
	}
}

func TestHub_AwarenessIsRelayedNotPersisted(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	bob := newFakePeer("bob")
	aRes, _ := h.Join(context.Background(), docID, orgID, alice)
	_, _ = h.Join(context.Background(), docID, orgID, bob)

	frame := []byte{MessageAwareness, 0x01, 0x02, 0x03}
	if err := aRes.Room.HandleFrame(context.Background(), alice, frame); err != nil {
		t.Fatal(err)
	}
	if len(bob.Received()) != 1 {
		t.Errorf("bob should receive awareness frame; got %d", len(bob.Received()))
	}
	if aRes.Room.StateLen() != 0 {
		t.Errorf("awareness should NOT touch state log; got %d bytes", aRes.Room.StateLen())
	}
}

func TestHub_LeaveTearsDownRoomAfterLastPeer(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	h.Join(context.Background(), docID, orgID, alice)
	h.Leave(context.Background(), docID, alice.ID())
	h.mu.Lock()
	_, ok := h.rooms[docID]
	h.mu.Unlock()
	if ok {
		t.Error("room should be removed once empty")
	}
}

func TestHub_RejectsEmptyFrame(t *testing.T) {
	h := NewHub(nil)
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	res, _ := h.Join(context.Background(), docID, orgID, alice)
	err := res.Room.HandleFrame(context.Background(), alice, nil)
	if err == nil {
		t.Error("expected error on empty frame")
	}
}

func TestHub_RejectsUnknownMessageType(t *testing.T) {
	h := NewHub(nil)
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	res, _ := h.Join(context.Background(), docID, orgID, alice)
	err := res.Room.HandleFrame(context.Background(), alice, []byte{0xFF})
	if err == nil {
		t.Error("expected error on unknown message type")
	}
}

func TestHub_DedupesIdenticalTrailingUpdates(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	res, _ := h.Join(context.Background(), docID, orgID, alice)

	frame := []byte{MessageSync, SyncUpdate, 0xCA, 0xFE}
	_ = res.Room.HandleFrame(context.Background(), alice, frame)
	first := res.Room.StateLen()
	_ = res.Room.HandleFrame(context.Background(), alice, frame)
	second := res.Room.StateLen()
	if first != second {
		t.Errorf("retransmit should be deduped; first=%d second=%d", first, second)
	}
}

func TestHub_TriggersCompactionAboveThreshold(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	h.CompactionThreshold = 64 // tiny so a single update trips it
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	bob := newFakePeer("bob")
	_, _ = h.Join(context.Background(), docID, orgID, alice)
	bRes, _ := h.Join(context.Background(), docID, orgID, bob)

	// Push enough bytes through alice to cross the 64-byte threshold.
	big := make([]byte, 0, 80)
	for i := 0; i < 80; i++ {
		big = append(big, byte(i))
	}
	frame := append([]byte{MessageSync, SyncUpdate}, big...)
	if err := bRes.Room.HandleFrame(context.Background(), alice, frame); err != nil {
		t.Fatalf("handle: %v", err)
	}

	// Expect the lower-id peer (alice) to receive a compact-request frame
	// with a 16-byte nonce after its own update was broadcast back through
	// the room. Locate the request in the slice; broadcast skips the
	// sender, so alice's received frames are compact-only.
	got := alice.Received()
	var req []byte
	for _, f := range got {
		if len(f) >= 2 && f[0] == MessageCompact && f[1] == CompactRequest {
			req = f
			break
		}
	}
	if req == nil {
		t.Fatalf("alice never got a compact-request; received frames=%d", len(got))
	}
	if len(req) != 2+16 {
		t.Fatalf("compact request length = %d, want 18", len(req))
	}

	// Apply a fake snapshot back and confirm state shrinks.
	var nonce [16]byte
	copy(nonce[:], req[2:2+16])
	// A real Yjs full-state encode never collapses an 80-byte log to a few
	// bytes, so keep the sample snapshot above applySnapshot's degenerate
	// floor (>=8 bytes when the old state is >=64) while still smaller than
	// the log it replaces, so it both passes the guard and shrinks state.
	snapshot := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	respFrame := append([]byte{MessageCompact, CompactSnapshot}, nonce[:]...)
	respFrame = append(respFrame, snapshot...)
	if err := bRes.Room.HandleFrame(context.Background(), alice, respFrame); err != nil {
		t.Fatalf("handle snapshot: %v", err)
	}
	if bRes.Room.StateLen() != len(snapshot) {
		t.Errorf("post-compaction state len = %d, want %d", bRes.Room.StateLen(), len(snapshot))
	}
}

func TestHub_RejectsCompactionWithBadNonce(t *testing.T) {
	h := NewHub(nil)
	h.FlushEvery = time.Hour
	h.CompactionThreshold = 16
	docID := uuid.New()
	orgID := uuid.New()
	alice := newFakePeer("alice")
	res, _ := h.Join(context.Background(), docID, orgID, alice)

	// Cross the threshold so a compaction is requested.
	frame := append([]byte{MessageSync, SyncUpdate}, make([]byte, 32)...)
	_ = res.Room.HandleFrame(context.Background(), alice, frame)
	originalLen := res.Room.StateLen()

	// Send a snapshot with the wrong nonce; should be ignored.
	var wrong [16]byte
	for i := range wrong {
		wrong[i] = 0xFF
	}
	bad := append([]byte{MessageCompact, CompactSnapshot}, wrong[:]...)
	bad = append(bad, 0x01)
	if err := res.Room.HandleFrame(context.Background(), alice, bad); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if res.Room.StateLen() != originalLen {
		t.Errorf("state should be unchanged on bad nonce; got %d, want %d", res.Room.StateLen(), originalLen)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
