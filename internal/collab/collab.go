// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package collab implements v1.1 Yjs collaborative editing for the
// block editor. The server is a relay: clients hold the CRDT state,
// the server only:
//
//  1. Broadcasts binary updates between connected peers on a per-
//     document hub.
//  2. Persists a snapshot of the document state so a fresh client
//     gets the current state at connect time.
//  3. Tracks awareness (cursors, user labels) so peers can render
//     "Alice is typing here" indicators.
//
// Wire protocol matches y-websocket so the standard yjs client library
// plugs in without a custom adapter:
//
//   - Binary frames only
//   - Message types (first byte):
//     0x00  sync   (subtypes: 0=sync_step1, 1=sync_step2, 2=update)
//     0x01  awareness
//     0x03  query awareness
//
// We forward frames as-is without re-encoding, so the Go side doesn't
// need a Yjs CRDT implementation. Persistence stores the most recent
// "sync_step2" + concatenated "update" frames as one append-only log
// per doc, which any Yjs client can replay via Y.applyUpdate.
package collab

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brightinteraction/hash/internal/db/generated"
)

// Message types per y-protocols/sync + y-protocols/awareness wire spec.
// MessageCompact is a Hash extension: the server asks a peer for a
// freshly-encoded full doc state so the append-only log can be replaced
// with one self-contained snapshot.
const (
	MessageSync       = 0x00
	MessageAwareness  = 0x01
	MessageAuth       = 0x02
	MessageQueryAware = 0x03
	MessageCompact    = 0x04
	SyncStep1         = 0x00
	SyncStep2         = 0x01
	SyncUpdate        = 0x02
	CompactRequest    = 0x00
	CompactSnapshot   = 0x01
)

// DefaultCompactionThreshold is the size (bytes) above which the room
// asks a connected peer for a fresh snapshot.
const DefaultCompactionThreshold = 1 << 20 // 1 MiB

// CompactionTimeout is how long a pending compaction request is allowed
// to sit unanswered before we let a new one fire.
const CompactionTimeout = 10 * time.Second

// Hub is the process-wide collab server. Holds one Room per active
// document; rooms are created on first connect + torn down when the
// last peer leaves (after flushing state to the DB).
type Hub struct {
	Queries             *generated.Queries
	FlushEvery          time.Duration // how often a busy room writes to DB; default 5s
	IdleTimeout         time.Duration // how long an empty room sticks around for late joiners; default 0 (immediate teardown)
	CompactionThreshold int           // size in bytes above which we ask a peer for a snapshot; default 1 MiB

	mu    sync.Mutex
	rooms map[uuid.UUID]*Room
}

// NewHub constructs a Hub with sensible defaults.
func NewHub(q *generated.Queries) *Hub {
	return &Hub{
		Queries:             q,
		FlushEvery:          5 * time.Second,
		IdleTimeout:         0,
		CompactionThreshold: DefaultCompactionThreshold,
		rooms:               map[uuid.UUID]*Room{},
	}
}

// Shutdown flushes every live room to the DB and tears them down. Wire it into
// the server's graceful-shutdown path so a SIGTERM/deploy doesn't drop the
// edits each room accumulated since its last periodic flush (up to FlushEvery).
func (h *Hub) Shutdown(ctx context.Context) {
	h.mu.Lock()
	rooms := make([]*Room, 0, len(h.rooms))
	for id, r := range h.rooms {
		rooms = append(rooms, r)
		delete(h.rooms, id)
	}
	h.mu.Unlock()
	for _, r := range rooms {
		r.close(ctx)
	}
}

// Peer is the connection-side view of a single client. Implementations
// wrap a websocket; tests can use an in-memory adapter that buffers
// frames in a channel.
type Peer interface {
	// ID is unique per connection; clients with multiple tabs each get
	// their own peer ID.
	ID() string
	// Send forwards a binary frame to this peer. Returns an error if
	// the underlying transport is closed.
	Send(ctx context.Context, frame []byte) error
	// UserID is the authenticated user for the connection, for audit
	// + awareness labels.
	UserID() uuid.UUID
	// DisplayName is the human-readable label shown next to remote
	// cursors. Falls back to user email if name is empty.
	DisplayName() string
}

// Room is the per-document state. Holds the peer set + the persisted
// state blob; serializes broadcasts behind a mutex so peers never see
// out-of-order frames.
type Room struct {
	hub        *Hub
	documentID uuid.UUID
	orgID      uuid.UUID

	mu          sync.Mutex
	peers       map[string]Peer
	state       []byte // append-only Yjs update log
	dirty       bool
	pending     int // updates since last flush
	closed      bool
	flushCh     chan struct{}
	flushDoneCh chan struct{}

	compactionPending   bool
	compactionNonce     [16]byte
	compactionStartedAt time.Time
}

// JoinResult is what a fresh peer receives on connect: the persisted
// state to bootstrap their local Y.Doc and a Send hook for outgoing
// frames.
type JoinResult struct {
	Room         *Room
	InitialState []byte // raw bytes a y-websocket client unwraps via Y.applyUpdate
}

// Join attaches the peer to the room for documentID, loading persisted
// state from the DB on first join.
func (h *Hub) Join(ctx context.Context, documentID, orgID uuid.UUID, peer Peer) (*JoinResult, error) {
	h.mu.Lock()
	room, ok := h.rooms[documentID]
	if !ok {
		room = &Room{
			hub:         h,
			documentID:  documentID,
			orgID:       orgID,
			peers:       map[string]Peer{},
			flushCh:     make(chan struct{}, 1),
			flushDoneCh: make(chan struct{}),
		}
		h.rooms[documentID] = room
		// Load persisted state outside the hub mutex.
		h.mu.Unlock()
		if err := room.loadInitialState(ctx); err != nil {
			slog.Warn("collab: load initial state", "doc_id", documentID, "err", err)
		}
		go room.flushLoop()
		h.mu.Lock()
	}
	room.mu.Lock()
	room.peers[peer.ID()] = peer
	state := append([]byte(nil), room.state...)
	room.mu.Unlock()
	h.mu.Unlock()
	return &JoinResult{Room: room, InitialState: state}, nil
}

// Leave removes the peer + tears the room down if it's now empty.
// Flushes the persisted state to the DB synchronously before
// teardown so a quick reconnect doesn't see stale bytes.
func (h *Hub) Leave(ctx context.Context, documentID uuid.UUID, peerID string) {
	h.mu.Lock()
	room, ok := h.rooms[documentID]
	if !ok {
		h.mu.Unlock()
		return
	}
	room.mu.Lock()
	delete(room.peers, peerID)
	empty := len(room.peers) == 0
	room.mu.Unlock()
	if empty {
		delete(h.rooms, documentID)
		h.mu.Unlock()
		room.close(ctx)
		return
	}
	h.mu.Unlock()
}

// loadInitialState reads any persisted Yjs state from the DB and
// stores it as the room's append-only log.
func (r *Room) loadInitialState(ctx context.Context) error {
	if r.hub == nil || r.hub.Queries == nil {
		return nil
	}
	row, err := r.hub.Queries.GetCollabDocState(ctx, r.documentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.state = append([]byte(nil), row.YdocState...)
	r.pending = int(row.UpdateCount)
	r.mu.Unlock()
	return nil
}

// HandleFrame routes a wire frame from a peer. Sync updates get
// appended to the room state + broadcast; awareness frames just relay.
// Returns an error if the frame is malformed.
func (r *Room) HandleFrame(ctx context.Context, sender Peer, frame []byte) error {
	if len(frame) == 0 {
		return errors.New("collab: empty frame")
	}
	switch frame[0] {
	case MessageSync:
		if len(frame) < 2 {
			return errors.New("collab: sync frame missing subtype")
		}
		switch frame[1] {
		case SyncStep1:
			// Peer asked for our state vector. Respond with our full
			// state as a sync_step2 frame so they can fast-forward.
			r.mu.Lock()
			state := append([]byte(nil), r.state...)
			r.mu.Unlock()
			if len(state) > 0 {
				resp := append([]byte{MessageSync, SyncStep2}, state...)
				_ = sender.Send(ctx, resp)
			}
		case SyncStep2, SyncUpdate:
			// Append the update bytes (skip the 2-byte header) to our
			// log + broadcast to other peers.
			update := frame[2:]
			r.appendUpdate(ctx, sender, update)
			r.broadcast(ctx, sender.ID(), frame)
		default:
			return fmt.Errorf("collab: unknown sync subtype %d", frame[1])
		}
	case MessageAwareness, MessageQueryAware:
		// Awareness is ephemeral (cursor positions, user labels). We
		// don't persist it; just relay between peers.
		r.broadcast(ctx, sender.ID(), frame)
	case MessageAuth:
		// Auth frames are advisory; the websocket-layer auth gate
		// already accepted this peer. Echo back so y-protocols stays
		// happy.
		_ = sender.Send(ctx, []byte{MessageAuth, 0x01})
	case MessageCompact:
		// Hash extension: peer is responding to a compact-request
		// with a freshly encoded full snapshot. We do not broadcast
		// this; only the server cares about the snapshot.
		if len(frame) < 2 {
			return errors.New("collab: compact frame missing subtype")
		}
		if frame[1] != CompactSnapshot {
			return fmt.Errorf("collab: unexpected compact subtype %d", frame[1])
		}
		if len(frame) < 2+16 {
			return errors.New("collab: compact snapshot frame too short")
		}
		var nonce [16]byte
		copy(nonce[:], frame[2:2+16])
		r.applySnapshot(nonce, frame[2+16:])
	default:
		return fmt.Errorf("collab: unknown message type %d", frame[0])
	}
	return nil
}

func (r *Room) appendUpdate(ctx context.Context, sender Peer, update []byte) {
	target, nonce, shouldRequest := r.applyAppend(update)
	if shouldRequest && target != nil {
		frame := make([]byte, 0, 2+16)
		frame = append(frame, MessageCompact, CompactRequest)
		frame = append(frame, nonce[:]...)
		if err := target.Send(ctx, frame); err != nil {
			slog.Debug("collab: compact request send", "peer_id", target.ID(), "err", err)
			r.mu.Lock()
			r.compactionPending = false
			r.mu.Unlock()
		}
	}
}

// applyAppend is the locked half of appendUpdate. Returns a peer + nonce
// when the log has crossed the compaction threshold and we want to ask
// for a fresh snapshot.
func (r *Room) applyAppend(update []byte) (Peer, [16]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var zeroNonce [16]byte
	// Yjs CRDT is associative + commutative; appending raw updates is
	// safe because the client unifies them via Y.applyUpdate. We do a
	// trivial de-dup so a chatty client retransmitting the same frame
	// doesn't bloat the log.
	if len(r.state) > 0 && len(update) > 0 && bytes.HasSuffix(r.state, update) {
		return nil, zeroNonce, false
	}
	r.state = append(r.state, update...)
	r.pending++
	r.dirty = true
	// Signal the flush loop without blocking; if the channel is full
	// the loop will pick up the work on its next tick.
	select {
	case r.flushCh <- struct{}{}:
	default:
	}

	threshold := DefaultCompactionThreshold
	if r.hub != nil && r.hub.CompactionThreshold > 0 {
		threshold = r.hub.CompactionThreshold
	}
	if r.compactionPending {
		if time.Since(r.compactionStartedAt) <= CompactionTimeout {
			return nil, zeroNonce, false
		}
		// Stale; let a new request fire below.
		r.compactionPending = false
	}
	if len(r.state) <= threshold || len(r.peers) == 0 {
		return nil, zeroNonce, false
	}
	// Pick the deterministically-lowest peer ID so we don't race two
	// snapshots from different peers.
	var target Peer
	var targetID string
	for id, p := range r.peers {
		if target == nil || id < targetID {
			target = p
			targetID = id
		}
	}
	if target == nil {
		return nil, zeroNonce, false
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, zeroNonce, false
	}
	r.compactionPending = true
	r.compactionNonce = nonce
	r.compactionStartedAt = time.Now()
	return target, nonce, true
}

// applySnapshot replaces the append-only log with a single freshly
// encoded full state from one peer. Rejects snapshots with mismatched
// nonces or that are larger than the log we were trying to shrink.
func (r *Room) applySnapshot(nonce [16]byte, snapshot []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.compactionPending {
		slog.Debug("collab: ignore snapshot, no pending compaction", "doc_id", r.documentID)
		return
	}
	if nonce != r.compactionNonce {
		slog.Debug("collab: ignore snapshot, nonce mismatch", "doc_id", r.documentID)
		return
	}
	r.compactionPending = false
	if len(snapshot) == 0 {
		return
	}
	// A correct snapshot should be smaller than the bloated log; allow
	// a 10% slack for varint framing differences. If it's bigger, the
	// peer is confused; leave the existing state alone.
	limit := len(r.state) + len(r.state)/10
	if limit > 0 && len(snapshot) > limit {
		slog.Warn("collab: reject oversized snapshot", "doc_id", r.documentID, "old", len(r.state), "new", len(snapshot))
		return
	}
	// Lower-bound guard: a real full-state encode of substantial content can't
	// collapse to a near-empty blob. A 1-byte/degenerate snapshot replacing a
	// non-trivial log means the peer sent a corrupt/half-initialised state, so
	// keep what we have rather than wiping the persisted doc.
	if len(r.state) >= 64 && len(snapshot) < 8 {
		slog.Warn("collab: reject degenerate snapshot", "doc_id", r.documentID, "old", len(r.state), "new", len(snapshot))
		return
	}
	oldSize := len(r.state)
	r.state = append([]byte(nil), snapshot...)
	r.pending = 0
	r.dirty = true
	select {
	case r.flushCh <- struct{}{}:
	default:
	}
	slog.Info("collab: compacted state", "doc_id", r.documentID, "from", oldSize, "to", len(snapshot))
}

func (r *Room) broadcast(ctx context.Context, exceptPeerID string, frame []byte) {
	r.mu.Lock()
	peers := make([]Peer, 0, len(r.peers))
	for id, p := range r.peers {
		if id == exceptPeerID {
			continue
		}
		peers = append(peers, p)
	}
	r.mu.Unlock()
	for _, p := range peers {
		if err := p.Send(ctx, frame); err != nil {
			slog.Debug("collab: peer send", "peer_id", p.ID(), "err", err)
		}
	}
}

// flushLoop debounces DB writes so a hot room doesn't hammer Postgres.
// Exits when close() is called.
func (r *Room) flushLoop() {
	if r.hub == nil || r.hub.FlushEvery <= 0 {
		close(r.flushDoneCh)
		return
	}
	ticker := time.NewTicker(r.hub.FlushEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.maybeFlush(context.Background())
		case <-r.flushCh:
			// Coalesce a few rapid updates into one flush.
			r.maybeFlush(context.Background())
		case <-r.flushDoneCh:
			return
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			close(r.flushDoneCh)
			return
		}
		r.mu.Unlock()
	}
}

func (r *Room) maybeFlush(ctx context.Context) {
	if r.hub == nil || r.hub.Queries == nil {
		return
	}
	r.mu.Lock()
	if !r.dirty || r.closed {
		r.mu.Unlock()
		return
	}
	state := append([]byte(nil), r.state...)
	count := r.pending
	r.dirty = false
	r.pending = 0
	var lastUser pgtype.UUID
	for _, p := range r.peers {
		uid := p.UserID()
		if uid != uuid.Nil {
			lastUser = pgtype.UUID{Bytes: uid, Valid: true}
			break
		}
	}
	r.mu.Unlock()
	_, err := r.hub.Queries.UpsertCollabDocState(ctx, generated.UpsertCollabDocStateParams{
		DocumentID:  r.documentID,
		YdocState:   state,
		StateSize:   int32(len(state)),
		UpdateCount: int32(count),
		LastUserID:  lastUser,
	})
	if err != nil {
		slog.Warn("collab: persist state", "doc_id", r.documentID, "err", err)
	}
}

func (r *Room) close(ctx context.Context) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()
	// Final durable write while the room is still 'open' so maybeFlush's
	// closed-guard doesn't early-return and silently drop the last edits.
	// (Previously close set closed=true first, making this flush dead code.)
	r.maybeFlush(ctx)
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
}

// PeerCount returns the number of attached peers. Used by metrics +
// tests; the value can be stale by the time the caller reads it.
func (r *Room) PeerCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.peers)
}

// StateLen returns the byte length of the current state log. Tests use
// this to confirm updates landed.
func (r *Room) StateLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.state)
}
