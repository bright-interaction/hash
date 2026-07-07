package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/collab"
	"github.com/brightinteraction/hash/internal/config"
	"github.com/brightinteraction/hash/internal/db/generated"
)

// collabMaxMessageSize caps a single Yjs frame. Routine updates are
// 10-200 bytes; sync_step2 snapshots and the 0x04 compact-snapshot
// message type can grow with document size. The collab Hub already
// compacts above 1 MiB and rejects snapshots > 110% of current state,
// so 2 MiB leaves comfortable headroom while bounding any single
// malicious or malformed frame.
const collabMaxMessageSize = 2 * 1024 * 1024

// collabPingInterval drives an application-level keepalive so a dead
// peer (NAT timeout, hung browser tab) gets reaped instead of holding
// a goroutine indefinitely. Browsers respond to ws ping automatically.
const collabPingInterval = 30 * time.Second
const collabPingTimeout = 10 * time.Second

// wsPeer wraps a nhooyr websocket as a collab.Peer. Implements
// thread-safe Send + serializes outgoing writes via a mutex inside the
// wsjson layer (nhooyr ws is safe for one writer + one reader).
type wsPeer struct {
	id          string
	conn        *websocket.Conn
	userID      uuid.UUID
	displayName string
}

func (p *wsPeer) ID() string          { return p.id }
func (p *wsPeer) UserID() uuid.UUID   { return p.userID }
func (p *wsPeer) DisplayName() string { return p.displayName }

func (p *wsPeer) Send(ctx context.Context, frame []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.conn.Write(ctx, websocket.MessageBinary, frame)
}

// handleCollabSocket upgrades the connection to a WebSocket + joins
// the per-document collab room. Authentication is session-cookie OR
// doc-scoped agent token (both come through the auth middleware
// chain). Per-document scope is re-enforced here because the agent
// token may be scoped to a different document.
func (s *Server) handleCollabSocket(w http.ResponseWriter, r *http.Request) {
	if s.Collab == nil {
		writeError(w, http.StatusServiceUnavailable, "collab not enabled on this instance")
		return
	}
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	// RBAC: the collab socket mutates the persisted append-only CRDT log, so it is a
	// write surface. The route lives under RequireRoleForWrites(RoleSender) but that
	// middleware lets GET through unchecked and a WebSocket upgrade IS a GET, so a
	// viewer would otherwise join and write frames. Enforce the role here explicitly.
	if !auth.RoleAtLeast(r.Context(), auth.RoleSender) {
		writeError(w, http.StatusForbidden, "insufficient role for this action")
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	// nhooyr.io/websocket OriginPatterns: lock to the configured public
	// host so an attacker on a different origin can't ride a logged-in
	// user's session cookie into a collab room. Local dev gets the
	// loopback variants because the SvelteKit dev server runs on a
	// different port than the Go API. CompressionMode stays disabled
	// to avoid a CRIME-style sidechannel mixing with the auth cookie.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  collabOriginPatterns(s.PublicURL),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		slog.Warn("collab: ws accept", "err", err, "origin", r.Header.Get("Origin"))
		return
	}
	defer conn.CloseNow()

	// Cap any single frame so a hostile peer (or a wedged Y.Doc) can't
	// blow the process memory with one 1 GB binary blob.
	conn.SetReadLimit(collabMaxMessageSize)

	peerID := newPeerID()
	peer := &wsPeer{
		id:          peerID,
		conn:        conn,
		userID:      u.UserID,
		displayName: firstNonEmpty(u.Email, "Anonymous"),
	}

	// Detach from the request context so a slow client doesn't tear
	// the room down when the request handler returns; the websocket
	// connection has its own lifecycle.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	join, err := s.Collab.Join(ctx, doc.ID, doc.OrgID, peer)
	if err != nil {
		conn.Close(websocket.StatusInternalError, "join failed")
		return
	}
	defer s.Collab.Leave(ctx, doc.ID, peerID)

	stopPing := startCollabKeepalive(ctx, cancel, conn, peerID)
	defer stopPing()

	// Send the persisted state as a sync_step2 frame so the client's
	// Y.Doc fast-forwards before the user starts typing.
	if len(join.InitialState) > 0 {
		header := []byte{collab.MessageSync, collab.SyncStep2}
		_ = conn.Write(ctx, websocket.MessageBinary, append(header, join.InitialState...))
	}

	_, _ = s.Audit.Log(ctx, audit.Entry{
		OrgID:       doc.OrgID,
		ActorUserID: &u.UserID,
		DocumentID:  &doc.ID,
		Kind:        audit.KindCollabPeerJoined,
		Payload: map[string]any{
			"peer_id":      peerID,
			"display_name": peer.displayName,
		},
	})
	// On the way out, log the peer leaving so the timeline shows the
	// full collaboration window.
	defer func() {
		_, _ = s.Audit.Log(context.Background(), audit.Entry{
			OrgID:       doc.OrgID,
			ActorUserID: &u.UserID,
			DocumentID:  &doc.ID,
			Kind:        audit.KindCollabPeerLeft,
			Payload:     map[string]any{"peer_id": peerID},
		})
	}()

	// Read loop: every frame routes to the hub. nhooyr cancels Read on
	// connection close so we exit cleanly.
	for {
		mtype, payload, err := conn.Read(ctx)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				slog.Debug("collab: ws closed", "code", ce.Code, "peer_id", peerID)
			}
			return
		}
		if mtype != websocket.MessageBinary {
			// Yjs is binary-only; reject anything else so a misbehaving
			// client doesn't trigger weird state.
			continue
		}
		if err := join.Room.HandleFrame(ctx, peer, payload); err != nil {
			slog.Debug("collab: bad frame", "peer_id", peerID, "err", err)
		}
	}
}

func newPeerID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// collabOriginPatterns derives the OriginPatterns allow-list from the
// configured public URL. Production gets exactly its own host (the
// nhooyr matcher is hostname-only, ports + paths are ignored). Local
// dev expands to common loopback ports so SvelteKit's vite-dev origin
// (http://localhost:5173) can still join while testing.
func collabOriginPatterns(publicURL string) []string {
	host := collabHost(publicURL)
	if host == "" {
		host = "localhost"
	}
	out := []string{host}
	if config.IsLocalDevelopment(publicURL) {
		out = append(out, "localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*", "[::1]", "[::1]:*")
	}
	return out
}

func collabHost(publicURL string) string {
	u, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// startCollabKeepalive pings every collabPingInterval and tears the
// connection down if the peer fails to pong within collabPingTimeout.
// Returns a stop func the caller must call on disconnect.
func startCollabKeepalive(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, peerID string) func() {
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(collabPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				pctx, pcancel := context.WithTimeout(ctx, collabPingTimeout)
				if err := conn.Ping(pctx); err != nil {
					pcancel()
					slog.Debug("collab: ping timeout", "peer_id", peerID, "err", err)
					cancel() // force read loop exit
					return
				}
				pcancel()
			}
		}
	}()
	return func() { close(done) }
}
