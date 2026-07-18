// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"time"

	"github.com/google/uuid"
)

// chainDomain separates this hash construction from any other SHA-256 use in
// the system, and versions the wire format so a future field addition is a
// new domain string rather than a silent break.
const chainDomain = "hash.audit.chain.v2"

// HashInput is the full set of columns bound into an event row's hash. Binding
// the forensic columns (org/doc/recipient/actor/ip/ua/created_at) means they
// can no longer be edited without breaking the chain, and binding the exact
// payload_hashed bytes (not the JSONB re-serialization) means verification is
// reproducible. created_at is generated in Go and inserted explicitly so the
// verifier recomputes the identical value.
type HashInput struct {
	Prev      []byte
	OrgID     uuid.UUID
	DocID     uuid.UUID // zero UUID when nil
	RecID     uuid.UUID // zero UUID when nil
	ActorID   uuid.UUID // zero UUID when nil
	Kind      string
	IP        string
	UA        string
	CreatedAt time.Time
	Payload   []byte // the exact bytes stored in events.payload_hashed
}

// ChainHashRecord returns the SHA-256 over a length-delimited encoding of the
// predecessor hash plus all bound fields. Every variable-length field is
// length-prefixed (big-endian uint32) so no field can bleed into the next;
// the empty predecessor (first row in an org's chain) is 32 zero bytes.
func ChainHashRecord(in HashInput) []byte {
	h := sha256.New()
	var seed [32]byte
	if len(in.Prev) == 32 {
		copy(seed[:], in.Prev)
	}
	_, _ = h.Write(seed[:])
	writeField(h, []byte(chainDomain))
	writeField(h, in.OrgID[:])
	writeField(h, in.DocID[:])
	writeField(h, in.RecID[:])
	writeField(h, in.ActorID[:])
	writeField(h, []byte(in.Kind))
	writeField(h, []byte(in.IP))
	writeField(h, []byte(in.UA))
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(in.CreatedAt.UTC().UnixNano()))
	_, _ = h.Write(ts[:])
	writeField(h, in.Payload)
	return h.Sum(nil)
}

// ChainHashRecordHex is a stringified helper for verifier UIs.
func ChainHashRecordHex(in HashInput) string {
	return hex.EncodeToString(ChainHashRecord(in))
}

func writeField(h hash.Hash, b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, _ = h.Write(l[:])
	_, _ = h.Write(b)
}
