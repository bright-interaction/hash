// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package ai

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
)

// NoopEmbedder returns a deterministic all-zeros vector. Used in tests
// and as the default until a real Embedder is wired in Phase 11.1.
type NoopEmbedder struct{}

func (NoopEmbedder) Name() string    { return "noop" }
func (NoopEmbedder) Dimensions() int { return 16 }
func (NoopEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i := range texts {
		out[i] = make([]float32, 16)
	}
	return out, nil
}

// HashEmbedder is a deterministic stand-in: it derives a 64-dimensional
// pseudo-embedding from SHA-256 of the input. NOT semantic, but stable +
// trivial to test against. Useful for verifying the embedding storage
// + retrieval round-trip without standing up a real model server.
type HashEmbedder struct {
	Dim int
}

func (h HashEmbedder) Name() string {
	return "hash-stub"
}
func (h HashEmbedder) Dimensions() int {
	if h.Dim <= 0 {
		return 64
	}
	return h.Dim
}
func (h HashEmbedder) Embed(_ context.Context, texts []string) ([][]float32, error) {
	dim := h.Dimensions()
	out := make([][]float32, len(texts))
	for i, t := range texts {
		sum := sha256.Sum256([]byte(t))
		vec := make([]float32, dim)
		for j := 0; j < dim; j++ {
			// take 4-byte windows of the digest, wrap around with j%8.
			start := (j * 4) % 28
			u := binary.BigEndian.Uint32(sum[start : start+4])
			vec[j] = float32(int32(u)) / float32(1<<31) // -1..1
		}
		out[i] = vec
	}
	return out, nil
}

// CosineSimilarity is a small helper for callers that do similarity in
// app code (until pgvector lands). Returns 1 for identical directions,
// 0 for orthogonal, -1 for opposite.
func CosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float32
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (sqrt32(na) * sqrt32(nb))
}

func sqrt32(x float32) float32 {
	// math.Sqrt(float64) is fine; keep the float32 surface for caller
	// convenience.
	if x <= 0 {
		return 0
	}
	z := x
	for i := 0; i < 8; i++ {
		z = 0.5 * (z + x/z)
	}
	return z
}
