// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package e2e holds end-to-end integration tests that exercise the real
// send -> sign -> finalize loop against live Postgres + MinIO + Gotenberg.
//
// The tests are behind the `e2e` build tag and additionally skip unless the
// HASH_E2E_* env vars are set, so the normal unit suite (`go test ./...`)
// never builds or runs them. The hash-ci workflow's `e2e` job provides the
// service containers + env. See .github/workflows/hash-ci.yml and
// hash/DEPLOY.md.
package e2e
