# Releasing Hash as a public fair-code repo

Hash lives in the private `bright-interaction/automations` monorepo under
`hash/`. The public release is a mirror of that subtree at
`github.com/bright-interaction/hash`.

Hash is open core (see [../LICENSING.md](../LICENSING.md)): the mirror carries
the whole `hash/` tree under the Hash Sustainable Use License. Nothing is
stripped for licensing; the commercial layer (hosted cloud, eIDAS trust service
provider agreements, production payment account) is not code. The split script
strips only internal-ops files (the estate prod compose, cutover/deploy
runbooks, the internal audit report, the build plan) and redacts internal infra
hostnames from history (`scripts/split-public-repo.sh`).

Distribution is the container image, not `go install`: the server embeds the
built SvelteKit frontend, so a bare `go install` produces a binary without a
UI. Self-hosters build with the repo `Dockerfile` or run `docker compose up`.
The Go module path is `github.com/bright-interaction/hash` (same choice as
Reactor), and it must stay byte-identical to the public mirror URL. Go resolves
a module by fetching the repo its path names, so an unhyphenated
`brightinteraction` path makes the published module unresolvable even though
Hash ships as an image and nothing imports it.

Publishing is an outward, hard-to-reverse step (it exposes the source
publicly), so it is a deliberate operator action, not part of `git psync`. It
requires `git-filter-repo` and `gitleaks` on PATH.

## One-time: create the public repo and seed it

1. Dry run first (safe, no push): `./scripts/split-public-repo.sh`. It
   subtree-splits, strips/redacts, build-checks and gitleaks-scans the filtered
   tree, then prints what it WOULD push. Get this green before step 2.
2. Create the public repo (outward):
   ```
   gh repo create bright-interaction/hash --public \
     --description "EU-sovereign self-hosted e-signing: block editor, hash-chained audit trail, offline-verifiable evidence, agent-native via MCP. Fair-code."
   ```
3. Mirror and push:
   ```
   ./scripts/split-public-repo.sh --push
   ```
4. Verify the mirror builds standalone:
   ```
   git clone git@github.com:bright-interaction/hash.git /tmp/hash-mirror-check
   cd /tmp/hash-mirror-check && docker build -t hash-mirror-check .
   ```

## Cut a version

Tag on the public mirror after a push, matching the estate convention:

```
cd <filtered clone or a fresh clone of the public repo>
git tag v0.1.0 && git push git@github.com:bright-interaction/hash.git v0.1.0
gh release create v0.1.0 --repo bright-interaction/hash --generate-notes
```

## Re-publish after monorepo changes

Re-run `./scripts/split-public-repo.sh --push`. The subtree split is
deterministic, so re-runs fast-forward the mirror; if history was rewritten in
the monorepo the push will refuse and you must reconcile deliberately (never
`--force` without reading what diverged).

## Frozen crypto constants

The wire/crypto identifiers (`hash:audit-cert:v1`, `hash.audit.chain.v2`, the
`/.well-known/hash-public-key` route) are FROZEN: they are baked into every
signed document and evidence bundle in the wild. No rebrand or refactor may
touch them (see the Mesh gotcha on the Mithras rename). The publish flow never
needs to change them.
