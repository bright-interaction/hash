# Licensing and open core

Hash is open core (fair-code).

## Core (this repository): Hash Sustainable Use License

The original Hash source and documentation in this repository are licensed under the Hash Sustainable
Use License (see [LICENSE](LICENSE)). Third-party dependencies and assets remain under their own
licenses; in particular, the bundled font files are distributed under the SIL Open Font License in
`frontend/static/fonts/OFL.txt` (with copies alongside renderer assets). The Hash-licensed portion is
the whole single-org e-signing product: the
block-based document editor, envelopes and signing flows, the SES signature
engine with the hash-chained audit timeline, offline-verifiable evidence
bundles, eIDAS routing rules with an SES-only fail-closed production guard,
templates, comments, webhooks, the agent-native MCP surface, and the
billing/entitlement engine.

Nothing here is feature-gated behind a separate source package. Local
development may run with the mock billing provider, but every non-local
deployment deliberately fail-closes unless Mollie and its webhook secret are
configured. Self-hosters therefore need their own supported payment-provider
configuration and plan catalog before production boot; this repository does
not promise an unmetered or provider-free production mode.

This is a [fair-code](https://faircode.io) license, not an OSI "open source"
license. The one limit: you may not resell Hash or run it as a hosted e-sign
service for third parties (a competing "Hash cloud"). Self-hosting, internal
commercial use, having any third party sign your documents, and running
signing for your own clients (as a law firm, agency, or consultancy) are all
expressly fine.

## Commercial layer (not in this repository)

What you cannot get from this repo is not code, it is standing:

- the hosted EU cloud (managed, provisioned, backed up, EU data residency);
- qualified electronic signatures in production. AES and QES are unavailable
  in this release; a future implementation would require a contracted eIDAS
  trust service provider plus independent technical and legal validation;
- a production payment provider account for the billing engine;
- enterprise support and SLAs.

## Commercial license

If you want to do something the Sustainable Use License does not permit (for
example, offering Hash as a hosted service to third parties, or embedding it in
a closed product), a commercial license is available at
licensing@brightinteraction.com.
