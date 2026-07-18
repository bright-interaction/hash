# Licensing and open core

Hash is open core (fair-code).

## Core (this repository): Hash Sustainable Use License

Everything in this repository is licensed under the Hash Sustainable Use License
(see [LICENSE](LICENSE)). That is the whole single-org e-signing product: the
block-based document editor, envelopes and signing flows, the SES signature
engine with the hash-chained audit timeline, offline-verifiable evidence
bundles, the QES/eIDAS client integration, templates, comments, webhooks, the
agent-native MCP surface, and the billing/entitlement engine.

Nothing here is crippled. A self-hosted instance with no payment provider
configured and no billing plans seeded runs unmetered: your signers, customers,
and counterparties sign on your instance for free, forever. The quota engine
only meters orgs on a seeded paid-plan catalog (that is how the hosted product
uses it).

This is a [fair-code](https://faircode.io) license, not an OSI "open source"
license. The one limit: you may not resell Hash or run it as a hosted e-sign
service for third parties (a competing "Hash cloud"). Self-hosting, internal
commercial use, having any third party sign your documents, and running
signing for your own clients (as a law firm, agency, or consultancy) are all
expressly fine.

## Commercial layer (not in this repository)

What you cannot get from this repo is not code, it is standing:

- the hosted EU cloud (managed, provisioned, backed up, EU data residency);
- qualified electronic signatures in production, which require a contracted
  eIDAS trust service provider (this repo carries the client integration, you
  bring your own provider agreement and credentials);
- a production payment provider account for the billing engine;
- enterprise support and SLAs.

## Commercial license

If you want to do something the Sustainable Use License does not permit (for
example, offering Hash as a hosted service to third parties, or embedding it in
a closed product), a commercial license is available at
licensing@brightinteraction.com.
