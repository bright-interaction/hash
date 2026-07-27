// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/qes"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
)

// Deps gathers the runtime dependencies the tool + resource handlers need.
type Deps struct {
	Pool    *pgxpool.Pool
	Queries *generated.Queries
	Storage *storage.Client
	// PDF renders designed HTML proposals to a signable PDF (create_pdf_document).
	PDF          *render.Gotenberg
	Audit        *audit.Logger
	Mailer       dispatch.Mailer
	Versions     *versions.Engine
	Resolver     *resolver.Resolver
	AIRuntime    *ai.Runtime
	Envelopes    *envelopes.Engine
	EIDAS        *eidas.Engine
	Evidence     *evidence.Builder
	Clarifier    *aiapps.Clarifier
	Negotiator   *aiapps.Negotiator
	Bilingual    *aiapps.Bilingual
	RiskAnalyzer *aiapps.RiskAnalyzer
	Compliance   *compliance.Seeder
	QES          *qes.Engine
	Billing      *billing.Engine
	// Send is the document-lifecycle engine. The workflow write tools route
	// send/void/remind through it so the magic-token TTL, variable freeze,
	// eIDAS guard, and billing quota are enforced identically to the REST
	// surface (they previously diverged with raw SQL that fooled the TTL).
	Send      *send.Engine
	PublicURL string

	// RenderEmail is an optional function that lets the workflow write
	// tools fan out invite + reminder emails. The handler layer wires this
	// via `MailFromMCP` in cmd/server/main.go so the MCP package doesn't
	// pull in the html/template + http stack itself. Pass nil to skip
	// email sends entirely (tests, dev environments without SMTP).
	RenderEmail func(m dispatch.Mailer, kind, toEmail, toName, docName, senderEmail, signURL, beaconURL string)
}

// New builds a fully-registered MCP server bound to deps.
func New(d Deps) *Server {
	s := NewServer()
	s.billing = d.Billing // central MinFeature enforcement in handleToolsCall

	registerReadTools(s, d)
	registerAuthoringTools(s, d)
	registerWorkflowTools(s, d)
	registerVersionTools(s, d)
	registerVariableBindingTools(s, d)
	registerEngagementTools(s, d)
	registerAITools(s, d)
	registerBrandingTools(s, d)
	registerEnvelopeTools(s, d)
	registerTimelineTools(s, d)
	registerEIDASTools(s, d)
	registerEvidenceTools(s, d)
	registerAIAppsTools(s, d)
	registerComplianceTools(s, d)
	registerQESTools(s, d)
	registerBillingTools(s, d)
	registerWebhookTools(s, d)
	registerFieldTools(s, d)
	registerResources(s, d)
	registerPrompts(s)

	return s
}

// guard so the context import survives even if the server wiring evolves.
var _ = context.Background
