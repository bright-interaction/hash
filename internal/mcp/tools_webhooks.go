// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

// registerWebhookTools exposes outbound-webhook CRUD over MCP so an
// agent can stand up integrations without a human touching the settings
// page. Mirrors the REST surface at /api/v1/webhooks but routes audit
// kinds through the MCP fan-out path (`via: "mcp"`).
func registerWebhookTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "list_webhooks",
		MinRole:     auth.RoleOwner,
		Description: "List the outbound webhook endpoints registered for the caller's org. Returns id, url, events_subscribed, active, created_at per endpoint.",
		InputSchema: schemaObject(map[string]any{}, nil),
		Handler: func(r *http.Request, _ json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			rows, err := d.Queries.ListWebhookEndpointsByOrg(r.Context(), u.OrgID)
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, row := range rows {
				out = append(out, webhookRow(row.ID, row.Url, row.EventsSubscribed, row.Active, row.CreatedAt.Time))
			}
			return map[string]any{"webhooks": out, "count": len(out)}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:    "create_webhook",
		Write:   true,
		MinRole: auth.RoleOwner, // REST create-webhook is owner-only; match it (a sender webhook is a data-exfil primitive)
		Description: "Register a new outbound webhook endpoint. The URL receives signed POST bodies on every subscribed event kind. " +
			"Signature header: X-Hash-Signature: t=<unix>,v1=<hex>. Valid event kinds: " +
			"document.created, document.sent, document.opened, document.viewed, document.field_filled, document.signed, document.completed, document.declined, document.changes_requested, document.voided, document.expired, recipient.created, recipient.invited, recipient.bounced.",
		InputSchema: schemaObject(map[string]any{
			"url": stringSchema("https URL that will receive the POST"),
			"events_subscribed": map[string]any{
				"type":        "array",
				"description": "events to deliver to this endpoint",
				"items":       stringSchema("event kind"),
			},
		}, []string{"url", "events_subscribed"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				URL              string   `json:"url"`
				EventsSubscribed []string `json:"events_subscribed"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			if p.URL == "" {
				return nil, errors.New("url required")
			}
			if err := dispatch.ValidateWebhookURL(p.URL, config.IsLocalDevelopment(d.PublicURL)); err != nil {
				return nil, err
			}
			if len(p.EventsSubscribed) == 0 {
				return nil, errors.New("events_subscribed required")
			}
			for _, ev := range p.EventsSubscribed {
				if !dispatch.IsPublicEventKind(ev) {
					return nil, errors.New("unknown event kind: " + ev)
				}
			}
			if d.WebhookSecrets == nil {
				return nil, errors.New("webhook endpoint encryption is unavailable")
			}
			endpointID, err := uuid.NewRandom()
			if err != nil {
				return nil, err
			}
			secret, err := webhooksecret.Mint()
			if err != nil {
				return nil, err
			}
			secretCiphertext, err := d.WebhookSecrets.SealNew(u.OrgID, endpointID, secret)
			if err != nil {
				return nil, err
			}
			row, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (*generated.CreateWebhookEndpointRow, error) {
					return q.CreateWebhookEndpoint(r.Context(), generated.CreateWebhookEndpointParams{
						ID:               endpointID,
						OrgID:            u.OrgID,
						Url:              p.URL,
						SecretRef:        "per-endpoint-aesgcm-v1",
						SecretCiphertext: secretCiphertext,
						EventsSubscribed: p.EventsSubscribed,
					})
				},
				func(created *generated.CreateWebhookEndpointRow) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID,
						Kind: "webhook.created",
						Payload: map[string]any{
							"endpoint_id": created.ID.String(),
							"events":      p.EventsSubscribed,
							"via":         "mcp",
						},
					}
				},
			)
			if err != nil {
				return nil, err
			}
			// The secret is returned exactly once on create.
			// Subsequent reads (list_webhooks) omit it.
			out := webhookRow(row.ID, row.Url, row.EventsSubscribed, row.Active, row.CreatedAt.Time)
			out["secret"] = secret
			return out, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "delete_webhook",
		Write:       true,
		MinRole:     auth.RoleOwner, // REST delete-webhook is owner-only; match it
		Description: "Delete an outbound webhook endpoint by id. Past deliveries are retained for audit; future events stop firing.",
		InputSchema: schemaObject(map[string]any{
			"endpoint_id": stringSchema("uuid of the endpoint to remove"),
		}, []string{"endpoint_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				EndpointID string `json:"endpoint_id"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.EndpointID)
			if err != nil {
				return nil, errors.New("endpoint_id must be a uuid")
			}
			deletedID, err := audit.CommitMutation(r.Context(), d.Pool, d.Audit,
				func(q *generated.Queries) (uuid.UUID, error) {
					return q.DeleteWebhookEndpoint(r.Context(), generated.DeleteWebhookEndpointParams{
						ID: id, OrgID: u.OrgID,
					})
				},
				func(deletedID uuid.UUID) audit.Entry {
					return audit.Entry{
						OrgID: u.OrgID, ActorUserID: &u.UserID,
						Kind:    "webhook.deleted",
						Payload: map[string]any{"endpoint_id": deletedID.String(), "via": "mcp"},
					}
				},
			)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, errors.New("webhook endpoint not found")
			}
			if err != nil {
				return nil, err
			}
			return map[string]any{"deleted": deletedID.String()}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_webhook_deliveries",
		MinRole:     auth.RoleOwner,
		Description: "List recent delivery attempts for an outbound webhook endpoint. Up to 200 rows. Useful for debugging why a downstream isn't receiving events.",
		InputSchema: schemaObject(map[string]any{
			"endpoint_id": stringSchema("uuid of the endpoint"),
			"limit":       intSchema("max rows to return", 1, 200, 100),
		}, []string{"endpoint_id"}),
		Handler: func(r *http.Request, args json.RawMessage) (any, error) {
			u, _ := auth.FromContext(r.Context())
			var p struct {
				EndpointID string `json:"endpoint_id"`
				Limit      int    `json:"limit"`
			}
			if err := MustParseArgs(args, &p); err != nil {
				return nil, err
			}
			id, err := uuid.Parse(p.EndpointID)
			if err != nil {
				return nil, errors.New("endpoint_id must be a uuid")
			}
			endpoints, err := d.Queries.ListWebhookEndpointsByOrg(r.Context(), u.OrgID)
			if err != nil {
				return nil, err
			}
			found := false
			for _, ep := range endpoints {
				if ep.ID == id {
					found = true
					break
				}
			}
			if !found {
				return nil, errors.New("webhook endpoint not found")
			}
			limit := p.Limit
			if limit <= 0 {
				limit = 100
			}
			if limit > 200 {
				limit = 200
			}
			rows, err := d.Queries.ListDeliveriesByEndpoint(r.Context(), generated.ListDeliveriesByEndpointParams{
				EndpointID: id, Limit: int32(limit),
			})
			if err != nil {
				return nil, err
			}
			out := make([]map[string]any, 0, len(rows))
			for _, dl := range rows {
				entry := map[string]any{
					"id":         dl.ID.String(),
					"event_id":   dl.EventID.String(),
					"status":     dl.Status,
					"attempts":   dl.Attempts,
					"created_at": dl.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
				}
				if dl.LastStatusCode.Valid {
					entry["last_status_code"] = dl.LastStatusCode.Int32
				}
				if dl.LastError.Valid {
					entry["last_error"] = dl.LastError.String
				}
				out = append(out, entry)
			}
			return map[string]any{"deliveries": out, "count": len(out)}, nil
		},
	})
}

func webhookRow(id uuid.UUID, endpointURL string, events []string, active bool, createdAt time.Time) map[string]any {
	return map[string]any{
		"id":                id.String(),
		"url":               endpointURL,
		"events_subscribed": append([]string{}, events...),
		"active":            active,
		"created_at":        createdAt.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}
