package mcp

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/brightinteraction/hash/internal/audit"
	"github.com/brightinteraction/hash/internal/auth"
	"github.com/brightinteraction/hash/internal/config"
	"github.com/brightinteraction/hash/internal/db/generated"
	"github.com/brightinteraction/hash/internal/dispatch"
)

// mintWebhookSecret matches the handler-side helper. Duplicated here
// (rather than imported) to keep the mcp package free of an http handler
// import; the value is purely a random hex string.
func mintWebhookSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// registerWebhookTools exposes outbound-webhook CRUD over MCP so an
// agent can stand up integrations without a human touching the settings
// page. Mirrors the REST surface at /api/v1/webhooks but routes audit
// kinds through the MCP fan-out path (`via: "mcp"`).
func registerWebhookTools(s *Server, d Deps) {
	s.RegisterTool(ToolDef{
		Name:        "list_webhooks",
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
				out = append(out, webhookRow(row))
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
			"document.created, document.sent, document.opened, document.viewed, document.field_filled, document.signed, document.completed, document.declined, document.voided, document.expired, recipient.invited, recipient.bounced.",
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
			secret, err := mintWebhookSecret()
			if err != nil {
				return nil, err
			}
			row, err := d.Queries.CreateWebhookEndpoint(r.Context(), generated.CreateWebhookEndpointParams{
				OrgID:            u.OrgID,
				Url:              p.URL,
				SecretRef:        "per-endpoint",
				Secret:           secret,
				EventsSubscribed: p.EventsSubscribed,
			})
			if err != nil {
				return nil, err
			}
			if d.Audit != nil {
				_, _ = d.Audit.Log(r.Context(), audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID,
					Kind: "webhook.created",
					Payload: map[string]any{
						"endpoint_id": row.ID.String(),
						"url":         row.Url,
						"events":      p.EventsSubscribed,
						"via":         "mcp",
					},
				})
			}
			// The secret is returned exactly once on create.
			// Subsequent reads (list_webhooks) omit it.
			out := webhookRow(row)
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
			if err := d.Queries.DeleteWebhookEndpoint(r.Context(), generated.DeleteWebhookEndpointParams{
				ID: id, OrgID: u.OrgID,
			}); err != nil {
				return nil, err
			}
			if d.Audit != nil {
				_, _ = d.Audit.Log(r.Context(), audit.Entry{
					OrgID: u.OrgID, ActorUserID: &u.UserID,
					Kind:    "webhook.deleted",
					Payload: map[string]any{"endpoint_id": id.String(), "via": "mcp"},
				})
			}
			return map[string]any{"deleted": id.String()}, nil
		},
	})

	s.RegisterTool(ToolDef{
		Name:        "list_webhook_deliveries",
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

func webhookRow(row *generated.WebhookEndpoint) map[string]any {
	return map[string]any{
		"id":                row.ID.String(),
		"url":               row.Url,
		"events_subscribed": append([]string{}, row.EventsSubscribed...),
		"active":            row.Active,
		"created_at":        row.CreatedAt.Time.UTC().Format("2006-01-02T15:04:05.000Z"),
	}
}
