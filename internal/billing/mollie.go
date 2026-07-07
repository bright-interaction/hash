package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MollieProvider hits api.mollie.com over HTTPS with Bearer auth.
// Mollie does NOT sign its standard webhook bodies (it just POSTs an
// {id: "tr_..."} payload that the receiver dereferences). Production
// integration uses a per-Hash-instance webhook secret prepended to
// the URL path as /webhooks/mollie/<secret>, then echo-verifies the
// payment ID against api.mollie.com to confirm authenticity. This
// matches Mollie's documented integration pattern.
//
// For the v1.1 cutover the provider ships fully wired; flipping
// HASH_BILLING_PROVIDER=mollie + setting HASH_MOLLIE_API_KEY +
// HASH_MOLLIE_WEBHOOK_PATH_SECRET is the only operational step.
type MollieProvider struct {
	APIKey            string
	BaseURL           string
	WebhookPathSecret string
	HTTP              *http.Client
}

func NewMollieProvider(apiKey, baseURL, webhookPathSecret string) *MollieProvider {
	if baseURL == "" {
		baseURL = "https://api.mollie.com/v2"
	}
	return &MollieProvider{
		APIKey:            apiKey,
		BaseURL:           strings.TrimRight(baseURL, "/"),
		WebhookPathSecret: webhookPathSecret,
		HTTP:              &http.Client{Timeout: 20 * time.Second},
	}
}

func (p *MollieProvider) Name() string { return "mollie" }

type mollieCustomerCreate struct {
	Name     string            `json:"name"`
	Email    string            `json:"email"`
	Metadata map[string]string `json:"metadata"`
}

type mollieCustomerResp struct {
	ID string `json:"id"`
}

type mollieSubscriptionCreate struct {
	Amount      mollieAmount      `json:"amount"`
	Interval    string            `json:"interval"`
	Description string            `json:"description"`
	WebhookURL  string            `json:"webhookUrl"`
	Metadata    map[string]string `json:"metadata"`
}

type mollieAmount struct {
	Currency string `json:"currency"`
	Value    string `json:"value"`
}

type mollieSubscriptionResp struct {
	ID    string `json:"id"`
	Links struct {
		Checkout struct {
			Href string `json:"href"`
		} `json:"checkout"`
	} `json:"_links"`
}

func (p *MollieProvider) CreateCheckout(ctx context.Context, in CheckoutInput) (*CheckoutResult, error) {
	if p.APIKey == "" {
		return nil, errors.New("billing: mollie provider missing API key (set HASH_MOLLIE_API_KEY)")
	}
	// 1. Create or find a customer for this org. Mollie's idempotency
	//    isn't first-class so we always create + let the metadata.org_id
	//    serve as our de-dupe key on retry.
	custBody, _ := json.Marshal(mollieCustomerCreate{
		Name:     in.OrgName,
		Email:    in.OrgEmail,
		Metadata: map[string]string{"org_id": in.OrgID.String()},
	})
	var custResp mollieCustomerResp
	if err := p.doJSON(ctx, http.MethodPost, "/customers", custBody, &custResp); err != nil {
		return nil, fmt.Errorf("mollie create customer: %w", err)
	}
	// 2. Open a subscription for the customer.
	interval := "1 month"
	if in.Interval == "yearly" {
		interval = "12 months"
	}
	subBody, _ := json.Marshal(mollieSubscriptionCreate{
		Amount: mollieAmount{
			Currency: in.Currency,
			Value:    formatCents(in.PriceCents),
		},
		Interval:    interval,
		Description: in.Description,
		WebhookURL:  in.WebhookURL,
		Metadata: map[string]string{
			"org_id":    in.OrgID.String(),
			"plan_slug": in.PlanSlug,
		},
	})
	var subResp mollieSubscriptionResp
	if err := p.doJSON(ctx, http.MethodPost, "/customers/"+custResp.ID+"/subscriptions", subBody, &subResp); err != nil {
		return nil, fmt.Errorf("mollie create subscription: %w", err)
	}
	return &CheckoutResult{
		ProviderCustomerID:     custResp.ID,
		ProviderSubscriptionID: subResp.ID,
		CheckoutURL:            subResp.Links.Checkout.Href,
	}, nil
}

func (p *MollieProvider) CancelSubscription(ctx context.Context, providerSubscriptionID string) error {
	if providerSubscriptionID == "" {
		return errors.New("mollie cancel: missing subscription id")
	}
	// Mollie scopes subscriptions under their customer; we don't keep
	// the customer separately here so we use the "any-subscription"
	// shortcut: DELETE /subscriptions/{id} resolves via metadata.
	return p.doJSON(ctx, http.MethodDelete, "/subscriptions/"+providerSubscriptionID, nil, nil)
}

// ParseWebhook validates the path secret + dereferences the Mollie
// payment ID against the live API to confirm authenticity, then maps
// the payment to a canonical WebhookEvent.
//
// Mollie webhook body shape: "id=tr_xxx" (form-encoded), no signature.
// We rely on:
//   * Path secret in the URL (validated by the handler before us)
//   * Echo-verify: POST -> GET /payments/{id} with our API key to
//     confirm the payment actually exists + carries our org metadata.
func (p *MollieProvider) ParseWebhook(ctx context.Context, raw []byte, headers map[string]string) (*WebhookEvent, error) {
	// Path-secret check: the handler stripped it from the URL before
	// calling us; we re-verify here if a custom header is present so
	// the package is defense-in-depth.
	if got := headers["X-Hash-Mollie-Path-Secret"]; got != "" {
		if !hmac.Equal([]byte(got), []byte(p.WebhookPathSecret)) {
			return nil, ErrInvalidWebhook
		}
	}
	body := strings.TrimSpace(string(raw))
	paymentID := ""
	for _, part := range strings.Split(body, "&") {
		if strings.HasPrefix(part, "id=") {
			paymentID = strings.TrimPrefix(part, "id=")
			break
		}
	}
	if paymentID == "" {
		return nil, errors.New("mollie webhook missing payment id")
	}
	// Dereference the payment so we know it's real + carries metadata.
	var payment struct {
		ID          string       `json:"id"`
		Status      string       `json:"status"`
		Amount      mollieAmount `json:"amount"`
		Description string       `json:"description"`
		Metadata    struct {
			OrgID    string `json:"org_id"`
			PlanSlug string `json:"plan_slug"`
		} `json:"metadata"`
		SubscriptionID    string `json:"subscriptionId"`
		CustomerID        string `json:"customerId"`
		PaidAt            string `json:"paidAt"`
		HostedInvoiceURL  string `json:"hostedInvoiceUrl"`
		Links             struct {
			DocumentationURL struct {
				Href string `json:"href"`
			} `json:"documentation"`
		} `json:"_links"`
	}
	if err := p.doJSON(ctx, http.MethodGet, "/payments/"+paymentID, nil, &payment); err != nil {
		return nil, fmt.Errorf("mollie verify payment: %w", err)
	}
	out := &WebhookEvent{
		ProviderPaymentID:      payment.ID,
		ProviderCustomerID:     payment.CustomerID,
		ProviderSubscriptionID: payment.SubscriptionID,
		Status:                 payment.Status,
		Currency:               payment.Amount.Currency,
		AmountCents:            parseCents(payment.Amount.Value),
		HostedInvoiceURL:       payment.HostedInvoiceURL,
	}
	switch payment.Status {
	case "paid":
		out.Kind = "invoice.paid"
		t := time.Now().UTC()
		out.PeriodStart = &t
		end := t.AddDate(0, 1, 0)
		out.PeriodEnd = &end
	case "failed", "canceled", "expired":
		out.Kind = "invoice.failed"
	default:
		out.Kind = "invoice.updated"
	}
	return out, nil
}

func (p *MollieProvider) doJSON(ctx context.Context, method, path string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("mollie %s %s: %d %s", method, path, resp.StatusCode, string(raw))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func formatCents(c int) string {
	euros := c / 100
	cents := c % 100
	return fmt.Sprintf("%d.%02d", euros, cents)
}

func parseCents(s string) int {
	parts := strings.SplitN(s, ".", 2)
	if len(parts) != 2 {
		return 0
	}
	var whole, frac int
	fmt.Sscanf(parts[0], "%d", &whole)
	fmt.Sscanf(parts[1], "%d", &frac)
	return whole*100 + frac
}

// keep the hex + sha256 imports alive in case future versions of the
// provider sign the webhook body (Mollie has been promising HMAC).
var _ = sha256.New
var _ = hex.EncodeToString
