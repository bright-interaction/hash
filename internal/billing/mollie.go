// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/nethard"
)

// MollieProvider follows Mollie's recurring-payment sequence: a customer and
// sequenceType=first payment produce the hosted checkout; only a paid webhook
// with a valid mandate permits creation of the recurring subscription.
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
		APIKey: apiKey, BaseURL: strings.TrimRight(baseURL, "/"), WebhookPathSecret: webhookPathSecret,
		HTTP: nethard.Client(20*time.Second, func() bool { return false }),
	}
}

func (p *MollieProvider) Name() string { return "mollie" }

var mollieIDPattern = regexp.MustCompile(`^(cst|tr|sub|mdt)_[A-Za-z0-9]+$`)

type mollieAmount struct {
	Currency string `json:"currency"`
	Value    string `json:"value"`
}

type mollieMetadata struct {
	ActivationKey string `json:"activation_key"`
	OrgID         string `json:"org_id"`
	PlanSlug      string `json:"plan_slug"`
	Interval      string `json:"interval"`
}

type mollieCustomer struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Email    string         `json:"email"`
	Metadata map[string]any `json:"metadata"`
}

type mollieLinks struct {
	Checkout struct {
		Href string `json:"href"`
	} `json:"checkout"`
	Next struct {
		Href string `json:"href"`
	} `json:"next"`
}

type molliePayment struct {
	ID             string         `json:"id"`
	Status         string         `json:"status"`
	Amount         mollieAmount   `json:"amount"`
	Description    string         `json:"description"`
	Metadata       mollieMetadata `json:"metadata"`
	SequenceType   string         `json:"sequenceType"`
	SubscriptionID string         `json:"subscriptionId"`
	CustomerID     string         `json:"customerId"`
	MandateID      string         `json:"mandateId"`
	PaidAt         string         `json:"paidAt"`
	CreatedAt      string         `json:"createdAt"`
	Links          mollieLinks    `json:"_links"`
}

type mollieSubscription struct {
	ID          string         `json:"id"`
	Status      string         `json:"status"`
	CustomerID  string         `json:"customerId"`
	Amount      mollieAmount   `json:"amount"`
	Interval    string         `json:"interval"`
	Description string         `json:"description"`
	WebhookURL  string         `json:"webhookUrl"`
	Metadata    mollieMetadata `json:"metadata"`
}

type molliePaymentList struct {
	Embedded struct {
		Payments []molliePayment `json:"payments"`
	} `json:"_embedded"`
	Links mollieLinks `json:"_links"`
}

type mollieCustomerList struct {
	Embedded struct {
		Customers []mollieCustomer `json:"customers"`
	} `json:"_embedded"`
	Links mollieLinks `json:"_links"`
}

type mollieSubscriptionList struct {
	Embedded struct {
		Subscriptions []mollieSubscription `json:"subscriptions"`
	} `json:"_embedded"`
	Links mollieLinks `json:"_links"`
}

func (p *MollieProvider) CreateCheckout(ctx context.Context, in CheckoutInput) (*CheckoutResult, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	if in.ActivationKey == uuid.Nil || in.OrgID == uuid.Nil || in.PriceCents <= 0 ||
		!validCurrency(in.Currency) || !validInterval(in.Interval) || in.PlanSlug == "" {
		return nil, fmt.Errorf("%w: incomplete first-payment input", ErrInvalidCheckout)
	}
	if err := requireHTTPSURL(in.ReturnURL); err != nil {
		return nil, fmt.Errorf("%w: redirect URL: %v", ErrInvalidCheckout, err)
	}
	if err := requireHTTPSURL(in.WebhookURL); err != nil {
		return nil, fmt.Errorf("%w: webhook URL: %v", ErrInvalidCheckout, err)
	}

	customer, err := p.ensureCustomer(ctx, in)
	if err != nil {
		return nil, err
	}
	metadata := checkoutMetadata(in.ActivationKey, in.OrgID, in.PlanSlug, in.Interval)
	if in.Reconcile {
		existing, err := p.findPayment(ctx, customer.ID, metadata)
		if err != nil {
			return nil, fmt.Errorf("mollie reconcile first payment: %w", err)
		}
		if existing != nil {
			return validateFirstPayment(*existing, customer.ID, in)
		}
	}

	body, err := json.Marshal(struct {
		Amount       mollieAmount   `json:"amount"`
		CustomerID   string         `json:"customerId"`
		SequenceType string         `json:"sequenceType"`
		Description  string         `json:"description"`
		RedirectURL  string         `json:"redirectUrl"`
		WebhookURL   string         `json:"webhookUrl"`
		Metadata     mollieMetadata `json:"metadata"`
	}{
		Amount: mollieAmount{Currency: in.Currency, Value: formatCents(in.PriceCents)}, CustomerID: customer.ID,
		SequenceType: "first", Description: in.Description, RedirectURL: in.ReturnURL,
		WebhookURL: in.WebhookURL, Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("mollie encode first payment: %w", err)
	}
	var payment molliePayment
	err = p.doJSON(ctx, http.MethodPost, "/payments", body, &payment, "hash-first-"+in.ActivationKey.String())
	if err != nil {
		// The request can time out after Mollie commits. Reconcile before
		// returning so retry/crash recovery persists the provider ID.
		existing, reconcileErr := p.findPayment(ctx, customer.ID, metadata)
		if reconcileErr == nil && existing != nil {
			return validateFirstPayment(*existing, customer.ID, in)
		}
		return nil, fmt.Errorf("mollie create first payment: %w", err)
	}
	return validateFirstPayment(payment, customer.ID, in)
}

func (p *MollieProvider) CreateSubscription(ctx context.Context, in SubscriptionInput) (*SubscriptionResult, error) {
	if err := p.ready(); err != nil {
		return nil, err
	}
	if in.ActivationKey == uuid.Nil || in.OrgID == uuid.Nil || in.PriceCents <= 0 ||
		!validCurrency(in.Currency) || !validInterval(in.Interval) || in.PlanSlug == "" ||
		!validMollieID(in.ProviderCustomerID, "cst") || !validMollieID(in.MandateID, "mdt") {
		return nil, fmt.Errorf("%w: incomplete subscription input", ErrInvalidCheckout)
	}
	if err := requireHTTPSURL(in.WebhookURL); err != nil {
		return nil, fmt.Errorf("%w: webhook URL: %v", ErrInvalidCheckout, err)
	}

	var mandate struct {
		ID         string `json:"id"`
		Status     string `json:"status"`
		CustomerID string `json:"customerId"`
	}
	mandatePath := "/customers/" + url.PathEscape(in.ProviderCustomerID) + "/mandates/" + url.PathEscape(in.MandateID)
	if err := p.doJSON(ctx, http.MethodGet, mandatePath, nil, &mandate, ""); err != nil {
		return nil, fmt.Errorf("mollie verify mandate: %w", err)
	}
	if mandate.ID != in.MandateID || mandate.Status != "valid" ||
		(mandate.CustomerID != "" && mandate.CustomerID != in.ProviderCustomerID) {
		return nil, errors.New("mollie verify mandate: mandate is not valid for checkout customer")
	}

	metadata := checkoutMetadata(in.ActivationKey, in.OrgID, in.PlanSlug, in.Interval)
	existing, err := p.findSubscription(ctx, in.ProviderCustomerID, metadata)
	if err != nil {
		return nil, fmt.Errorf("mollie reconcile subscription: %w", err)
	}
	if existing != nil {
		return validateSubscription(*existing, in)
	}
	body, err := json.Marshal(struct {
		Amount      mollieAmount   `json:"amount"`
		Interval    string         `json:"interval"`
		Description string         `json:"description"`
		WebhookURL  string         `json:"webhookUrl"`
		MandateID   string         `json:"mandateId"`
		Metadata    mollieMetadata `json:"metadata"`
	}{
		Amount: mollieAmount{Currency: in.Currency, Value: formatCents(in.PriceCents)}, Interval: mollieInterval(in.Interval),
		Description: in.Description + " " + in.ActivationKey.String(), WebhookURL: in.WebhookURL,
		MandateID: in.MandateID, Metadata: metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("mollie encode subscription: %w", err)
	}
	var subscription mollieSubscription
	path := "/customers/" + url.PathEscape(in.ProviderCustomerID) + "/subscriptions"
	err = p.doJSON(ctx, http.MethodPost, path, body, &subscription, "hash-subscription-"+in.ActivationKey.String())
	if err != nil {
		existing, reconcileErr := p.findSubscription(ctx, in.ProviderCustomerID, metadata)
		if reconcileErr == nil && existing != nil {
			return validateSubscription(*existing, in)
		}
		return nil, fmt.Errorf("mollie create subscription: %w", err)
	}
	return validateSubscription(subscription, in)
}

func (p *MollieProvider) CancelSubscription(ctx context.Context, customerID, subscriptionID string) error {
	if !validMollieID(customerID, "cst") || !validMollieID(subscriptionID, "sub") {
		return errors.New("mollie cancel: invalid customer or subscription id")
	}
	path := "/customers/" + url.PathEscape(customerID) + "/subscriptions/" + url.PathEscape(subscriptionID)
	err := p.doJSON(ctx, http.MethodDelete, path, nil, nil, "")
	var httpErr *mollieHTTPError
	if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
		return nil
	}
	return err
}

// ParseWebhook treats the posted id only as a lookup key. Every field used by
// the state machine comes from the authenticated GET /payments/{id} response.
func (p *MollieProvider) ParseWebhook(ctx context.Context, raw []byte, headers map[string]string) (*WebhookEvent, error) {
	if p.WebhookPathSecret == "" ||
		!hmac.Equal([]byte(headers["X-Hash-Mollie-Path-Secret"]), []byte(p.WebhookPathSecret)) {
		return nil, ErrInvalidWebhook
	}
	values, err := url.ParseQuery(strings.TrimSpace(string(raw)))
	if err != nil || len(values["id"]) != 1 || !validMollieID(values.Get("id"), "tr") {
		return nil, fmt.Errorf("%w: invalid Mollie payment id", ErrInvalidWebhook)
	}
	paymentID := values.Get("id")
	var payment molliePayment
	if err := p.doJSON(ctx, http.MethodGet, "/payments/"+url.PathEscape(paymentID), nil, &payment, ""); err != nil {
		var httpErr *mollieHTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusNotFound {
			return nil, ErrWebhookCorrelation
		}
		return nil, fmt.Errorf("mollie verify payment: %w", err)
	}
	if payment.ID != paymentID || !validMollieID(payment.CustomerID, "cst") {
		return nil, fmt.Errorf("%w: payment identity mismatch", ErrInvalidWebhook)
	}
	amountCents, err := parseCentsStrict(payment.Amount.Value)
	if err != nil || amountCents <= 0 || !validCurrency(payment.Amount.Currency) {
		return nil, fmt.Errorf("%w: invalid payment amount", ErrInvalidWebhook)
	}
	activationKey, err := uuid.Parse(payment.Metadata.ActivationKey)
	if err != nil || activationKey == uuid.Nil {
		return nil, fmt.Errorf("%w: invalid activation metadata", ErrInvalidWebhook)
	}
	orgID, err := uuid.Parse(payment.Metadata.OrgID)
	if err != nil || orgID == uuid.Nil || payment.Metadata.PlanSlug == "" || !validInterval(payment.Metadata.Interval) {
		return nil, fmt.Errorf("%w: invalid checkout metadata", ErrInvalidWebhook)
	}
	if payment.SequenceType != "first" && payment.SequenceType != "recurring" {
		return nil, fmt.Errorf("%w: unsupported payment sequence", ErrInvalidWebhook)
	}
	if payment.SequenceType == "recurring" && !validMollieID(payment.SubscriptionID, "sub") {
		return nil, fmt.Errorf("%w: recurring payment lacks subscription", ErrInvalidWebhook)
	}

	out := &WebhookEvent{
		ProviderPaymentID: payment.ID, ProviderCustomerID: payment.CustomerID,
		ProviderSubscriptionID: payment.SubscriptionID, ActivationKey: activationKey, OrgID: orgID,
		PlanSlug: payment.Metadata.PlanSlug, Interval: payment.Metadata.Interval,
		SequenceType: payment.SequenceType, MandateID: payment.MandateID, Status: payment.Status,
		Currency: payment.Amount.Currency, AmountCents: amountCents,
	}
	out.CheckoutURL = payment.Links.Checkout.Href
	if payment.CreatedAt != "" {
		createdAt, parseErr := time.Parse(time.RFC3339Nano, payment.CreatedAt)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: invalid payment createdAt", ErrInvalidWebhook)
		}
		createdAt = createdAt.UTC()
		out.ProviderCreatedAt = &createdAt
	}
	if payment.SequenceType == "recurring" && out.ProviderCreatedAt == nil {
		return nil, fmt.Errorf("%w: recurring payment lacks createdAt", ErrInvalidWebhook)
	}
	switch payment.Status {
	case "paid":
		paidAt, err := time.Parse(time.RFC3339Nano, payment.PaidAt)
		if err != nil || (payment.SequenceType == "first" && !validMollieID(payment.MandateID, "mdt")) {
			return nil, fmt.Errorf("%w: paid payment lacks paidAt or mandate", ErrInvalidWebhook)
		}
		paidAt = paidAt.UTC()
		out.PaidAt = &paidAt
		out.Kind = "invoice.paid"
	case "failed", "canceled", "expired":
		out.Kind = "invoice.failed"
	case "open", "pending", "authorized":
		out.Kind = "invoice.updated"
	default:
		return nil, fmt.Errorf("%w: unsupported payment status", ErrInvalidWebhook)
	}
	return out, nil
}

func (p *MollieProvider) ensureCustomer(ctx context.Context, in CheckoutInput) (*mollieCustomer, error) {
	if in.ExistingCustomerID != "" {
		if !validMollieID(in.ExistingCustomerID, "cst") {
			return nil, errors.New("mollie checkout: invalid persisted customer id")
		}
		var customer mollieCustomer
		if err := p.doJSON(ctx, http.MethodGet, "/customers/"+url.PathEscape(in.ExistingCustomerID), nil, &customer, ""); err != nil {
			return nil, fmt.Errorf("mollie verify customer: %w", err)
		}
		if err := validateCustomer(customer, in.OrgID); err != nil {
			return nil, err
		}
		return &customer, nil
	}
	if in.Reconcile {
		customer, err := p.findCustomer(ctx, in.OrgID)
		if err != nil || customer != nil {
			return customer, err
		}
	}
	body, err := json.Marshal(struct {
		Name     string            `json:"name"`
		Email    string            `json:"email"`
		Metadata map[string]string `json:"metadata"`
	}{Name: in.OrgName, Email: in.OrgEmail, Metadata: map[string]string{"org_id": in.OrgID.String()}})
	if err != nil {
		return nil, err
	}
	var customer mollieCustomer
	err = p.doJSON(ctx, http.MethodPost, "/customers", body, &customer, "hash-customer-"+in.OrgID.String())
	if err != nil {
		found, reconcileErr := p.findCustomer(ctx, in.OrgID)
		if reconcileErr == nil && found != nil {
			return found, nil
		}
		return nil, fmt.Errorf("mollie create customer: %w", err)
	}
	if err := validateCustomer(customer, in.OrgID); err != nil {
		return nil, err
	}
	return &customer, nil
}

func (p *MollieProvider) findCustomer(ctx context.Context, orgID uuid.UUID) (*mollieCustomer, error) {
	path := "/customers?limit=250"
	var match *mollieCustomer
	for page := 0; path != "" && page < 100; page++ {
		var list mollieCustomerList
		if err := p.doJSON(ctx, http.MethodGet, path, nil, &list, ""); err != nil {
			return nil, err
		}
		for i := range list.Embedded.Customers {
			customer := list.Embedded.Customers[i]
			if metadataString(customer.Metadata, "org_id") != orgID.String() {
				continue
			}
			if match != nil && match.ID != customer.ID {
				return nil, errors.New("multiple Mollie customers match org metadata")
			}
			copy := customer
			match = &copy
		}
		var err error
		path, err = p.pagePath(list.Links.Next.Href)
		if err != nil {
			return nil, err
		}
	}
	if path != "" {
		return nil, errors.New("Mollie customer reconciliation exceeded 100 pages")
	}
	return match, nil
}

func (p *MollieProvider) findPayment(ctx context.Context, customerID string, metadata mollieMetadata) (*molliePayment, error) {
	path := "/customers/" + url.PathEscape(customerID) + "/payments?limit=250"
	var match *molliePayment
	for page := 0; path != "" && page < 100; page++ {
		var list molliePaymentList
		if err := p.doJSON(ctx, http.MethodGet, path, nil, &list, ""); err != nil {
			return nil, err
		}
		for i := range list.Embedded.Payments {
			payment := list.Embedded.Payments[i]
			if payment.Metadata != metadata {
				continue
			}
			if match != nil && match.ID != payment.ID {
				return nil, errors.New("multiple Mollie payments match activation metadata")
			}
			copy := payment
			match = &copy
		}
		var err error
		path, err = p.pagePath(list.Links.Next.Href)
		if err != nil {
			return nil, err
		}
	}
	if path != "" {
		return nil, errors.New("Mollie payment reconciliation exceeded 100 pages")
	}
	return match, nil
}

func (p *MollieProvider) findSubscription(ctx context.Context, customerID string, metadata mollieMetadata) (*mollieSubscription, error) {
	path := "/customers/" + url.PathEscape(customerID) + "/subscriptions?limit=250"
	var match *mollieSubscription
	for page := 0; path != "" && page < 100; page++ {
		var list mollieSubscriptionList
		if err := p.doJSON(ctx, http.MethodGet, path, nil, &list, ""); err != nil {
			return nil, err
		}
		for i := range list.Embedded.Subscriptions {
			subscription := list.Embedded.Subscriptions[i]
			if subscription.Metadata != metadata {
				continue
			}
			if match != nil && match.ID != subscription.ID {
				return nil, errors.New("multiple Mollie subscriptions match activation metadata")
			}
			copy := subscription
			match = &copy
		}
		var err error
		path, err = p.pagePath(list.Links.Next.Href)
		if err != nil {
			return nil, err
		}
	}
	if path != "" {
		return nil, errors.New("Mollie subscription reconciliation exceeded 100 pages")
	}
	return match, nil
}

func validateFirstPayment(payment molliePayment, customerID string, in CheckoutInput) (*CheckoutResult, error) {
	amount, err := parseCentsStrict(payment.Amount.Value)
	if err != nil || !validMollieID(payment.ID, "tr") || payment.CustomerID != customerID ||
		payment.SequenceType != "first" || amount != in.PriceCents || payment.Amount.Currency != in.Currency ||
		payment.Metadata != checkoutMetadata(in.ActivationKey, in.OrgID, in.PlanSlug, in.Interval) {
		return nil, errors.New("mollie first payment response does not match checkout intent")
	}
	switch payment.Status {
	case "open":
		// The only state in which returning the hosted URL can still advance
		// checkout. Pending/authorized/paid payments must finish via webhook.
	case "failed", "canceled", "expired":
		return nil, &CheckoutPaymentTerminalError{Status: payment.Status}
	case "pending", "authorized", "paid":
		return nil, ErrCheckoutInProgress
	default:
		return nil, errors.New("mollie first payment returned unsupported status")
	}
	if err := requireHTTPSURL(payment.Links.Checkout.Href); err != nil {
		return nil, fmt.Errorf("mollie first payment returned invalid checkout URL: %w", err)
	}
	return &CheckoutResult{ProviderCustomerID: customerID, ProviderPaymentID: payment.ID, CheckoutURL: payment.Links.Checkout.Href}, nil
}

func validateSubscription(subscription mollieSubscription, in SubscriptionInput) (*SubscriptionResult, error) {
	amount, err := parseCentsStrict(subscription.Amount.Value)
	if err != nil || !validMollieID(subscription.ID, "sub") || subscription.CustomerID != in.ProviderCustomerID ||
		subscription.Status != "active" || amount != in.PriceCents || subscription.Amount.Currency != in.Currency ||
		subscription.Interval != mollieInterval(in.Interval) ||
		subscription.Metadata != checkoutMetadata(in.ActivationKey, in.OrgID, in.PlanSlug, in.Interval) {
		return nil, errors.New("mollie subscription response does not match checkout intent")
	}
	return &SubscriptionResult{ProviderSubscriptionID: subscription.ID}, nil
}

func validateCustomer(customer mollieCustomer, orgID uuid.UUID) error {
	if !validMollieID(customer.ID, "cst") || metadataString(customer.Metadata, "org_id") != orgID.String() {
		return errors.New("mollie customer response does not match org")
	}
	return nil
}

func checkoutMetadata(key, orgID uuid.UUID, planSlug, interval string) mollieMetadata {
	return mollieMetadata{ActivationKey: key.String(), OrgID: orgID.String(), PlanSlug: planSlug, Interval: interval}
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return value
}

func validMollieID(id, prefix string) bool {
	return strings.HasPrefix(id, prefix+"_") && mollieIDPattern.MatchString(id)
}

func validCurrency(currency string) bool {
	if len(currency) != 3 {
		return false
	}
	for _, r := range currency {
		if r < 'A' || r > 'Z' {
			return false
		}
	}
	return true
}

func validInterval(interval string) bool { return interval == "monthly" || interval == "yearly" }

func mollieInterval(interval string) string {
	if interval == "yearly" {
		return "12 months"
	}
	return "1 month"
}

func requireHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("absolute HTTPS URL required")
	}
	return nil
}

func (p *MollieProvider) ready() error {
	if p == nil || p.APIKey == "" || p.HTTP == nil {
		return errors.New("billing: Mollie provider is not configured")
	}
	return nil
}

type mollieHTTPError struct {
	StatusCode int
	Method     string
	Path       string
}

func (e *mollieHTTPError) Error() string {
	return fmt.Sprintf("mollie %s %s returned HTTP %d", e.Method, e.Path, e.StatusCode)
}

func (p *MollieProvider) doJSON(ctx context.Context, method, path string, body []byte, out any, idempotencyKey string) error {
	if err := p.ready(); err != nil {
		return err
	}
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return errors.New("mollie request path is not relative to configured API origin")
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp, err := p.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return &mollieHTTPError{StatusCode: resp.StatusCode, Method: method, Path: path}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("mollie response contains trailing JSON")
	}
	return nil
}

func (p *MollieProvider) pagePath(href string) (string, error) {
	if href == "" {
		return "", nil
	}
	next, err := url.Parse(href)
	if err != nil {
		return "", errors.New("invalid Mollie pagination link")
	}
	base, err := url.Parse(p.BaseURL)
	if err != nil || next.Scheme != base.Scheme || next.Host != base.Host || next.User != nil {
		return "", errors.New("Mollie pagination link changed API origin")
	}
	basePath := strings.TrimRight(base.EscapedPath(), "/")
	if !strings.HasPrefix(next.EscapedPath(), basePath+"/") {
		return "", errors.New("Mollie pagination link escaped API base path")
	}
	path := strings.TrimPrefix(next.EscapedPath(), basePath)
	if next.RawQuery != "" {
		path += "?" + next.RawQuery
	}
	return path, nil
}

func formatCents(cents int) string { return fmt.Sprintf("%d.%02d", cents/100, cents%100) }

func parseCentsStrict(value string) (int, error) {
	if len(value) < 4 || value[len(value)-3] != '.' {
		return 0, errors.New("amount must have exactly two decimal places")
	}
	whole, err := strconv.ParseInt(value[:len(value)-3], 10, 32)
	if err != nil || whole < 0 {
		return 0, errors.New("invalid amount whole units")
	}
	fraction, err := strconv.ParseInt(value[len(value)-2:], 10, 8)
	if err != nil || fraction < 0 || fraction > 99 {
		return 0, errors.New("invalid amount fraction")
	}
	maxInt := int(^uint(0) >> 1)
	if whole > int64((maxInt-int(fraction))/100) {
		return 0, errors.New("amount overflows cents")
	}
	return int(whole)*100 + int(fraction), nil
}

func parseCents(value string) int {
	cents, _ := parseCentsStrict(value)
	return cents
}
