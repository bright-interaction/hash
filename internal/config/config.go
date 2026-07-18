// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package config loads Hash runtime configuration from environment
// variables. It refuses to start if required values are missing ,  never
// silently default a secret.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Port      int
	PublicURL string
	LogLevel  string

	DBURL string

	S3Endpoint  string
	S3Region    string
	S3Bucket    string
	S3AccessKey string
	S3SecretKey string
	S3UseSSL    bool

	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	SignerTokenKey  string // 64 hex chars (32 bytes)
	AuditPrivateKey string // base64 ed25519
	SessionKey      string // 64 hex chars (32 bytes)

	WebhookSecret         string
	WebhookSecretPrevious string

	GotenbergURL string

	// Phase 8.2 variable resolver source plugins. Empty means
	// "not configured" and the resolver returns ErrNotConfigured for
	// any binding using that source kind, which the UI surfaces as a
	// "configure integration" hint instead of a 500.
	BrightCRMURL           string
	BrightCRMToken         string
	BrightCRMWebhookSecret string
	ScannerURL             string
	ScannerToken           string

	// Phase 8.4 AI runtime. All optional; empty keys mean the
	// corresponding provider isn't registered. ShieldKey is 64 hex
	// chars (32 bytes); empty disables tokenization (NoopShield).
	AIShieldKey       string
	AIDefaultProvider string // 'mistral' (recommended) | 'anthropic'
	MistralBaseURL    string
	MistralAPIKey     string
	MistralModel      string
	AnthropicBaseURL  string
	AnthropicAPIKey   string
	AnthropicModel    string

	// Comma-separated list of extra hostnames (or domain suffixes)
	// considered EU-compliant for the AI provider lock. Built-ins:
	// api.mistral.ai, eu.anthropic.com, eu.openrouter.ai. Self-hosted
	// runtimes inside Bright Interaction's VPC should be listed here.
	AIEUHostsAllowlist string

	// QESTrustListPath is the JSON file holding the curated QTSP-root
	// allow-list (SHA-256 fingerprints). Empty disables validation;
	// non-empty + missing file is a hard boot error so a misconfigured
	// trust-list path never silently falls through to "accept every
	// cert chain".
	QESTrustListPath string

	// Phase 10.2 evidence bundle. OTS anchoring is opt-in via env so
	// laptop dev doesn't hit the public calendar on every test.
	EvidenceOTSEnabled  bool
	EvidenceOTSEndpoint string

	// Phase 12.2 compliance feed. Empty disables the rollup loop;
	// HASH_COMPLIANCE_FEED_URL points at a JSON proxy of EDPB
	// advisories (we own the proxy because EDPB's native format
	// wobbles + we want a stable wire shape).
	ComplianceFeedURL string

	// v1.1 QES provider behind a feature flag. When QESProvider is
	// 'mock' (or empty), a stub provider auto-completes the signing
	// flow under a synthetic identity assertion - useful for local
	// dev + e2e. When 'idura', the IduraProvider hits the live Idura
	// REST API using QESIduraBaseURL + QESIduraAPIKey. eIDAS routing
	// rules with required_tier=QES route through this.
	QESProvider     string
	QESIduraBaseURL string
	QESIduraAPIKey  string
	QESIduraTenant  string

	// v1.1 Mollie billing. 'mock' default keeps the surface callable
	// in dev/e2e without a Mollie account; 'mollie' switches to the
	// live api.mollie.com integration. HASH_MOLLIE_WEBHOOK_PATH_SECRET
	// is the per-instance secret embedded in the webhook URL so an
	// attacker can't spam /webhooks/billing/<random>.
	BillingProvider         string
	MollieAPIKey            string
	MollieBaseURL           string
	MollieWebhookPathSecret string
}

// Load reads configuration from the environment and returns either a valid
// Config or an aggregate error listing every missing required value.
func Load() (*Config, error) {
	c := &Config{
		Port:                    envInt("HASH_PORT", 8080),
		PublicURL:               os.Getenv("HASH_PUBLIC_URL"),
		LogLevel:                envString("HASH_LOG_LEVEL", "info"),
		DBURL:                   os.Getenv("HASH_DB_URL"),
		S3Endpoint:              os.Getenv("HASH_S3_ENDPOINT"),
		S3Region:                envString("HASH_S3_REGION", "eu-central-1"),
		S3Bucket:                envString("HASH_S3_BUCKET", "hash"),
		S3AccessKey:             os.Getenv("HASH_S3_ACCESS_KEY"),
		S3SecretKey:             os.Getenv("HASH_S3_SECRET_KEY"),
		S3UseSSL:                envBool("HASH_S3_USE_SSL", true),
		SMTPHost:                os.Getenv("HASH_SMTP_HOST"),
		SMTPPort:                envInt("HASH_SMTP_PORT", 587),
		SMTPUser:                os.Getenv("HASH_SMTP_USER"),
		SMTPPassword:            os.Getenv("HASH_SMTP_PASSWORD"),
		SMTPFrom:                os.Getenv("HASH_SMTP_FROM"),
		OIDCIssuer:              os.Getenv("HASH_OIDC_ISSUER"),
		OIDCClientID:            os.Getenv("HASH_OIDC_CLIENT_ID"),
		OIDCClientSecret:        os.Getenv("HASH_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:         os.Getenv("HASH_OIDC_REDIRECT_URL"),
		SignerTokenKey:          os.Getenv("HASH_SIGNER_TOKEN_KEY"),
		AuditPrivateKey:         os.Getenv("HASH_AUDIT_PRIVATE_KEY"),
		SessionKey:              os.Getenv("HASH_SESSION_KEY"),
		WebhookSecret:           os.Getenv("HASH_WEBHOOK_SECRET"),
		WebhookSecretPrevious:   os.Getenv("HASH_WEBHOOK_SECRET_PREVIOUS"),
		GotenbergURL:            envString("HASH_GOTENBERG_URL", "http://gotenberg:3000"),
		BrightCRMURL:            os.Getenv("HASH_BRIGHTCRM_URL"),
		BrightCRMToken:          os.Getenv("HASH_BRIGHTCRM_TOKEN"),
		BrightCRMWebhookSecret:  os.Getenv("HASH_BRIGHTCRM_WEBHOOK_SECRET"),
		ScannerURL:              os.Getenv("HASH_SCANNER_URL"),
		ScannerToken:            os.Getenv("HASH_SCANNER_TOKEN"),
		AIShieldKey:             os.Getenv("HASH_AI_SHIELD_KEY"),
		AIDefaultProvider:       envString("HASH_AI_DEFAULT_PROVIDER", "mistral"),
		MistralBaseURL:          os.Getenv("HASH_MISTRAL_BASE_URL"),
		MistralAPIKey:           os.Getenv("HASH_MISTRAL_API_KEY"),
		MistralModel:            os.Getenv("HASH_MISTRAL_MODEL"),
		AnthropicBaseURL:        os.Getenv("HASH_ANTHROPIC_BASE_URL"),
		AIEUHostsAllowlist:      os.Getenv("HASH_AI_EU_HOSTS_ALLOWLIST"),
		QESTrustListPath:        os.Getenv("HASH_QES_TRUST_LIST_PATH"),
		AnthropicAPIKey:         os.Getenv("HASH_ANTHROPIC_API_KEY"),
		AnthropicModel:          os.Getenv("HASH_ANTHROPIC_MODEL"),
		EvidenceOTSEnabled:      envBool("HASH_EVIDENCE_OTS_ENABLED", false),
		EvidenceOTSEndpoint:     os.Getenv("HASH_EVIDENCE_OTS_ENDPOINT"),
		ComplianceFeedURL:       os.Getenv("HASH_COMPLIANCE_FEED_URL"),
		QESProvider:             os.Getenv("HASH_QES_PROVIDER"),
		QESIduraBaseURL:         envString("HASH_QES_IDURA_BASE_URL", "https://api.idura.se"),
		QESIduraAPIKey:          os.Getenv("HASH_QES_IDURA_API_KEY"),
		QESIduraTenant:          os.Getenv("HASH_QES_IDURA_TENANT"),
		BillingProvider:         os.Getenv("HASH_BILLING_PROVIDER"),
		MollieAPIKey:            os.Getenv("HASH_MOLLIE_API_KEY"),
		MollieBaseURL:           envString("HASH_MOLLIE_BASE_URL", "https://api.mollie.com/v2"),
		MollieWebhookPathSecret: os.Getenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET"),
	}

	var missing []string
	require := func(name, value string) {
		if value == "" {
			missing = append(missing, name)
		}
	}
	require("HASH_PUBLIC_URL", c.PublicURL)
	require("HASH_DB_URL", c.DBURL)
	require("HASH_S3_ENDPOINT", c.S3Endpoint)
	require("HASH_S3_ACCESS_KEY", c.S3AccessKey)
	require("HASH_S3_SECRET_KEY", c.S3SecretKey)
	require("HASH_OIDC_ISSUER", c.OIDCIssuer)
	require("HASH_OIDC_CLIENT_ID", c.OIDCClientID)
	// HASH_OIDC_CLIENT_SECRET is optional: the login flow uses PKCE, so a public
	// OIDC client (no secret, the estate's Zitadel pattern) is supported; a
	// confidential deployment may still set a secret and it will be used.
	require("HASH_OIDC_REDIRECT_URL", c.OIDCRedirectURL)
	require("HASH_SIGNER_TOKEN_KEY", c.SignerTokenKey)
	require("HASH_SESSION_KEY", c.SessionKey)

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}

	if isWeakKey(c.SignerTokenKey) {
		return nil, errors.New("HASH_SIGNER_TOKEN_KEY must be at least 32 chars of real entropy (all-identical-character keys are rejected)")
	}
	if isWeakKey(c.SessionKey) {
		return nil, errors.New("HASH_SESSION_KEY must be at least 32 chars of real entropy (all-identical-character keys are rejected)")
	}

	if !IsLocalDevelopment(c.PublicURL) {
		// Mock providers are dev/e2e only. The mock QES provider
		// auto-completes a legally-styled "Qualified Electronic Signature"
		// with zero verification; the mock billing provider accepts
		// unauthenticated, forgeable webhooks. Refuse to boot a production
		// instance on either.
		// QES is optional. Leaving the provider unset disables QES, and any
		// QES-tier send is refused at send time; this is correct for an SES-only
		// B2B deployment (the default tier). If a provider IS configured it must
		// be a real QTSP, never the auto-completing mock, and fully keyed.
		if c.QESProvider == "mock" {
			return nil, errors.New("HASH_QES_PROVIDER must be a real QTSP (e.g. 'idura') or left unset outside local dev; the mock provider auto-completes signatures without verification")
		}
		if c.QESProvider != "" {
			if c.QESProvider == "idura" && c.QESIduraAPIKey == "" {
				return nil, errors.New("HASH_QES_IDURA_API_KEY is required when HASH_QES_PROVIDER is 'idura'")
			}
			// A real QTSP MUST present a chain that anchors to a curated EU Trust
			// List root, per eIDAS Art. 22. Without a configured trust list,
			// CompleteCallback degrades root-anchoring to a warning and accepts
			// any (even self-signed) chain, so a forged chain could complete a
			// "qualified" signature. Require it whenever a QES provider is set.
			if c.QESTrustListPath == "" {
				return nil, errors.New("HASH_QES_TRUST_LIST_PATH is required with a real QES provider outside local dev; without it QTSP cert chains are not root-anchored (eIDAS Art. 22)")
			}
		}
		// Billing is optional. Leaving the provider unset disables paid billing
		// entirely (the engine is nil, so no webhook/checkout routes register);
		// orgs run on the implied free plan. A configured provider must be the
		// real Mollie one, never the forgeable-webhook mock (dev-only) or a typo
		// that would silently disable billing.
		if c.BillingProvider != "" && c.BillingProvider != "mollie" {
			return nil, errors.New("HASH_BILLING_PROVIDER must be 'mollie' or left unset outside local dev; the mock provider accepts unauthenticated webhooks and runs only in local dev")
		}
		if c.BillingProvider == "mollie" {
			if c.MollieAPIKey == "" {
				return nil, errors.New("HASH_MOLLIE_API_KEY is required when billing provider is 'mollie'")
			}
			if len(c.MollieWebhookPathSecret) < 16 {
				return nil, errors.New("HASH_MOLLIE_WEBHOOK_PATH_SECRET must be set (>=16 chars) so the public webhook URL is unguessable")
			}
		}
		// Without a stable ed25519 audit key the boot path mints an
		// ephemeral one (cmd/server/main.go), so audit certificates signed
		// before a restart can never be verified against the published
		// public key. That silently breaks the evidentiary claim.
		if c.AuditPrivateKey == "" {
			return nil, errors.New("HASH_AUDIT_PRIVATE_KEY is required outside local dev; without a stable ed25519 key audit certificates cannot be verified across restarts")
		}
		// In production every public webhook receiver must verify HMAC
		// signatures. Fail-open on an unset secret was a known stopgap
		// from the v1.1 launch; outside localhost we now refuse to boot
		// without one. A leaked or omitted secret would let any caller
		// invalidate the variable resolver cache org-wide; that's
		// catastrophic enough to gate at startup.
		if c.BrightCRMURL != "" && len(c.BrightCRMWebhookSecret) < 32 {
			return nil, errors.New("HASH_BRIGHTCRM_WEBHOOK_SECRET must be at least 32 chars when BrightCRM integration is enabled outside local dev")
		}
		// AI runtime: Shield must be active and providers must be EU
		// when any provider API key is configured. Hash's EU-
		// sovereign claim says PII never reaches a non-EU LLM endpoint;
		// the audit log writes shield_active per call but a misconfig
		// would still leak before the row lands. Fail-closed here.
		if err := validateAIEUConfig(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// validateAIEUConfig refuses to boot when any AI provider has credentials
// AND Shield isn't enforced, or AND the base URL isn't on the EU host
// allow-list. Caller is responsible for only invoking this in production.
func validateAIEUConfig(c *Config) error {
	mistralOn := c.MistralAPIKey != ""
	anthropicOn := c.AnthropicAPIKey != ""
	if !mistralOn && !anthropicOn {
		return nil
	}
	if len(c.AIShieldKey) != 64 {
		return errors.New("HASH_AI_SHIELD_KEY must be 64 hex chars (32 bytes) when any AI provider is enabled in production; Shield-tokenizes PII before it leaves the host")
	}
	extra := strings.Split(strings.ReplaceAll(c.AIEUHostsAllowlist, " ", ""), ",")
	if mistralOn {
		host := hostOf(c.MistralBaseURL, "openrouter.ai")
		if !IsEUEndpoint(host, extra) {
			return fmt.Errorf("HASH_MISTRAL_BASE_URL host %q is not on the EU allow-list; use api.mistral.ai, eu.openrouter.ai, or extend HASH_AI_EU_HOSTS_ALLOWLIST", host)
		}
	}
	if anthropicOn {
		host := hostOf(c.AnthropicBaseURL, "api.anthropic.com")
		if !IsEUEndpoint(host, extra) {
			return fmt.Errorf("HASH_ANTHROPIC_BASE_URL host %q is not on the EU allow-list; use eu.anthropic.com or extend HASH_AI_EU_HOSTS_ALLOWLIST", host)
		}
	}
	return nil
}

// IsEUEndpoint reports whether the host is on the EU allow-list. Built-in
// matches: api.mistral.ai, *.mistral.ai, eu.anthropic.com, eu.openrouter.ai,
// any hostname containing a ".eu." or ".eu/" segment. Extra strings from
// HASH_AI_EU_HOSTS_ALLOWLIST are matched as suffixes (so "llm.example.eu"
// matches the FQDN; "brightinteraction.com" matches any subdomain).
func IsEUEndpoint(host string, extra []string) bool {
	h := strings.ToLower(host)
	if h == "" {
		return false
	}
	builtin := []string{
		"api.mistral.ai",
		"eu.anthropic.com",
		"eu.openrouter.ai",
		"eu.api.openrouter.ai",
	}
	for _, b := range builtin {
		if h == b || strings.HasSuffix(h, "."+b) {
			return true
		}
	}
	if strings.Contains(h, ".eu.") || strings.HasSuffix(h, ".eu") {
		return true
	}
	for _, e := range extra {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if h == e || strings.HasSuffix(h, "."+e) {
			return true
		}
	}
	return false
}

// hostOf returns the host component of rawURL, or the fallback when
// rawURL is empty or unparseable. Used so an empty HASH_*_BASE_URL
// validates against the provider's hardcoded default (which is what
// the provider package will actually call).
func hostOf(rawURL, fallback string) string {
	if rawURL == "" {
		return strings.ToLower(fallback)
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return strings.ToLower(fallback)
	}
	host := u.Host
	if i := strings.IndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.ToLower(host)
}

// IsLocalDevelopment returns true when the public URL points at a loopback
// or *.local host. Production guards (HMAC enforcement, Shield enforcement,
// EU AI endpoint enforcement, the mock-provider + weak-key boot guards) read
// this to decide whether to fail-closed.
//
// It parses the URL and matches the HOST exactly. A substring match would let
// an attacker-influenced hostname like app.localhost.company.com or
// prod.local.attacker.com flip the whole instance into permissive dev mode,
// silently disabling every fail-closed gate. An empty/unparseable URL is NOT
// treated as local: HASH_PUBLIC_URL is required, so reaching this with an
// empty value is a misconfiguration that must fail closed.
func IsLocalDevelopment(publicURL string) bool {
	raw := strings.TrimSpace(publicURL)
	if raw == "" {
		return false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname()) // strips port + [::1] brackets
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	// *.localhost and *.local only as the trailing labels (RFC 6761 / mDNS),
	// never as an interior substring.
	return strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local")
}

// isWeakKey reports whether a secret key is too short or has no real entropy.
// It rejects keys under 32 chars and all-identical-character keys (the
// docker-compose all-zero default passes a length-only check but is a known
// HMAC key that forges signer tokens + session cookies).
func isWeakKey(s string) bool {
	if len(s) < 32 {
		return true
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := strings.ToLower(os.Getenv(key))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}
