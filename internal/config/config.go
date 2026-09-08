// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package config loads Hash runtime configuration from environment
// variables. It refuses to start if required values are missing ,  never
// silently default a secret.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/s3policy"
)

type Config struct {
	Port        int
	PublicURL   string
	LogLevel    string
	Release     string
	Environment string
	// ProxyAuth is a shared, host-only secret which the production Caddy
	// overwrites into X-Hash-Proxy-Auth. It authenticates the immediate HTTP
	// hop because Hash necessarily shares its Docker networks with workloads
	// which can otherwise dial port 8080 and forge forwarding headers.
	ProxyAuth string
	// OperatorName, PrivacyContact, SupervisoryAuthority, and PrivacyPolicyURL describe the
	// actual operator of this Hash instance in the signer-facing Article 13
	// disclosure. They are deployment identity, never vendor defaults.
	OperatorName         string
	PrivacyContact       string
	SupervisoryAuthority string
	PrivacyPolicyURL     string

	DBURL string

	S3Endpoint     string
	S3Region       string
	S3Bucket       string
	S3AccessKey    string
	S3SecretKey    string
	S3UseSSL       bool
	S3SSEMode      string
	S3SSECKeyFile  string
	S3BucketLookup string

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
	// AuditTrustedPublicKeys retains comma-separated raw Ed25519 public keys
	// from prior rotations so historical evidence remains independently pinned.
	AuditTrustedPublicKeys string
	SessionKey             string // 64 hex chars (32 bytes)

	WebhookSecret         string
	WebhookSecretPrevious string
	// WebhookEncryptionKey seals per-endpoint outbound HMAC keys in Postgres.
	// Previous is accepted only during an explicit rewrap window.
	WebhookEncryptionKey         string // 64 hex chars (32 bytes)
	WebhookEncryptionKeyPrevious string // optional prior 64-hex key

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

	// QESTrustListPath is a reserved legacy configuration name. The SES-only
	// server does not load or use it, and it cannot activate QES.
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

	// These QES names are parsed only as reserved legacy configuration. Load
	// rejects every non-empty QESProvider, and no provider is wired into the
	// HTTP or MCP servers in this SES-only release.
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
	port, err := envInt("HASH_PORT", 8080)
	if err != nil {
		return nil, err
	}
	s3UseSSL, err := envBool("HASH_S3_USE_SSL", true)
	if err != nil {
		return nil, err
	}
	smtpPort, err := envInt("HASH_SMTP_PORT", 587)
	if err != nil {
		return nil, err
	}
	evidenceOTSEnabled, err := envBool("HASH_EVIDENCE_OTS_ENABLED", false)
	if err != nil {
		return nil, err
	}

	c := &Config{
		Port:                         port,
		PublicURL:                    os.Getenv("HASH_PUBLIC_URL"),
		LogLevel:                     envString("HASH_LOG_LEVEL", "info"),
		Release:                      envString("HASH_RELEASE", "unknown"),
		Environment:                  os.Getenv("HASH_ENVIRONMENT"),
		ProxyAuth:                    os.Getenv("HASH_PROXY_AUTH"),
		OperatorName:                 os.Getenv("HASH_OPERATOR_NAME"),
		PrivacyContact:               os.Getenv("HASH_PRIVACY_CONTACT"),
		SupervisoryAuthority:         os.Getenv("HASH_SUPERVISORY_AUTHORITY"),
		PrivacyPolicyURL:             os.Getenv("HASH_PRIVACY_POLICY_URL"),
		DBURL:                        os.Getenv("HASH_DB_URL"),
		S3Endpoint:                   os.Getenv("HASH_S3_ENDPOINT"),
		S3Region:                     envString("HASH_S3_REGION", "eu-central-1"),
		S3Bucket:                     envString("HASH_S3_BUCKET", "hash"),
		S3AccessKey:                  os.Getenv("HASH_S3_ACCESS_KEY"),
		S3SecretKey:                  os.Getenv("HASH_S3_SECRET_KEY"),
		S3UseSSL:                     s3UseSSL,
		S3SSEMode:                    envString("HASH_S3_SSE_MODE", s3policy.SSEModeS3),
		S3SSECKeyFile:                os.Getenv("HASH_S3_SSE_C_KEY_FILE"),
		S3BucketLookup:               envString("HASH_S3_BUCKET_LOOKUP", s3policy.BucketLookupAuto),
		SMTPHost:                     os.Getenv("HASH_SMTP_HOST"),
		SMTPPort:                     smtpPort,
		SMTPUser:                     os.Getenv("HASH_SMTP_USER"),
		SMTPPassword:                 os.Getenv("HASH_SMTP_PASSWORD"),
		SMTPFrom:                     os.Getenv("HASH_SMTP_FROM"),
		OIDCIssuer:                   os.Getenv("HASH_OIDC_ISSUER"),
		OIDCClientID:                 os.Getenv("HASH_OIDC_CLIENT_ID"),
		OIDCClientSecret:             os.Getenv("HASH_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:              os.Getenv("HASH_OIDC_REDIRECT_URL"),
		SignerTokenKey:               os.Getenv("HASH_SIGNER_TOKEN_KEY"),
		AuditPrivateKey:              os.Getenv("HASH_AUDIT_PRIVATE_KEY"),
		AuditTrustedPublicKeys:       os.Getenv("HASH_AUDIT_TRUSTED_PUBLIC_KEYS"),
		SessionKey:                   os.Getenv("HASH_SESSION_KEY"),
		WebhookSecret:                os.Getenv("HASH_WEBHOOK_SECRET"),
		WebhookSecretPrevious:        os.Getenv("HASH_WEBHOOK_SECRET_PREVIOUS"),
		WebhookEncryptionKey:         os.Getenv("HASH_WEBHOOK_ENCRYPTION_KEY"),
		WebhookEncryptionKeyPrevious: os.Getenv("HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS"),
		GotenbergURL:                 envString("HASH_GOTENBERG_URL", "http://gotenberg:3000"),
		BrightCRMURL:                 os.Getenv("HASH_BRIGHTCRM_URL"),
		BrightCRMToken:               os.Getenv("HASH_BRIGHTCRM_TOKEN"),
		BrightCRMWebhookSecret:       os.Getenv("HASH_BRIGHTCRM_WEBHOOK_SECRET"),
		ScannerURL:                   os.Getenv("HASH_SCANNER_URL"),
		ScannerToken:                 os.Getenv("HASH_SCANNER_TOKEN"),
		AIShieldKey:                  os.Getenv("HASH_AI_SHIELD_KEY"),
		AIDefaultProvider:            envString("HASH_AI_DEFAULT_PROVIDER", "mistral"),
		MistralBaseURL:               os.Getenv("HASH_MISTRAL_BASE_URL"),
		MistralAPIKey:                os.Getenv("HASH_MISTRAL_API_KEY"),
		MistralModel:                 os.Getenv("HASH_MISTRAL_MODEL"),
		AnthropicBaseURL:             os.Getenv("HASH_ANTHROPIC_BASE_URL"),
		AIEUHostsAllowlist:           os.Getenv("HASH_AI_EU_HOSTS_ALLOWLIST"),
		QESTrustListPath:             os.Getenv("HASH_QES_TRUST_LIST_PATH"),
		AnthropicAPIKey:              os.Getenv("HASH_ANTHROPIC_API_KEY"),
		AnthropicModel:               os.Getenv("HASH_ANTHROPIC_MODEL"),
		EvidenceOTSEnabled:           evidenceOTSEnabled,
		EvidenceOTSEndpoint:          os.Getenv("HASH_EVIDENCE_OTS_ENDPOINT"),
		ComplianceFeedURL:            os.Getenv("HASH_COMPLIANCE_FEED_URL"),
		QESProvider:                  os.Getenv("HASH_QES_PROVIDER"),
		QESIduraBaseURL:              envString("HASH_QES_IDURA_BASE_URL", "https://api.idura.se"),
		QESIduraAPIKey:               os.Getenv("HASH_QES_IDURA_API_KEY"),
		QESIduraTenant:               os.Getenv("HASH_QES_IDURA_TENANT"),
		BillingProvider:              os.Getenv("HASH_BILLING_PROVIDER"),
		MollieAPIKey:                 os.Getenv("HASH_MOLLIE_API_KEY"),
		MollieBaseURL:                envString("HASH_MOLLIE_BASE_URL", "https://api.mollie.com/v2"),
		MollieWebhookPathSecret:      os.Getenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET"),
	}
	c.Environment = strings.ToLower(strings.TrimSpace(c.Environment))
	if c.Environment == "" {
		// Fail closed. The bundled development Compose file sets this
		// explicitly; an omitted runtime mode must never turn production into
		// development merely because an internal/reverse-proxy URL is local.
		c.Environment = "production"
	}
	switch c.Environment {
	case "development", "staging", "production":
		// These are the only runtime modes with defined safety semantics.
	default:
		return nil, errors.New("HASH_ENVIRONMENT must be exactly development, staging, or production")
	}
	c.OperatorName = strings.TrimSpace(c.OperatorName)
	c.PrivacyContact = strings.TrimSpace(c.PrivacyContact)
	c.SupervisoryAuthority = strings.TrimSpace(c.SupervisoryAuthority)
	c.PrivacyPolicyURL = strings.TrimSpace(c.PrivacyPolicyURL)
	if c.Environment == "development" {
		if c.OperatorName == "" {
			c.OperatorName = "Hash local development operator"
		}
		if c.PrivacyContact == "" {
			c.PrivacyContact = "privacy@localhost.invalid"
		}
		if c.SupervisoryAuthority == "" {
			c.SupervisoryAuthority = "Local development only; configure the applicable supervisory authority before deployment"
		}
		if c.PrivacyPolicyURL == "" {
			c.PrivacyPolicyURL = "/legal/privacy"
		}
	}
	// Development relaxations require two independent signals: an explicit
	// development environment AND a local
	// public URL. A production/staging deployment occasionally uses a loopback
	// URL behind a reverse proxy; that must never enable mock billing/QES,
	// private-network webhooks/AI, or the weaker production boot policy.
	if c.Environment == "development" && !isLocalPublicURL(c.PublicURL) {
		return nil, errors.New("HASH_ENVIRONMENT=development requires a loopback, *.localhost, or *.local HASH_PUBLIC_URL")
	}
	// The bundle builder can request an OpenTimestamps proof, but the public
	// verifier deliberately rejects OTS today because calendar-proof parsing
	// and verification are not implemented. Enabling it in production would
	// therefore generate evidence that Hash itself cannot validate.
	if c.Environment != "development" && c.EvidenceOTSEnabled {
		return nil, errors.New("HASH_EVIDENCE_OTS_ENABLED is unsupported outside development until OTS proof verification is implemented")
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
	require("HASH_WEBHOOK_ENCRYPTION_KEY", c.WebhookEncryptionKey)
	if c.Environment == "production" {
		require("HASH_PROXY_AUTH", c.ProxyAuth)
	}
	if c.Environment != "development" {
		require("HASH_OPERATOR_NAME", c.OperatorName)
		require("HASH_PRIVACY_CONTACT", c.PrivacyContact)
		require("HASH_SUPERVISORY_AUTHORITY", c.SupervisoryAuthority)
		require("HASH_PRIVACY_POLICY_URL", c.PrivacyPolicyURL)
		// Invitations and reminders are core ceremony outputs, not an optional
		// integration. A worker without SMTP previously booted with a NoopMailer
		// and could mark a deployment healthy while no signer received a link.
		require("HASH_SMTP_HOST", c.SMTPHost)
		require("HASH_SMTP_FROM", c.SMTPFrom)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	// Configcheck runs without a network and must still catch an unreadable,
	// malformed, or plaintext-transport SSE-C deployment before cutover. Load
	// reads at most 33 bytes and never renders the key contents.
	if _, err := s3policy.Load(c.S3SSEMode, c.S3SSECKeyFile, c.S3BucketLookup, c.S3UseSSL); err != nil {
		return nil, err
	}
	if err := validateDatabaseConfig(c.DBURL, c.Environment); err != nil {
		return nil, err
	}
	if c.Environment == "production" && !isImmutableReleaseID(c.Release) {
		return nil, errors.New("HASH_RELEASE must be an exact lowercase 40- or 64-character hexadecimal commit identifier in production")
	}
	if err := validateRuntimeURLs(c); err != nil {
		return nil, err
	}

	if !isStrongHexSecret(c.SignerTokenKey, 32) {
		return nil, errors.New("HASH_SIGNER_TOKEN_KEY must be 32 random bytes encoded as exactly 64 hexadecimal characters (all-identical-character values are rejected)")
	}
	if isWeakKey(c.SessionKey) {
		return nil, errors.New("HASH_SESSION_KEY must be at least 32 chars of real entropy (all-identical-character keys are rejected)")
	}
	if key, err := hex.DecodeString(c.SessionKey); err != nil || len(key) < 32 {
		return nil, errors.New("HASH_SESSION_KEY must be valid hexadecimal encoding at least 32 bytes")
	}
	if !isStrongEncryptionHexKey(c.WebhookEncryptionKey) {
		return nil, errors.New("HASH_WEBHOOK_ENCRYPTION_KEY must be 32 random bytes encoded as exactly 64 hexadecimal characters (all-identical-character values are rejected)")
	}
	if c.WebhookEncryptionKeyPrevious != "" {
		if !isStrongEncryptionHexKey(c.WebhookEncryptionKeyPrevious) {
			return nil, errors.New("HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS must be 32 random bytes encoded as exactly 64 hexadecimal characters when configured")
		}
		if strings.EqualFold(c.WebhookEncryptionKeyPrevious, c.WebhookEncryptionKey) {
			return nil, errors.New("HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS must differ from HASH_WEBHOOK_ENCRYPTION_KEY")
		}
	}
	if strings.EqualFold(c.WebhookEncryptionKey, c.SignerTokenKey) ||
		strings.EqualFold(c.WebhookEncryptionKey, c.SessionKey) ||
		strings.EqualFold(c.WebhookEncryptionKey, c.ProxyAuth) ||
		(c.AIShieldKey != "" && strings.EqualFold(c.WebhookEncryptionKey, c.AIShieldKey)) {
		return nil, errors.New("HASH_WEBHOOK_ENCRYPTION_KEY must be independently generated and must not reuse another Hash application key")
	}
	if c.WebhookSecret != "" && !isStrongLegacyWebhookSecret(c.WebhookSecret) {
		return nil, errors.New("HASH_WEBHOOK_SECRET must be at least 32 non-uniform characters without surrounding whitespace when configured for legacy-row migration")
	}
	if c.WebhookSecretPrevious != "" && !isStrongLegacyWebhookSecret(c.WebhookSecretPrevious) {
		return nil, errors.New("HASH_WEBHOOK_SECRET_PREVIOUS must be at least 32 non-uniform characters without surrounding whitespace when configured")
	}
	if c.AIShieldKey != "" {
		key, err := hex.DecodeString(c.AIShieldKey)
		if err != nil || len(key) != 32 {
			return nil, errors.New("HASH_AI_SHIELD_KEY must be valid hexadecimal encoding of exactly 32 bytes when configured")
		}
	}
	if c.Environment == "production" {
		if !isStrongProxyAuthSecret(c.ProxyAuth) {
			return nil, errors.New("HASH_PROXY_AUTH must be 32 random bytes encoded as exactly 64 hexadecimal characters (all-identical-character values are rejected)")
		}
		if c.ProxyAuth == c.SignerTokenKey || c.ProxyAuth == c.SessionKey {
			return nil, errors.New("HASH_PROXY_AUTH must be independently generated and must not equal HASH_SIGNER_TOKEN_KEY or HASH_SESSION_KEY")
		}
	}
	if err := validateDisclosureIdentity(c.OperatorName, c.PrivacyContact, c.SupervisoryAuthority); err != nil {
		return nil, err
	}
	if err := validatePrivacyPolicyURL(c.PrivacyPolicyURL, c.Environment == "development"); err != nil {
		return nil, err
	}
	if err := validateAuditTrustedPublicKeys(c.AuditTrustedPublicKeys); err != nil {
		return nil, err
	}
	if (c.SMTPUser == "") != (c.SMTPPassword == "") {
		return nil, errors.New("HASH_SMTP_USER and HASH_SMTP_PASSWORD must either both be set or both be empty")
	}
	if c.SMTPFrom != "" {
		from, err := mail.ParseAddress(c.SMTPFrom)
		if err != nil || from.Address == "" {
			return nil, errors.New("HASH_SMTP_FROM must be one valid RFC-5322 mailbox")
		}
	}
	if c.Port < 1 || c.Port > 65535 {
		return nil, errors.New("HASH_PORT must be between 1 and 65535")
	}
	if c.SMTPPort < 1 || c.SMTPPort > 65535 {
		return nil, errors.New("HASH_SMTP_PORT must be between 1 and 65535")
	}
	if c.Environment != "development" && c.SMTPPort == 1025 {
		return nil, errors.New("HASH_SMTP_PORT=1025 is reserved for plaintext local development; production/staging SMTP must use STARTTLS")
	}
	// A localhost public URL is not an authentication boundary: dev/e2e stacks
	// are frequently exposed through a proxy or shared network. If BrightCRM is
	// enabled, require its inbound HMAC key in every environment. Leaving the
	// integration URL empty still disables it without requiring a secret.
	if c.BrightCRMURL != "" && len(c.BrightCRMWebhookSecret) < 32 {
		return nil, errors.New("HASH_BRIGHTCRM_WEBHOOK_SECRET must be at least 32 chars when BrightCRM integration is enabled")
	}
	if err := validateCredentialedIntegration("HASH_BRIGHTCRM_URL", "HASH_BRIGHTCRM_TOKEN", c.BrightCRMURL, c.BrightCRMToken, c.Environment == "development"); err != nil {
		return nil, err
	}
	if err := validateCredentialedIntegration("HASH_SCANNER_URL", "HASH_SCANNER_TOKEN", c.ScannerURL, c.ScannerToken, c.Environment == "development"); err != nil {
		return nil, err
	}
	if err := validateOptionalFeedURL("HASH_COMPLIANCE_FEED_URL", c.ComplianceFeedURL, c.Environment == "development"); err != nil {
		return nil, err
	}

	// AES has no identity-bound proof path and QES does not yet persist and
	// cryptographically consume a provider signature over the exact ceremony
	// digest. Refuse every provider configuration rather than advertise or
	// silently downgrade a higher-assurance legal claim to typed SES.
	if c.QESProvider != "" {
		return nil, errors.New("HASH_QES_PROVIDER must be unset: QES is disabled until document-digest verification and atomic proof consumption are implemented")
	}

	if !IsLocalDevelopment(c.PublicURL) {
		// Mock billing accepts unauthenticated, forgeable webhooks. Refuse to
		// boot a production instance on it. An unset or misspelled provider is
		// also unsafe: it leaves the billing engine nil, which bypasses document
		// quotas and paid-feature checks. Production therefore has exactly one
		// supported billing mode and fails closed before serving traffic.
		if c.BillingProvider != "mollie" {
			return nil, errors.New("HASH_BILLING_PROVIDER must be 'mollie' outside local dev; an unset provider bypasses quota and paid-feature enforcement, and the mock provider is development-only")
		}
		if err := validateProductionMollieURL(c.MollieBaseURL); err != nil {
			return nil, fmt.Errorf("HASH_MOLLIE_BASE_URL: %w", err)
		}
		if c.MollieAPIKey == "" {
			return nil, errors.New("HASH_MOLLIE_API_KEY is required when billing provider is 'mollie'")
		}
		if !isURLSafePathToken(c.MollieWebhookPathSecret) {
			return nil, errors.New("HASH_MOLLIE_WEBHOOK_PATH_SECRET must be a 16-128 character URL-safe token using only letters, digits, '-', '.', '_', or '~'")
		}
		// Without a stable ed25519 audit key the boot path mints an
		// ephemeral one (cmd/server/main.go), so audit certificates signed
		// before a restart can never be verified against the published
		// public key. That silently breaks the evidentiary claim.
		if c.AuditPrivateKey == "" {
			return nil, errors.New("HASH_AUDIT_PRIVATE_KEY is required outside local dev; without a stable ed25519 key audit certificates cannot be verified across restarts")
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
	if c.AuditPrivateKey != "" {
		seed, err := decodeBase64Key(c.AuditPrivateKey)
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("HASH_AUDIT_PRIVATE_KEY must be a base64-encoded raw 32-byte Ed25519 seed")
		}
	}

	return c, nil
}

func validateDatabaseConfig(dsn, environment string) error {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// pgx parser errors can include the credential-bearing input. Keep the
		// release preflight diagnostic useful without echoing any part of the DSN.
		return errors.New("HASH_DB_URL is invalid")
	}
	if environment == "production" && cfg.MaxConns < 3 {
		return errors.New("HASH_DB_URL must configure at least 3 pool connections in production")
	}
	return nil
}

func validateDisclosureIdentity(operatorName, privacyContact, supervisoryAuthority string) error {
	if !validDisclosureText(operatorName, 200) {
		return errors.New("HASH_OPERATOR_NAME must be a non-empty plain-text legal/operator name of at most 200 characters")
	}
	address, err := mail.ParseAddress(privacyContact)
	if err != nil || address.Address != privacyContact || len(privacyContact) > 254 {
		return errors.New("HASH_PRIVACY_CONTACT must be one plain email address of at most 254 characters")
	}
	if !validDisclosureText(supervisoryAuthority, 300) {
		return errors.New("HASH_SUPERVISORY_AUTHORITY must be a non-empty plain-text authority name of at most 300 characters")
	}
	return nil
}

func validatePrivacyPolicyURL(raw string, development bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.User != nil || u.RawQuery != "" {
		return errors.New("HASH_PRIVACY_POLICY_URL must identify the deployed operator's privacy policy without credentials, query parameters, or a fragment")
	}
	escapedPath := strings.ToLower(u.EscapedPath())
	cleanPath := strings.ToLower(path.Clean(u.Path))
	if strings.Contains(escapedPath, "%2f") || strings.Contains(escapedPath, "%5c") ||
		strings.Contains(u.Path, "\\") || cleanPath == "/sign" || strings.HasPrefix(cleanPath, "/sign/") {
		return errors.New("HASH_PRIVACY_POLICY_URL must not reference a signer credential route")
	}
	if development && !u.IsAbs() && u.Host == "" && strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(u.Path, "//") {
		return nil
	}
	if u.Scheme != "https" || u.Host == "" {
		return errors.New("HASH_PRIVACY_POLICY_URL must be an absolute HTTPS URL outside explicit local development")
	}
	return nil
}

func validDisclosureText(value string, max int) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > max {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func isImmutableReleaseID(value string) bool {
	if value != strings.TrimSpace(value) || value != strings.ToLower(value) || (len(value) != 40 && len(value) != 64) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateProductionMollieURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return errors.New("must be a valid absolute URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errors.New("must use https")
	}
	if !strings.EqualFold(u.Hostname(), "api.mollie.com") {
		return errors.New("must use the official api.mollie.com host in production")
	}
	if port := u.Port(); port != "" && port != "443" {
		return errors.New("must use the standard HTTPS port")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not contain userinfo, a query, or a fragment")
	}
	if strings.TrimRight(u.EscapedPath(), "/") != "/v2" {
		return errors.New("must use the Mollie /v2 API root")
	}
	return nil
}

// validateCredentialedIntegration keeps resolver bearer credentials bound to
// one explicit HTTPS origin. Resolver paths are appended by Hash; accepting a
// configured path/query would make that construction ambiguous, while HTTP
// would expose the credential and resolved document data on the wire.
func validateCredentialedIntegration(urlName, tokenName, rawURL, token string, development bool) error {
	if (rawURL == "") != (token == "") {
		return fmt.Errorf("%s and %s must either both be set or both be empty", urlName, tokenName)
	}
	if rawURL == "" {
		return nil
	}
	if rawURL != strings.TrimSpace(rawURL) {
		return fmt.Errorf("%s must not contain surrounding whitespace", urlName)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return fmt.Errorf("%s must be an absolute URL", urlName)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("%s must be an origin only, without userinfo, path, query, or fragment", urlName)
	}
	if development {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s must use http or https", urlName)
		}
	} else if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%s must use https outside local development", urlName)
	}
	return nil
}

func validateOptionalFeedURL(name, rawURL string, development bool) error {
	if rawURL == "" {
		return nil
	}
	if rawURL != strings.TrimSpace(rawURL) {
		return fmt.Errorf("%s must not contain surrounding whitespace", name)
	}
	u, err := url.Parse(rawURL)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%s must not contain userinfo or a fragment", name)
	}
	if development {
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%s must use http or https", name)
		}
	} else if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("%s must use https outside local development", name)
	}
	return nil
}

// validateRuntimeURLs protects every bearer link and session cookie generated
// from PublicURL. Outside explicit loopback development, all externally
// reachable authentication URLs must be HTTPS. The callback is intentionally
// pinned to the public origin and one fixed path so a typo or hostile config
// cannot send OIDC codes to another host.
func validateRuntimeURLs(c *Config) error {
	if c == nil {
		return errors.New("runtime URL configuration is nil")
	}
	publicURL, err := parseAbsoluteRuntimeURL("HASH_PUBLIC_URL", c.PublicURL)
	if err != nil {
		return err
	}
	if publicURL.RawQuery != "" || publicURL.Fragment != "" || (publicURL.Path != "" && publicURL.Path != "/") {
		return errors.New("HASH_PUBLIC_URL must be an origin only (no path, query, or fragment)")
	}

	issuerURL, err := parseAbsoluteRuntimeURL("HASH_OIDC_ISSUER", c.OIDCIssuer)
	if err != nil {
		return err
	}
	if issuerURL.RawQuery != "" || issuerURL.Fragment != "" {
		return errors.New("HASH_OIDC_ISSUER must not contain a query or fragment")
	}

	redirectURL, err := parseAbsoluteRuntimeURL("HASH_OIDC_REDIRECT_URL", c.OIDCRedirectURL)
	if err != nil {
		return err
	}
	if redirectURL.Path != "/auth/callback" || redirectURL.RawQuery != "" || redirectURL.Fragment != "" {
		return errors.New("HASH_OIDC_REDIRECT_URL must use the exact /auth/callback path with no query or fragment")
	}

	development := c.Environment == "development"
	if !development {
		if publicURL.Scheme != "https" {
			return errors.New("HASH_PUBLIC_URL must use https outside local development")
		}
		if issuerURL.Scheme != "https" {
			return errors.New("HASH_OIDC_ISSUER must use https outside local development")
		}
		if redirectURL.Scheme != "https" {
			return errors.New("HASH_OIDC_REDIRECT_URL must use https outside local development")
		}
	} else {
		if publicURL.Scheme != "http" && publicURL.Scheme != "https" {
			return errors.New("HASH_PUBLIC_URL must use http or https in local development")
		}
		if issuerURL.Scheme != "https" && !(issuerURL.Scheme == "http" && isLocalHostname(issuerURL.Hostname())) {
			return errors.New("HASH_OIDC_ISSUER may use http only for a loopback or local development host")
		}
		if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
			return errors.New("HASH_OIDC_REDIRECT_URL must use http or https in local development")
		}
	}

	if !sameURLOrigin(publicURL, redirectURL) {
		return errors.New("HASH_OIDC_REDIRECT_URL must match HASH_PUBLIC_URL origin and end in /auth/callback")
	}
	// PublicURL is concatenated with ceremony paths throughout the server.
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	return nil
}

func parseAbsoluteRuntimeURL(name, raw string) (*url.URL, error) {
	if raw == "" || raw != strings.TrimSpace(raw) {
		return nil, fmt.Errorf("%s must be an absolute URL without surrounding whitespace", name)
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%s must be an absolute URL", name)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s must not contain userinfo", name)
	}
	return u, nil
}

func sameURLOrigin(a, b *url.URL) bool {
	return a != nil && b != nil && strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func isLocalHostname(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		return true
	}
	return strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local")
}

func validateAuditTrustedPublicKeys(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 32 {
		return errors.New("HASH_AUDIT_TRUSTED_PUBLIC_KEYS may contain at most 32 rotation keys")
	}
	for i, part := range parts {
		key := strings.TrimSpace(part)
		if key == "" {
			return fmt.Errorf("HASH_AUDIT_TRUSTED_PUBLIC_KEYS entry %d is empty", i+1)
		}
		decoded, err := decodeBase64Key(key)
		if err != nil || len(decoded) != 32 {
			return fmt.Errorf("HASH_AUDIT_TRUSTED_PUBLIC_KEYS entry %d must be a base64-encoded 32-byte Ed25519 public key", i+1)
		}
	}
	return nil
}

func decodeBase64Key(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
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
	if _, err := hex.DecodeString(c.AIShieldKey); err != nil {
		return errors.New("HASH_AI_SHIELD_KEY must be valid hex when any AI provider is enabled in production")
	}
	extra := strings.Split(strings.ReplaceAll(c.AIEUHostsAllowlist, " ", ""), ",")
	if mistralOn {
		host, err := validatedAIEndpointHost(c.MistralBaseURL, "openrouter.ai")
		if err != nil {
			return fmt.Errorf("HASH_MISTRAL_BASE_URL: %w", err)
		}
		if !IsEUEndpoint(host, extra) {
			return fmt.Errorf("HASH_MISTRAL_BASE_URL host %q is not on the EU allow-list; use api.mistral.ai, eu.openrouter.ai, or extend HASH_AI_EU_HOSTS_ALLOWLIST", host)
		}
	}
	if anthropicOn {
		host, err := validatedAIEndpointHost(c.AnthropicBaseURL, "api.anthropic.com")
		if err != nil {
			return fmt.Errorf("HASH_ANTHROPIC_BASE_URL: %w", err)
		}
		if !IsEUEndpoint(host, extra) {
			return fmt.Errorf("HASH_ANTHROPIC_BASE_URL host %q is not on the EU allow-list; use eu.anthropic.com or extend HASH_AI_EU_HOSTS_ALLOWLIST", host)
		}
	}
	return nil
}

// IsEUEndpoint reports whether the host is on the explicit EU allow-list.
// A .eu label is not evidence of where inference or data processing occurs,
// so only the audited built-ins and operator-configured suffixes pass. Extra
// strings from HASH_AI_EU_HOSTS_ALLOWLIST are matched as suffixes (so
// "brightinteraction.com" matches any of its subdomains).
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

// validatedAIEndpointHost returns the endpoint hostname after enforcing an
// absolute HTTPS URL. AI requests carry a bearer credential and document text;
// accepting HTTP would expose both on the wire, while treating a malformed URL
// as the provider default would make the boot-time residency check validate a
// different destination from the one used at request time.
func validatedAIEndpointHost(rawURL, fallback string) (string, error) {
	if rawURL == "" {
		return strings.ToLower(fallback), nil
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("must be a valid absolute URL")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("must use https outside local development")
	}
	if u.User != nil {
		return "", errors.New("must not contain URL userinfo")
	}
	if u.Fragment != "" {
		return "", errors.New("must not contain a fragment")
	}
	return strings.ToLower(u.Hostname()), nil
}

// IsLocalDevelopment reports whether development-only relaxations are allowed.
// A local-looking URL is necessary but is not sufficient when HASH_ENVIRONMENT
// explicitly identifies production/staging: reverse-proxied production stacks
// commonly advertise a loopback URL internally. An omitted environment is
// production-safe; the bundled development Compose file opts in explicitly.
//
// It parses the URL and matches the HOST exactly. A substring match would let
// an attacker-influenced hostname like app.localhost.company.com or
// prod.local.attacker.com flip the whole instance into permissive dev mode,
// silently disabling every fail-closed gate. An empty/unparseable URL is NOT
// treated as local: HASH_PUBLIC_URL is required, so reaching this with an
// empty value is a misconfiguration that must fail closed.
func IsLocalDevelopment(publicURL string) bool {
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("HASH_ENVIRONMENT")))
	if environment != "development" {
		return false
	}
	return isLocalPublicURL(publicURL)
}

func isLocalPublicURL(publicURL string) bool {
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
	return isLocalHostname(u.Hostname()) // strips port + [::1] brackets
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

func isStrongProxyAuthSecret(value string) bool {
	return isStrongHexSecret(value, 32)
}

func isStrongHexSecret(value string, byteLength int) bool {
	if len(value) != byteLength*2 || isWeakKey(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength
}

func isStrongLegacyWebhookSecret(value string) bool {
	return len(value) <= 4096 && strings.TrimSpace(value) == value && !isWeakKey(value)
}

func isStrongEncryptionHexKey(value string) bool {
	if !isStrongHexSecret(value, 32) {
		return false
	}
	raw, _ := hex.DecodeString(value)
	for i := 1; i < len(raw); i++ {
		if raw[i] != raw[0] {
			return true
		}
	}
	return false
}

// isURLSafePathToken accepts exactly RFC 3986 unreserved ASCII characters.
// Mollie's secret is concatenated as one path segment without escaping, so
// accepting '/', '?', '#', '%' or non-ASCII input would make config preflight
// validate a different callback secret from the one the router receives.
func isURLSafePathToken(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '-', '.', '_', '~':
			continue
		default:
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

func envInt(key string, fallback int) (int, error) {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%s must be a base-10 integer", key)
		}
		return n, nil
	}
	return fallback, nil
}

func envBool(key string, fallback bool) (bool, error) {
	v := strings.ToLower(os.Getenv(key))
	switch v {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	case "":
		return fallback, nil
	default:
		return false, fmt.Errorf("%s must be one of true, false, 1, 0, yes, no, on, or off", key)
	}
}
