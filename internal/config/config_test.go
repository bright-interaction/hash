// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_MissingRequired(t *testing.T) {
	t.Setenv("HASH_PUBLIC_URL", "")
	t.Setenv("HASH_DB_URL", "")
	t.Setenv("HASH_S3_ENDPOINT", "")
	t.Setenv("HASH_OIDC_ISSUER", "")
	t.Setenv("HASH_OIDC_CLIENT_ID", "")
	t.Setenv("HASH_OIDC_CLIENT_SECRET", "")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "")
	t.Setenv("HASH_SIGNER_TOKEN_KEY", "")
	t.Setenv("HASH_SESSION_KEY", "")
	t.Setenv("HASH_WEBHOOK_ENCRYPTION_KEY", "")
	t.Setenv("HASH_PROXY_AUTH", "")
	t.Setenv("HASH_S3_ACCESS_KEY", "")
	t.Setenv("HASH_S3_SECRET_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing env, got nil")
	}
	if !strings.Contains(err.Error(), "HASH_DB_URL") {
		t.Errorf("error should mention DB_URL, got %q", err)
	}
}

func TestLoad_KeyTooShort(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SESSION_KEY", "short")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "SESSION_KEY") {
		t.Fatalf("expected SESSION_KEY error, got %v", err)
	}
}

func TestLoad_RejectsSessionKeyThatRuntimeCookieParserCannotUse(t *testing.T) {
	for _, key := range []string{
		strings.Repeat("zz", 32),
		strings.Repeat("ab", 31),
	} {
		setAllRequired(t)
		t.Setenv("HASH_SESSION_KEY", key)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_SESSION_KEY") {
			t.Fatalf("runtime-invalid session key was accepted: %v", err)
		}
	}
}

func TestLoad_RejectsMalformedTypedEnvironmentInsteadOfDefaulting(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{name: "HTTP port", key: "HASH_PORT", value: "eight-thousand"},
		{name: "SMTP port", key: "HASH_SMTP_PORT", value: "submission"},
		{name: "S3 TLS", key: "HASH_S3_USE_SSL", value: "enabled"},
		{name: "OTS evidence", key: "HASH_EVIDENCE_OTS_ENABLED", value: "definitely"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv(test.key, test.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("explicit malformed %s silently defaulted: %v", test.key, err)
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("typed configuration error exposed its raw value: %v", err)
			}
		})
	}
}

func TestLoad_RejectsHTTPPortThatServerCannotBind(t *testing.T) {
	for _, port := range []string{"-1", "0", "65536"} {
		t.Run(port, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_PORT", port)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_PORT") {
				t.Fatalf("runtime-invalid HTTP port %q was accepted: %v", port, err)
			}
		})
	}
}

func TestLoad_RejectsSignerKeyOutsideDocumentedRuntimeContract(t *testing.T) {
	for _, key := range []string{
		strings.Repeat("xy", 32),
		strings.Repeat("ab", 31),
		strings.Repeat("ab", 33),
	} {
		setAllRequired(t)
		t.Setenv("HASH_SIGNER_TOKEN_KEY", key)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_SIGNER_TOKEN_KEY") {
			t.Fatalf("runtime-contract-invalid signer key was accepted: %v", err)
		}
	}
}

func TestLoad_OK(t *testing.T) {
	setAllRequired(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Port == 0 {
		t.Error("port not defaulted")
	}
	if c.Release != strings.Repeat("ab", 20) || c.Environment != "production" {
		t.Errorf("telemetry identity = %q/%q, want immutable test release/production", c.Release, c.Environment)
	}
	if c.S3SSEMode != "sse-s3" || c.S3SSECKeyFile != "" || c.S3BucketLookup != "auto" {
		t.Fatalf("default S3 policy = %q/%q/%q, want sse-s3/no-key/auto", c.S3SSEMode, c.S3SSECKeyFile, c.S3BucketLookup)
	}
	if c.OperatorName != "Example Hash Operator AB" || c.PrivacyContact != "privacy@example.test" || c.SupervisoryAuthority != "Example Data Protection Authority" || c.PrivacyPolicyURL != "https://example.test/privacy" {
		t.Fatalf("operator disclosure identity was not loaded exactly: %#v", c)
	}
}

func TestLoad_ValidatesSSECPolicyBeforeNetworkAccess(t *testing.T) {
	key := sha256.Sum256([]byte("public config-test SSE-C key material"))
	keyFile := filepath.Join(t.TempDir(), "sse-c.key")
	if err := os.WriteFile(keyFile, key[:], 0o600); err != nil {
		t.Fatal(err)
	}

	setAllRequired(t)
	t.Setenv("HASH_S3_SSE_MODE", "sse-c")
	t.Setenv("HASH_S3_SSE_C_KEY_FILE", keyFile)
	t.Setenv("HASH_S3_BUCKET_LOOKUP", "path")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid SSE-C policy rejected: %v", err)
	}
	if cfg.S3SSEMode != "sse-c" || cfg.S3SSECKeyFile != keyFile || cfg.S3BucketLookup != "path" {
		t.Fatal("validated SSE-C configuration was not preserved")
	}

	for _, test := range []struct {
		name    string
		mode    string
		keyFile string
		lookup  string
		useSSL  string
		want    string
	}{
		{name: "missing key file", mode: "sse-c", lookup: "auto", useSSL: "true", want: "HASH_S3_SSE_C_KEY_FILE is required"},
		{name: "plaintext transport", mode: "sse-c", keyFile: keyFile, lookup: "auto", useSSL: "false", want: "requires HASH_S3_USE_SSL=true"},
		{name: "key path under sse-s3", mode: "sse-s3", keyFile: keyFile, lookup: "auto", useSSL: "true", want: "must be empty"},
		{name: "unknown encryption", mode: "SSE-C", keyFile: keyFile, lookup: "auto", useSSL: "true", want: "must be exactly sse-s3 or sse-c"},
		{name: "unknown addressing", mode: "sse-s3", lookup: "virtual", useSSL: "true", want: "must be exactly auto, path, or dns"},
	} {
		t.Run(test.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_S3_SSE_MODE", test.mode)
			t.Setenv("HASH_S3_SSE_C_KEY_FILE", test.keyFile)
			t.Setenv("HASH_S3_BUCKET_LOOKUP", test.lookup)
			t.Setenv("HASH_S3_USE_SSL", test.useSSL)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid S3 policy accepted: %v", err)
			}
		})
	}
}

func TestLoad_RejectsWrongLengthSSECKeyWithoutRenderingIt(t *testing.T) {
	contents := []byte("not-a-32-byte-customer-key")
	keyFile := filepath.Join(t.TempDir(), "sse-c.key")
	if err := os.WriteFile(keyFile, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	setAllRequired(t)
	t.Setenv("HASH_S3_SSE_MODE", "sse-c")
	t.Setenv("HASH_S3_SSE_C_KEY_FILE", keyFile)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "exactly 32 raw bytes") {
		t.Fatalf("wrong-length SSE-C key accepted: %v", err)
	}
	if strings.Contains(err.Error(), string(contents)) {
		t.Fatal("SSE-C key contents leaked through config validation")
	}
}

func TestLoad_NonDevelopmentRequiresInstanceDisclosureIdentity(t *testing.T) {
	for _, environment := range []string{"production", "staging"} {
		for _, field := range []string{"HASH_OPERATOR_NAME", "HASH_PRIVACY_CONTACT", "HASH_SUPERVISORY_AUTHORITY", "HASH_PRIVACY_POLICY_URL"} {
			t.Run(environment+"_missing_"+field, func(t *testing.T) {
				setAllRequired(t)
				t.Setenv("HASH_ENVIRONMENT", environment)
				t.Setenv(field, "")
				if _, err := Load(); err == nil || !strings.Contains(err.Error(), field) {
					t.Fatalf("missing signer disclosure identity %s was accepted: %v", field, err)
				}
			})
		}
	}
}

func TestLoad_ValidatesInstanceDisclosureIdentity(t *testing.T) {
	tests := []struct {
		name, field, value string
	}{
		{"display-name privacy address", "HASH_PRIVACY_CONTACT", "Privacy Team <privacy@example.test>"},
		{"invalid privacy address", "HASH_PRIVACY_CONTACT", "not-an-email"},
		{"operator control character", "HASH_OPERATOR_NAME", "Example\nOperator"},
		{"authority control character", "HASH_SUPERVISORY_AUTHORITY", "Authority\tElsewhere"},
		{"relative deployed privacy policy", "HASH_PRIVACY_POLICY_URL", "/legal/privacy"},
		{"insecure deployed privacy policy", "HASH_PRIVACY_POLICY_URL", "http://example.test/privacy"},
		{"credentialed privacy policy", "HASH_PRIVACY_POLICY_URL", "https://user@example.test/privacy"},
		{"query-bearing privacy policy", "HASH_PRIVACY_POLICY_URL", "https://example.test/privacy?version=1"},
		{"fragmented privacy policy", "HASH_PRIVACY_POLICY_URL", "https://example.test/privacy#section"},
		{"signer-route privacy policy", "HASH_PRIVACY_POLICY_URL", "https://example.test/sign/bearer-token/dsr"},
		{"encoded signer-route privacy policy", "HASH_PRIVACY_POLICY_URL", "https://example.test/sign%2Fbearer-token%2Fdsr"},
		{"traversal signer-route privacy policy", "HASH_PRIVACY_POLICY_URL", "https://example.test/legal/../sign/bearer-token/dsr"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv(test.field, test.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), test.field) {
				t.Fatalf("unsafe disclosure identity accepted: %v", err)
			}
		})
	}
}

func TestLoad_LocalDevelopmentUsesExplicitlyLocalDisclosureDefaults(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost:8090/auth/callback")
	t.Setenv("HASH_OPERATOR_NAME", "")
	t.Setenv("HASH_PRIVACY_CONTACT", "")
	t.Setenv("HASH_SUPERVISORY_AUTHORITY", "")
	t.Setenv("HASH_PRIVACY_POLICY_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("local disclosure defaults rejected: %v", err)
	}
	if !strings.Contains(strings.ToLower(cfg.OperatorName), "local development") || !strings.HasSuffix(cfg.PrivacyContact, ".invalid") || !strings.Contains(strings.ToLower(cfg.SupervisoryAuthority), "local development") || cfg.PrivacyPolicyURL != "/legal/privacy" {
		t.Fatalf("local defaults could be mistaken for deployed operator facts: %#v", cfg)
	}
}

func TestLoad_ProductionRequiresIndependentStrongProxyAuth(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "missing", value: ""},
		{name: "short", value: "abcd"},
		{name: "non hex", value: strings.Repeat("xy", 32)},
		{name: "all identical", value: strings.Repeat("a", 64)},
		{name: "reuses signer key", value: strings.Repeat("ab", 32)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_PROXY_AUTH", test.value)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_PROXY_AUTH") {
				t.Fatalf("unsafe production proxy authentication secret was accepted: %v", err)
			}
		})
	}
}

func TestLoad_DevelopmentAndStagingDoNotRequireProxyAuth(t *testing.T) {
	for _, environment := range []string{"development", "staging"} {
		t.Run(environment, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_PROXY_AUTH", "")
			t.Setenv("HASH_ENVIRONMENT", environment)
			if environment == "development" {
				t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
				t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
				t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost:8090/auth/callback")
			}
			if _, err := Load(); err != nil {
				t.Fatalf("%s unexpectedly required production proxy authentication: %v", environment, err)
			}
		})
	}
}

func TestLoad_RejectsUnknownEnvironmentInsteadOfBypassingProductionControls(t *testing.T) {
	for _, environment := range []string{"prod", "qa", "testing", "unknown"} {
		t.Run(strings.ReplaceAll(environment, " ", "_"), func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_ENVIRONMENT", environment)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must be exactly development, staging, or production") {
				t.Fatalf("unknown environment %q did not fail closed: %v", environment, err)
			}
		})
	}
}

func TestLoad_ProductionRequiresImmutableReleaseIdentity(t *testing.T) {
	for _, release := range []string{strings.Repeat("ab", 20), strings.Repeat("cd", 32)} {
		t.Run("accepts_"+release[:4], func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_RELEASE", release)
			if _, err := Load(); err != nil {
				t.Fatalf("valid immutable release rejected: %v", err)
			}
		})
	}
	for _, release := range []string{"", "unknown", "sha-0123456789abcdef", strings.Repeat("A", 40), strings.Repeat("a", 39), "sha256:" + strings.Repeat("a", 64)} {
		t.Run("rejects_"+strings.ReplaceAll(release, ":", "_"), func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_RELEASE", release)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "exact lowercase 40- or 64-character") {
				t.Fatalf("unsafe production release %q accepted: %v", release, err)
			}
		})
	}
}

func TestLoad_RejectsOTSOutsideDevelopment(t *testing.T) {
	for _, environment := range []string{"production", "staging"} {
		t.Run(environment, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_ENVIRONMENT", environment)
			t.Setenv("HASH_EVIDENCE_OTS_ENABLED", "true")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "OTS proof verification") {
				t.Fatalf("%s accepted unverifiable OTS evidence: %v", environment, err)
			}
		})
	}
}

func TestLoad_AllowsOTSOnlyInExplicitLocalDevelopment(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost:8090/auth/callback")
	t.Setenv("HASH_EVIDENCE_OTS_ENABLED", "true")
	config, err := Load()
	if err != nil {
		t.Fatalf("explicit local development OTS rejected: %v", err)
	}
	if !config.EvidenceOTSEnabled {
		t.Fatal("development OTS flag was lost")
	}
}

func TestLoad_ProductionAuthenticationURLsFailClosed(t *testing.T) {
	tests := []struct {
		name, key, value, want string
	}{
		{"plaintext public URL", "HASH_PUBLIC_URL", "http://hash.brightinteraction.com", "HASH_PUBLIC_URL must use https"},
		{"public URL path", "HASH_PUBLIC_URL", "https://hash.brightinteraction.com/app", "origin only"},
		{"public URL query", "HASH_PUBLIC_URL", "https://hash.brightinteraction.com?next=evil", "origin only"},
		{"public URL userinfo", "HASH_PUBLIC_URL", "https://user@hash.brightinteraction.com", "userinfo"},
		{"relative public URL", "HASH_PUBLIC_URL", "hash.brightinteraction.com", "absolute URL"},
		{"plaintext issuer", "HASH_OIDC_ISSUER", "http://auth.example.com", "HASH_OIDC_ISSUER must use https"},
		{"relative issuer", "HASH_OIDC_ISSUER", "/realms/hash", "absolute URL"},
		{"plaintext redirect", "HASH_OIDC_REDIRECT_URL", "http://hash.brightinteraction.com/auth/callback", "HASH_OIDC_REDIRECT_URL must use https"},
		{"cross-origin redirect", "HASH_OIDC_REDIRECT_URL", "https://attacker.example/auth/callback", "must match HASH_PUBLIC_URL origin"},
		{"wrong redirect path", "HASH_OIDC_REDIRECT_URL", "https://hash.brightinteraction.com/callback", "exact /auth/callback"},
		{"redirect query", "HASH_OIDC_REDIRECT_URL", "https://hash.brightinteraction.com/auth/callback?next=evil", "exact /auth/callback"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv(tc.key, tc.value)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoad_LocalDevelopmentAuthenticationURLs(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "http://127.0.0.1:8090/")
	t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://127.0.0.1:8090/auth/callback")
	c, err := Load()
	if err != nil {
		t.Fatalf("local development URLs rejected: %v", err)
	}
	if c.PublicURL != "http://127.0.0.1:8090" {
		t.Fatalf("canonical PublicURL = %q", c.PublicURL)
	}

	t.Setenv("HASH_OIDC_ISSUER", "http://auth.example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "loopback or local") {
		t.Fatalf("public plaintext issuer accepted in development: %v", err)
	}
}

func TestLoad_TelemetryIdentity(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_RELEASE", "sha-0123456789abcdef")
	t.Setenv("HASH_ENVIRONMENT", "staging")

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Release != "sha-0123456789abcdef" || c.Environment != "staging" {
		t.Errorf("telemetry identity = %q/%q, want explicit release/staging", c.Release, c.Environment)
	}

	t.Setenv("HASH_ENVIRONMENT", "")
	t.Setenv("HASH_RELEASE", strings.Repeat("01", 20))
	c, err = Load()
	if err != nil {
		t.Fatalf("Load with inferred production environment: %v", err)
	}
	if c.Environment != "production" {
		t.Errorf("default environment = %q, want production", c.Environment)
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("X", "true")
	if got, err := envBool("X", false); err != nil || !got {
		t.Error("'true' parsed as false")
	}
	t.Setenv("X", "false")
	if got, err := envBool("X", true); err != nil || got {
		t.Error("'false' parsed as true")
	}
	t.Setenv("X", "")
	if got, err := envBool("X", true); err != nil || !got {
		t.Error("empty did not return fallback")
	}
	t.Setenv("X", "truthy")
	if _, err := envBool("X", true); err == nil {
		t.Error("malformed explicit bool silently returned fallback")
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("X", "42")
	if got, err := envInt("X", 0); err != nil || got != 42 {
		t.Error("int parse failed")
	}
	t.Setenv("X", "abc")
	if _, err := envInt("X", 7); err == nil {
		t.Error("malformed explicit int silently returned fallback")
	}
	t.Setenv("X", "")
	if got, err := envInt("X", 7); err != nil || got != 7 {
		t.Error("empty did not return fallback")
	}
}

func TestIsLocalDevelopment(t *testing.T) {
	t.Setenv("HASH_ENVIRONMENT", "development")
	cases := map[string]bool{
		"":                                    false, // unconfigured fails closed, not local
		"http://localhost":                    true,
		"http://localhost:8080":               true,
		"https://127.0.0.1":                   true,
		"http://[::1]:8090":                   true,
		"http://0.0.0.0":                      true,
		"http://laptop.local":                 true,
		"http://x.localhost":                  true,
		"https://hash.brightinteraction.com":  false,
		"https://esign.brightinteraction.com": false,
		// Adversarial: substring-of-"localhost"/".local" must NOT pass.
		"https://app.localhost.company.com": false,
		"https://prod.local.attacker.com":   false,
		"https://localhost.evil.com":        false,
	}
	for in, want := range cases {
		if got := IsLocalDevelopment(in); got != want {
			t.Errorf("IsLocalDevelopment(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsLocalDevelopment_ExplicitRuntimeModeWins(t *testing.T) {
	t.Setenv("HASH_ENVIRONMENT", "production")
	if IsLocalDevelopment("http://127.0.0.1:8080") {
		t.Fatal("explicit production mode must not enable development relaxations for a loopback URL")
	}
	t.Setenv("HASH_ENVIRONMENT", "staging")
	if IsLocalDevelopment("http://localhost:8080") {
		t.Fatal("explicit staging mode must not enable development relaxations for a loopback URL")
	}
	t.Setenv("HASH_ENVIRONMENT", "development")
	if !IsLocalDevelopment("http://localhost:8080") {
		t.Fatal("explicit development mode with a local URL should enable development relaxations")
	}
	if IsLocalDevelopment("https://hash.example.test") {
		t.Fatal("development mode alone must not relax a publicly addressed deployment")
	}
}

func TestLoad_ExplicitProductionModeOnLoopbackStillEnforcesProductionGuards(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "production")
	t.Setenv("HASH_PUBLIC_URL", "http://127.0.0.1:8080")
	t.Setenv("HASH_QES_PROVIDER", "mock")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_PUBLIC_URL must use https") {
		t.Fatalf("loopback URL bypassed explicit production guards: %v", err)
	}
}

func TestLoad_DevelopmentModeRejectsPublicURL(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "https://hash.example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_ENVIRONMENT=development") {
		t.Fatalf("publicly addressed development mode should fail closed: %v", err)
	}
}

func TestLoad_BrightCRMSecretRequiredInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_BRIGHTCRM_URL", "https://crm.example.com")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	t.Setenv("HASH_EVIDENCE_OTS_ENABLED", "false")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "BRIGHTCRM_WEBHOOK_SECRET") {
		t.Fatalf("expected BrightCRM secret guard, got %v", err)
	}
}

func TestLoad_BrightCRMSecretRequiredLocallyWhenIntegrationEnabled(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost:8090/auth/callback")
	t.Setenv("HASH_BRIGHTCRM_URL", "https://crm.example.com")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "BRIGHTCRM_WEBHOOK_SECRET") {
		t.Fatalf("enabled local integration should require a secret, got %v", err)
	}
}

func TestLoad_BrightCRMSecretSkippedWhenIntegrationOff(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_BRIGHTCRM_URL", "")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	if _, err := Load(); err != nil {
		t.Fatalf("integration disabled should skip secret check: %v", err)
	}
}

func TestLoad_CredentialedResolverIntegrationsFailClosed(t *testing.T) {
	tests := []struct {
		name, urlKey, tokenKey, endpoint, token, want string
	}{
		{"BrightCRM URL without token", "HASH_BRIGHTCRM_URL", "HASH_BRIGHTCRM_TOKEN", "https://crm.example.test", "", "both be set"},
		{"scanner token without URL", "HASH_SCANNER_URL", "HASH_SCANNER_TOKEN", "", "secret", "both be set"},
		{"plaintext BrightCRM", "HASH_BRIGHTCRM_URL", "HASH_BRIGHTCRM_TOKEN", "http://crm.example.test", "secret", "must use https"},
		{"BrightCRM userinfo", "HASH_BRIGHTCRM_URL", "HASH_BRIGHTCRM_TOKEN", "https://user@crm.example.test", "secret", "origin only"},
		{"BrightCRM path", "HASH_BRIGHTCRM_URL", "HASH_BRIGHTCRM_TOKEN", "https://crm.example.test/base", "secret", "origin only"},
		{"scanner query", "HASH_SCANNER_URL", "HASH_SCANNER_TOKEN", "https://scanner.example.test?target=x", "secret", "origin only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv(tc.urlKey, tc.endpoint)
			t.Setenv(tc.tokenKey, tc.token)
			if tc.urlKey == "HASH_BRIGHTCRM_URL" && tc.endpoint != "" {
				t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", strings.Repeat("b", 32))
			}
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe integration config accepted: %v", err)
			}
		})
	}
}

func TestLoad_AllowsLocalHTTPResolverIntegrationOnlyInDevelopment(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost:8090/auth/callback")
	t.Setenv("HASH_BRIGHTCRM_URL", "http://brightcrm.local:8080")
	t.Setenv("HASH_BRIGHTCRM_TOKEN", "development-token")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", strings.Repeat("b", 32))
	if _, err := Load(); err != nil {
		t.Fatalf("local development resolver rejected: %v", err)
	}
}

func TestLoad_ComplianceFeedRequiresSafeHTTPSInProduction(t *testing.T) {
	for _, endpoint := range []string{
		"http://compliance.example.test/feed.json",
		"compliance.example.test/feed.json",
		"https://user:secret@compliance.example.test/feed.json",
		"https://compliance.example.test/feed.json#fragment",
	} {
		t.Run(endpoint, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_COMPLIANCE_FEED_URL", endpoint)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_COMPLIANCE_FEED_URL") {
				t.Fatalf("unsafe compliance feed %q accepted: %v", endpoint, err)
			}
		})
	}

	setAllRequired(t)
	t.Setenv("HASH_COMPLIANCE_FEED_URL", "https://compliance.example.test/v1/feed.json")
	if _, err := Load(); err != nil {
		t.Fatalf("valid HTTPS compliance feed rejected: %v", err)
	}
}

func TestIsEUEndpoint(t *testing.T) {
	cases := map[string]bool{
		"api.mistral.ai":               true,
		"chat.api.mistral.ai":          true,
		"eu.anthropic.com":             true,
		"eu.openrouter.ai":             true,
		"eu.api.openrouter.ai":         true,
		"llm.eu.brightinteraction.com": false,
		"sovereign-llm.eu":             false,
		"openrouter.ai":                false,
		"api.anthropic.com":            false,
		"api.openai.com":               false,
		"":                             false,
	}
	for in, want := range cases {
		if got := IsEUEndpoint(in, nil); got != want {
			t.Errorf("IsEUEndpoint(%q) = %v want %v", in, got, want)
		}
	}
}

func TestIsEUEndpoint_ExtraAllowlist(t *testing.T) {
	extra := []string{"llm.example.eu", "llama.tailscale.local"}
	if !IsEUEndpoint("llm.example.eu", extra) {
		t.Error("FQDN allowlist match failed")
	}
	if !IsEUEndpoint("v2.llm.example.eu", extra) {
		t.Error("subdomain of allowlist match failed")
	}
	if IsEUEndpoint("evil.example", extra) {
		t.Error("non-allowlisted host should fail")
	}
}

func TestLoad_AIShieldRequiredInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", "")
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-test")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://api.mistral.ai/v1/chat/completions")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "AI_SHIELD_KEY") {
		t.Fatalf("expected AI Shield guard, got %v", err)
	}
}

func TestLoad_AIShieldMustBeValidHexInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", strings.Repeat("z", 64))
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-test")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://api.mistral.ai/v1/chat/completions")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "valid hex") {
		t.Fatalf("expected malformed AI Shield key to fail closed, got %v", err)
	}
}

func TestLoad_AIShieldNotRequiredWhenAIDisabled(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", "")
	t.Setenv("HASH_MISTRAL_API_KEY", "")
	t.Setenv("HASH_ANTHROPIC_API_KEY", "")
	if _, err := Load(); err != nil {
		t.Fatalf("AI disabled prod should boot without Shield, got %v", err)
	}
}

func TestLoad_AIShieldConfiguredWithoutProviderMustMatchRuntimeKeyFormat(t *testing.T) {
	for _, key := range []string{
		strings.Repeat("z", 64),
		strings.Repeat("ab", 31),
		strings.Repeat("ab", 33),
	} {
		setAllRequired(t)
		t.Setenv("HASH_AI_SHIELD_KEY", key)
		t.Setenv("HASH_MISTRAL_API_KEY", "")
		t.Setenv("HASH_ANTHROPIC_API_KEY", "")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_AI_SHIELD_KEY") {
			t.Fatalf("runtime-invalid configured Shield key was accepted without a provider: %v", err)
		}
	}
}

func TestLoad_AIRejectsNonEUProviderInProd(t *testing.T) {
	setAllRequired(t)
	long := strings.Repeat("a", 64)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", long)
	t.Setenv("HASH_ANTHROPIC_API_KEY", "sk-anthropic")
	t.Setenv("HASH_ANTHROPIC_BASE_URL", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "ANTHROPIC_BASE_URL") {
		t.Fatalf("expected Anthropic EU lock, got %v", err)
	}
}

func TestLoad_AIRejectsDefaultOpenRouterInProd(t *testing.T) {
	setAllRequired(t)
	long := strings.Repeat("a", 64)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", long)
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-mistral")
	t.Setenv("HASH_MISTRAL_BASE_URL", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MISTRAL_BASE_URL") {
		t.Fatalf("openrouter.ai default should fail prod EU lock, got %v", err)
	}
}

func TestLoad_AIAcceptsEUMistralInProd(t *testing.T) {
	setAllRequired(t)
	long := strings.Repeat("a", 64)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", long)
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-mistral")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://api.mistral.ai/v1/chat/completions")
	if _, err := Load(); err != nil {
		t.Fatalf("api.mistral.ai should pass EU lock, got %v", err)
	}
}

func TestLoad_AIRejectsPlaintextOrMalformedEndpointInProd(t *testing.T) {
	for _, endpoint := range []string{
		"http://api.mistral.ai/v1/chat/completions",
		"api.mistral.ai/v1/chat/completions",
		"https://user:secret@api.mistral.ai/v1/chat/completions",
		"https://api.mistral.ai/v1/chat/completions#other",
	} {
		t.Run(endpoint, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_AI_SHIELD_KEY", strings.Repeat("a", 64))
			t.Setenv("HASH_MISTRAL_API_KEY", "sk-mistral")
			t.Setenv("HASH_MISTRAL_BASE_URL", endpoint)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_MISTRAL_BASE_URL") {
				t.Fatalf("unsafe AI endpoint %q should fail closed: %v", endpoint, err)
			}
		})
	}
}

func TestLoad_AIAcceptsAllowlistOverrideInProd(t *testing.T) {
	setAllRequired(t)
	long := strings.Repeat("a", 64)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", long)
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-mistral")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://llm.example.eu/v1/chat/completions")
	t.Setenv("HASH_AI_EU_HOSTS_ALLOWLIST", "example.eu")
	if _, err := Load(); err != nil {
		t.Fatalf("allowlist override should pass, got %v", err)
	}
}

func TestLoad_AIRejectsUnlistedDotEUHostInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", strings.Repeat("a", 64))
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-mistral")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://attacker-controlled.eu/v1/chat/completions")
	t.Setenv("HASH_AI_EU_HOSTS_ALLOWLIST", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "EU allow-list") {
		t.Fatalf("an unlisted .eu hostname is not residency evidence and must fail closed: %v", err)
	}
}

func TestLoad_AISkipsGateInLocalDev(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_ENVIRONMENT", "development")
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_OIDC_ISSUER", "http://localhost:9999")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost:8090/auth/callback")
	t.Setenv("HASH_AI_SHIELD_KEY", "")
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-test")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")
	if _, err := Load(); err != nil {
		t.Fatalf("local dev should skip AI gate, got %v", err)
	}
}

func TestLoad_ProductionRejectsUnsetBillingProvider(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_BILLING_PROVIDER", "")
	t.Setenv("HASH_MOLLIE_API_KEY", "")
	t.Setenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "bypasses quota") {
		t.Fatalf("production without billing must fail closed, got %v", err)
	}
}

func TestLoad_RejectsMollieWebhookSecretThatCannotRoundTripAsOnePathSegment(t *testing.T) {
	for _, secret := range []string{
		"sixteen-chars-ok/nested",
		"sixteen-chars-ok?query",
		"sixteen-chars-ok#fragment",
		"sixteen-chars-ok%2Fencoded",
		"sixteen-chars-ö",
	} {
		setAllRequired(t)
		t.Setenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET", secret)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_MOLLIE_WEBHOOK_PATH_SECRET") {
			t.Fatalf("non-round-trippable Mollie webhook path secret was accepted: %v", err)
		}
	}
}

func setAllRequired(t *testing.T) {
	t.Helper()
	// 64 chars of non-uniform content: passes the >=32 length check AND the
	// all-identical-character weak-key rejection.
	key := strings.Repeat("ab", 32)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_RELEASE", strings.Repeat("ab", 20))
	t.Setenv("HASH_ENVIRONMENT", "")
	t.Setenv("HASH_DB_URL", "postgres://x")
	t.Setenv("HASH_S3_ENDPOINT", "minio:9000")
	t.Setenv("HASH_S3_ACCESS_KEY", "k")
	t.Setenv("HASH_S3_SECRET_KEY", "s")
	t.Setenv("HASH_OIDC_ISSUER", "https://auth.example.com")
	t.Setenv("HASH_OIDC_CLIENT_ID", "c")
	t.Setenv("HASH_OIDC_CLIENT_SECRET", "cs")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "https://hash.brightinteraction.com/auth/callback")
	t.Setenv("HASH_SIGNER_TOKEN_KEY", key)
	t.Setenv("HASH_SESSION_KEY", key)
	// A third, independently generated 32-byte key seals outbound webhook
	// credentials at rest and is shared by the HTTP server + worker.
	t.Setenv("HASH_WEBHOOK_ENCRYPTION_KEY", strings.Repeat("ef01", 16))
	t.Setenv("HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS", "")
	// A distinct 32-byte value: proxy authentication is a separate trust domain
	// and production rejects reusing either application signing key.
	t.Setenv("HASH_PROXY_AUTH", strings.Repeat("cd", 32))
	t.Setenv("HASH_OPERATOR_NAME", "Example Hash Operator AB")
	t.Setenv("HASH_PRIVACY_CONTACT", "privacy@example.test")
	t.Setenv("HASH_SUPERVISORY_AUTHORITY", "Example Data Protection Authority")
	t.Setenv("HASH_PRIVACY_POLICY_URL", "https://example.test/privacy")
	t.Setenv("HASH_SMTP_HOST", "smtp.example.test")
	t.Setenv("HASH_PORT", "8080")
	t.Setenv("HASH_SMTP_PORT", "587")
	t.Setenv("HASH_SMTP_USER", "")
	t.Setenv("HASH_SMTP_PASSWORD", "")
	t.Setenv("HASH_SMTP_FROM", "Hash <esign@example.test>")
	t.Setenv("HASH_S3_USE_SSL", "true")
	t.Setenv("HASH_S3_SSE_MODE", "")
	t.Setenv("HASH_S3_SSE_C_KEY_FILE", "")
	t.Setenv("HASH_S3_BUCKET_LOOKUP", "")
	t.Setenv("HASH_EVIDENCE_OTS_ENABLED", "false")
	t.Setenv("HASH_BRIGHTCRM_URL", "")
	t.Setenv("HASH_BRIGHTCRM_TOKEN", "")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	t.Setenv("HASH_SCANNER_URL", "")
	t.Setenv("HASH_SCANNER_TOKEN", "")
	t.Setenv("HASH_COMPLIANCE_FEED_URL", "")
	// Higher-assurance signing is intentionally disabled until proofs bind to
	// and are consumed with the exact ceremony digest. Keep the baseline SES.
	t.Setenv("HASH_QES_PROVIDER", "")
	t.Setenv("HASH_QES_IDURA_API_KEY", "")
	t.Setenv("HASH_QES_TRUST_LIST_PATH", "")
	t.Setenv("HASH_BILLING_PROVIDER", "mollie")
	t.Setenv("HASH_MOLLIE_API_KEY", "mollie-test-key")
	t.Setenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET", "molliepathsecret16")
	// Computed, not a literal: a base64 string in source reads as a leaked
	// credential to secret scanners (see .gitleaks.toml allowlist for the
	// historical literal form).
	t.Setenv("HASH_AUDIT_PRIVATE_KEY",
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32))))
	t.Setenv("HASH_AUDIT_TRUSTED_PUBLIC_KEYS", "")
	t.Setenv("HASH_WEBHOOK_SECRET", "")
	t.Setenv("HASH_WEBHOOK_SECRET_PREVIOUS", "")
}

func TestLoad_ValidatesDedicatedWebhookEncryptionKeys(t *testing.T) {
	for _, test := range []struct {
		name     string
		current  string
		previous string
	}{
		{name: "short current", current: "abcd"},
		{name: "non-hex current", current: strings.Repeat("xz", 32)},
		{name: "uniform current", current: strings.Repeat("0", 64)},
		{name: "uniform decoded current", current: strings.Repeat("ef", 32)},
		{name: "short previous", current: strings.Repeat("ef01", 16), previous: "abcd"},
		{name: "same previous", current: strings.Repeat("ef01", 16), previous: strings.Repeat("ef01", 16)},
	} {
		t.Run(test.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_WEBHOOK_ENCRYPTION_KEY", test.current)
			t.Setenv("HASH_WEBHOOK_ENCRYPTION_KEY_PREVIOUS", test.previous)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_WEBHOOK_ENCRYPTION_KEY") {
				t.Fatalf("invalid webhook encryption keys were accepted: %v", err)
			}
		})
	}
}

func TestLoad_RejectsWebhookEncryptionKeyReuse(t *testing.T) {
	for _, webhookKey := range []string{strings.Repeat("ab01", 16), strings.ToUpper(strings.Repeat("ab01", 16))} {
		setAllRequired(t)
		reused := strings.Repeat("ab01", 16)
		t.Setenv("HASH_SIGNER_TOKEN_KEY", reused)
		t.Setenv("HASH_WEBHOOK_ENCRYPTION_KEY", webhookKey)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "independently generated") {
			t.Fatalf("signer/session key reuse was accepted: %v", err)
		}
	}
}

func TestLoad_ValidatesLegacyWebhookSecretBeforeBackfill(t *testing.T) {
	for _, legacy := range []string{"changeme", strings.Repeat("x", 32), " " + strings.Repeat("ab", 16)} {
		t.Run(legacy[:1], func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_WEBHOOK_SECRET", legacy)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_WEBHOOK_SECRET") {
				t.Fatalf("weak legacy webhook secret was accepted: %v", err)
			}
		})
	}
}

func TestLoad_ValidatesRotatedAuditPublicKeys(t *testing.T) {
	setAllRequired(t)
	key1 := base64.StdEncoding.EncodeToString([]byte("first-rotation-public-key-32byte"))
	key2 := base64.RawURLEncoding.EncodeToString([]byte("second-rotation-public-key-32byt"))
	t.Setenv("HASH_AUDIT_TRUSTED_PUBLIC_KEYS", key1+","+key2)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("valid rotated audit keys rejected: %v", err)
	}
	if cfg.AuditTrustedPublicKeys != key1+","+key2 {
		t.Fatalf("trusted audit keys changed during load: %q", cfg.AuditTrustedPublicKeys)
	}

	for _, invalid := range []string{"not-base64", key1 + ",", base64.StdEncoding.EncodeToString([]byte("too short"))} {
		t.Setenv("HASH_AUDIT_TRUSTED_PUBLIC_KEYS", invalid)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_AUDIT_TRUSTED_PUBLIC_KEYS") {
			t.Fatalf("invalid rotated audit key %q was accepted: %v", invalid, err)
		}
	}
}

func TestLoad_ProductionRequiresSMTP(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SMTP_HOST", "")
	t.Setenv("HASH_SMTP_FROM", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_SMTP_HOST") || !strings.Contains(err.Error(), "HASH_SMTP_FROM") {
		t.Fatalf("production without SMTP must fail closed: %v", err)
	}
}

func TestLoad_RejectsSMTPFromThatWorkerCannotParse(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SMTP_FROM", "sender-one@example.test, sender-two@example.test")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_SMTP_FROM") {
		t.Fatalf("runtime-invalid SMTP From was accepted: %v", err)
	}
}

func TestLoad_RejectsInvalidOrUndersizedProductionDatabasePool(t *testing.T) {
	for _, tc := range []struct {
		name string
		dsn  string
	}{
		{name: "invalid DSN", dsn: "postgres://user:do-not-log-me@%"},
		{name: "pool too small", dsn: "postgres://db.example.test/hash?pool_max_conns=2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_DB_URL", tc.dsn)
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), "HASH_DB_URL") {
				t.Fatalf("invalid production database config was accepted: %v", err)
			}
			if strings.Contains(err.Error(), "do-not-log-me") {
				t.Fatalf("database validation error exposed DSN credentials: %v", err)
			}
		})
	}
}

func TestLoad_ProductionRejectsPlaintextDevelopmentSMTPPort(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SMTP_PORT", "1025")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("production plaintext SMTP port must fail closed: %v", err)
	}
}

func TestLoad_RejectsPartialSMTPCredentials(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SMTP_USER", "mailer")
	t.Setenv("HASH_SMTP_PASSWORD", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_SMTP_PASSWORD") {
		t.Fatalf("partial SMTP credentials must fail closed: %v", err)
	}
}

func TestLoad_RejectsAllZeroKeys(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SIGNER_TOKEN_KEY", strings.Repeat("0", 64))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SIGNER_TOKEN_KEY") {
		t.Fatalf("all-zero signer key should be rejected, got %v", err)
	}
}

func TestLoad_RejectsEveryQESProviderUntilProofBindingExists(t *testing.T) {
	for _, provider := range []string{"mock", "idura", "signicat"} {
		t.Run(provider, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_QES_PROVIDER", provider)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "QES is disabled") {
				t.Fatalf("QES provider %q should fail closed, got %v", provider, err)
			}
		})
	}
}

func TestLoad_RejectsMockBillingInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_BILLING_PROVIDER", "mock")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_BILLING_PROVIDER") {
		t.Fatalf("mock billing in prod should be rejected, got %v", err)
	}
}

func TestLoad_ProductionPinsOfficialMollieEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://api.mollie.com/v2",
		"https://api.mollie.com.evil.example/v2",
		"https://user:secret@api.mollie.com/v2",
		"https://api.mollie.com/v1",
		"https://api.mollie.com:8443/v2",
	} {
		t.Run(endpoint, func(t *testing.T) {
			setAllRequired(t)
			t.Setenv("HASH_MOLLIE_BASE_URL", endpoint)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_MOLLIE_BASE_URL") {
				t.Fatalf("unsafe Mollie endpoint %q should fail closed: %v", endpoint, err)
			}
		})
	}
}

func TestLoad_AuditKeyRequiredInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AUDIT_PRIVATE_KEY", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_AUDIT_PRIVATE_KEY") {
		t.Fatalf("missing audit key in prod should be rejected, got %v", err)
	}
}

func TestLoad_AuditKeyMustBeExactRawEd25519Seed(t *testing.T) {
	for _, value := range []string{
		"not-base64",
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 31))),
		base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 33))),
	} {
		setAllRequired(t)
		t.Setenv("HASH_AUDIT_PRIVATE_KEY", value)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_AUDIT_PRIVATE_KEY") {
			t.Fatalf("runtime-invalid audit seed was accepted: %v", err)
		}
	}
}

func TestLoad_ProdHappyPath(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	if _, err := Load(); err != nil {
		t.Fatalf("valid prod config should boot, got %v", err)
	}
}
