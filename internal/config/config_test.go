package config

import (
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

func TestLoad_OK(t *testing.T) {
	setAllRequired(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Port == 0 {
		t.Error("port not defaulted")
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("X", "true")
	if !envBool("X", false) {
		t.Error("'true' parsed as false")
	}
	t.Setenv("X", "false")
	if envBool("X", true) {
		t.Error("'false' parsed as true")
	}
	t.Setenv("X", "")
	if !envBool("X", true) {
		t.Error("empty did not return fallback")
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("X", "42")
	if envInt("X", 0) != 42 {
		t.Error("int parse failed")
	}
	t.Setenv("X", "abc")
	if envInt("X", 7) != 7 {
		t.Error("non-int did not return fallback")
	}
}

func TestIsLocalDevelopment(t *testing.T) {
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

func TestLoad_BrightCRMSecretRequiredInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_BRIGHTCRM_URL", "https://crm.example.com")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "BRIGHTCRM_WEBHOOK_SECRET") {
		t.Fatalf("expected BrightCRM secret guard, got %v", err)
	}
}

func TestLoad_BrightCRMSecretOptionalLocally(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_BRIGHTCRM_URL", "https://crm.example.com")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	if _, err := Load(); err != nil {
		t.Fatalf("local dev should tolerate missing secret: %v", err)
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

func TestIsEUEndpoint(t *testing.T) {
	cases := map[string]bool{
		"api.mistral.ai":               true,
		"chat.api.mistral.ai":          true,
		"eu.anthropic.com":             true,
		"eu.openrouter.ai":             true,
		"eu.api.openrouter.ai":         true,
		"llm.eu.brightinteraction.com": true,
		"sovereign-llm.eu":             true,
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
	extra := []string{"llm.example.com", "llama.tailscale.local"}
	if !IsEUEndpoint("llm.example.com", extra) {
		t.Error("FQDN allowlist match failed")
	}
	if !IsEUEndpoint("v2.llm.example.com", extra) {
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

func TestLoad_AIAcceptsAllowlistOverrideInProd(t *testing.T) {
	setAllRequired(t)
	long := strings.Repeat("a", 64)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AI_SHIELD_KEY", long)
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-mistral")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://llm.example.com/v1/chat/completions")
	t.Setenv("HASH_AI_EU_HOSTS_ALLOWLIST", "brightinteraction.com")
	if _, err := Load(); err != nil {
		t.Fatalf("allowlist override should pass, got %v", err)
	}
}

func TestLoad_AISkipsGateInLocalDev(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "http://localhost:8090")
	t.Setenv("HASH_AI_SHIELD_KEY", "")
	t.Setenv("HASH_MISTRAL_API_KEY", "sk-test")
	t.Setenv("HASH_MISTRAL_BASE_URL", "https://openrouter.ai/api/v1/chat/completions")
	if _, err := Load(); err != nil {
		t.Fatalf("local dev should skip AI gate, got %v", err)
	}
}

func TestLoad_SESOnlyBootsOnPublicURLWithoutQESorBilling(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	// SES-only B2B deployment: no QES provider, no billing provider.
	t.Setenv("HASH_QES_PROVIDER", "")
	t.Setenv("HASH_QES_IDURA_API_KEY", "")
	t.Setenv("HASH_QES_TRUST_LIST_PATH", "")
	t.Setenv("HASH_BILLING_PROVIDER", "")
	t.Setenv("HASH_MOLLIE_API_KEY", "")
	t.Setenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET", "")
	if _, err := Load(); err != nil {
		t.Fatalf("SES-only prod deployment should boot without QES or billing, got %v", err)
	}
}

func setAllRequired(t *testing.T) {
	t.Helper()
	// 64 chars of non-uniform content: passes the >=32 length check AND the
	// all-identical-character weak-key rejection.
	key := strings.Repeat("ab", 32)
	t.Setenv("HASH_PUBLIC_URL", "http://localhost")
	t.Setenv("HASH_DB_URL", "postgres://x")
	t.Setenv("HASH_S3_ENDPOINT", "minio:9000")
	t.Setenv("HASH_S3_ACCESS_KEY", "k")
	t.Setenv("HASH_S3_SECRET_KEY", "s")
	t.Setenv("HASH_OIDC_ISSUER", "https://i")
	t.Setenv("HASH_OIDC_CLIENT_ID", "c")
	t.Setenv("HASH_OIDC_CLIENT_SECRET", "cs")
	t.Setenv("HASH_OIDC_REDIRECT_URL", "http://localhost/cb")
	t.Setenv("HASH_SIGNER_TOKEN_KEY", key)
	t.Setenv("HASH_SESSION_KEY", key)
	// Production-only guards: set valid non-mock providers + a stable audit
	// key so prod-URL tests reach the specific guard they exercise instead of
	// tripping the mock/audit guards first. Ignored in local dev (skipped).
	t.Setenv("HASH_QES_PROVIDER", "idura")
	t.Setenv("HASH_QES_IDURA_API_KEY", "idura-test-key")
	t.Setenv("HASH_QES_TRUST_LIST_PATH", "/etc/hash/qes-trust-list.json")
	t.Setenv("HASH_BILLING_PROVIDER", "mollie")
	t.Setenv("HASH_MOLLIE_API_KEY", "mollie-test-key")
	t.Setenv("HASH_MOLLIE_WEBHOOK_PATH_SECRET", "molliepathsecret16")
	t.Setenv("HASH_AUDIT_PRIVATE_KEY", "ZmFrZS1lZDI1NTE5LXNlZWQtZm9yLXRlc3Rz")
}

func TestLoad_RejectsAllZeroKeys(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_SIGNER_TOKEN_KEY", strings.Repeat("0", 64))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SIGNER_TOKEN_KEY") {
		t.Fatalf("all-zero signer key should be rejected, got %v", err)
	}
}

func TestLoad_RejectsMockQESInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_QES_PROVIDER", "mock")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_QES_PROVIDER") {
		t.Fatalf("mock QES in prod should be rejected, got %v", err)
	}
}

func TestLoad_RequiresQESTrustListInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_QES_TRUST_LIST_PATH", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_QES_TRUST_LIST_PATH") {
		t.Fatalf("prod QES without a trust list should be rejected, got %v", err)
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

func TestLoad_AuditKeyRequiredInProd(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	t.Setenv("HASH_AUDIT_PRIVATE_KEY", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HASH_AUDIT_PRIVATE_KEY") {
		t.Fatalf("missing audit key in prod should be rejected, got %v", err)
	}
}

func TestLoad_ProdHappyPath(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_PUBLIC_URL", "https://hash.brightinteraction.com")
	if _, err := Load(); err != nil {
		t.Fatalf("valid prod config should boot, got %v", err)
	}
}
