package ai

import (
	"context"
	"strings"
	"testing"
)

func newTestShield(t *testing.T) *LocalShield {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*7 + 1)
	}
	sh, err := NewLocalShield(key)
	if err != nil {
		t.Fatalf("NewLocalShield: %v", err)
	}
	return sh.(*LocalShield)
}

func TestShield_TokenizesPersonnummerAndIBAN(t *testing.T) {
	sh := newTestShield(t)
	ctx := context.Background()
	cases := map[string]string{
		"personnummer dashed":  "Anna pnr 850101-1234 signs",
		"personnummer full":    "ID 19850101-1234 here",
		"personnummer compact": "num 8501011234 end",
		"iban spaced":          "pay to SE35 5000 0000 0549 1000 0003 now",
		"iban compact":         "iban DE89370400440532013000 ok",
	}
	for name, in := range cases {
		out, h, err := sh.Tokenize(ctx, in)
		if err != nil {
			t.Fatalf("%s: tokenize: %v", name, err)
		}
		if out == in {
			t.Errorf("%s: nothing tokenised: %q", name, out)
		}
		if !strings.Contains(out, "[shield:") {
			t.Errorf("%s: no shield token in %q", name, out)
		}
		// The original sensitive digits must not survive in the shielded text.
		for _, secret := range []string{"850101-1234", "19850101-1234", "8501011234", "5000 0000 0549", "532013000"} {
			if strings.Contains(in, secret) && strings.Contains(out, secret) {
				t.Errorf("%s: PII %q leaked through shield: %q", name, secret, out)
			}
		}
		// Round-trip restores the plaintext.
		back, err := sh.Untokenize(ctx, out, h)
		if err != nil {
			t.Fatalf("%s: untokenize: %v", name, err)
		}
		if back != in {
			t.Errorf("%s: round-trip mismatch:\n  in:  %q\n  out: %q", name, in, back)
		}
	}
}
