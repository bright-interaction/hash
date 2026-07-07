package dispatch

import (
	"strings"
	"testing"
)

// Recipient-facing emails render in the recipient locale, keep the dynamic
// values, and differ from English.
func TestRender_LocalizedInvite(t *testing.T) {
	ctx := TemplateContext{
		DocumentName:  "NDA",
		SenderName:    "Jane",
		SenderEmail:   "jane@example.com",
		RecipientName: "Bo",
		OrgName:       "Acme",
		Locale:        "sv",
		SignURL:       "https://esign.example/sign/tok",
	}
	subj, html, text, err := Render(KindInvite, ctx)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(subj, "NDA") {
		t.Errorf("subject dropped document name: %q", subj)
	}
	if !strings.Contains(html, "https://esign.example/sign/tok") {
		t.Errorf("html missing sign URL")
	}
	if !strings.Contains(text, "NDA") {
		t.Errorf("text dropped document name: %q", text)
	}

	enCtx := ctx
	enCtx.Locale = "en"
	enSubj, _, _, _ := Render(KindInvite, enCtx)
	if subj == enSubj {
		t.Errorf("sv subject should differ from en (got %q for both)", subj)
	}
}

// An unknown locale falls back to English without error.
func TestRender_UnknownLocaleFallsBack(t *testing.T) {
	zz := TemplateContext{DocumentName: "NDA", SenderName: "Jane", OrgName: "Acme", Locale: "zz", SignURL: "x"}
	en := zz
	en.Locale = "en"
	zzSubj, _, _, err := Render(KindReminder, zz)
	if err != nil {
		t.Fatal(err)
	}
	enSubj, _, _, _ := Render(KindReminder, en)
	if zzSubj != enSubj {
		t.Errorf("unknown locale should match en: %q vs %q", zzSubj, enSubj)
	}
}

// Sender-facing emails are unaffected by Locale (stay English).
func TestRender_SenderFacingIgnoresLocale(t *testing.T) {
	ctx := TemplateContext{DocumentName: "NDA", SenderName: "Jane", OrgName: "Acme", Locale: "sv"}
	subj, _, _, err := Render(KindCompletedSender, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(subj, "signed by all parties") {
		t.Errorf("sender-facing subject should stay English: %q", subj)
	}
}
