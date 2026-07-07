// Package i18n provides backend localization for signer-facing strings: the
// GDPR Article 13 privacy notice, signer-document chrome, and the recipient
// lifecycle emails. Translations live in messages_gen.go (generated from the
// i18n translation workflow); English is the per-key fallback. The key set
// mirrors the frontend $lib/i18n layer so the signer sees one consistent
// language across the email, the page, and the notice.
package i18n

import "strings"

const fallback = "en"

// Normalize maps an empty/unknown locale to the English fallback so callers can
// pass a recipient locale straight through.
func Normalize(locale string) string {
	if locale == "" || !Has(locale) {
		return fallback
	}
	return locale
}

// T returns the localized string for key in locale, falling back to English per
// key (then to the key itself if even English is missing). {placeholder} tokens
// are substituted from params.
func T(locale, key string, params map[string]string) string {
	s := lookup(locale, key)
	if s == "" {
		s = lookup(fallback, key)
	}
	if s == "" {
		s = key
	}
	for k, v := range params {
		s = strings.ReplaceAll(s, "{"+k+"}", v)
	}
	return s
}

func lookup(locale, key string) string {
	if m, ok := messages[locale]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return ""
}

// Has reports whether a locale has a message map.
func Has(locale string) bool {
	_, ok := messages[locale]
	return ok
}
