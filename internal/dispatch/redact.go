package dispatch

import (
	"regexp"
	"strings"
)

var reEmail = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// MaskEmail reduces a recipient address to a non-identifying diagnostic form:
// the first local-part character plus the full domain (a***@example.com). The
// domain is retained because "which domain / why did it bounce" is the useful
// signal in a delivery-failure log, while the data subject's address is not
// shipped. Empty / non-address input returns "[redacted]".
func MaskEmail(addr string) string {
	addr = strings.TrimSpace(addr)
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		if addr == "" {
			return "[redacted]"
		}
		return "***"
	}
	local, domain := addr[:at], addr[at+1:]
	return local[:1] + "***@" + domain
}

// ScrubEmails masks every email address embedded in a free-text string (e.g. an
// SMTP rejection that echoes the recipient). Used on error strings before they
// reach a log record that may egress to the shared observability store.
func ScrubEmails(s string) string {
	return reEmail.ReplaceAllStringFunc(s, MaskEmail)
}
