package flarereport

import (
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// signTokenPath matches the signer magic token in the request path
// (/sign/<token>/...) so it can be redacted before an event leaves the process.
var signTokenPath = regexp.MustCompile(`(/sign/)[^/?#]+`)

// scrubSensitive strips credentials that ride in the request line: the signer
// magic token (/sign/<token>/...) and the one-click action token (?t=<token> on
// /a/cr, /a/comment). sentry-go serialises URL path + query regardless of
// SendDefaultPII, so without this a Flare viewer could lift a still-valid token
// off a panic event and replay a signing link. Applied to every event via
// BeforeSend so it covers panics and CaptureException alike.
func scrubSensitive(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event != nil && event.Request != nil {
		event.Request.QueryString = ""
		event.Request.URL = signTokenPath.ReplaceAllString(event.Request.URL, "${1}[redacted]")
	}
	return event
}

// InitFlare wires error reporting to the house Flare instance (Sentry-wire
// protocol) when FLARE_DSN is set in the environment. The DSN is injected by
// the CI flare-provision deploy step; without it this is a no-op so
// dev runs and self-hosts boot unchanged.
func InitFlare(service, release string) bool {
	dsn := os.Getenv("FLARE_DSN")
	if dsn == "" {
		return false
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		ServerName:       service,
		EnableTracing:    true,
		TracesSampleRate: tracesSampleRate(),
		BeforeSend:       scrubSensitive,
	})
	if err != nil {
		slog.Warn("flare: error reporting disabled (sentry init failed)", "error", err)
		return false
	}
	slog.Info("flare: error reporting enabled", "service", service)
	startHeartbeat(service)
	installLogShipper(service)
	return true
}

// FlareRecoverer captures panics to Flare and re-panics so the existing
// recovery middleware (chi Recoverer) still renders the 500. Mount it AFTER
// Recoverer in the chain so it sees the panic first. Safe to mount when
// InitFlare was a no-op: capture calls on an uninitialized hub do nothing.
func FlareRecoverer(next http.Handler) http.Handler {
	traced := flareTracer(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				hub := sentry.CurrentHub().Clone()
				hub.Scope().SetRequest(r)
				hub.RecoverWithContext(r.Context(), rec)
				hub.Flush(2 * time.Second)
				panic(rec)
			}
		}()
		traced.ServeHTTP(w, r)
	})
}

// CaptureErr reports a non-panic error to Flare. No-op when reporting is
// disabled. Use for errors that are handled but should page someone.
func CaptureErr(err error) {
	if err == nil {
		return
	}
	sentry.CaptureException(err)
}
