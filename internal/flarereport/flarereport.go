// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// credentialPathPatterns match credentials/high-cardinality authentication
// handles carried in URL paths so they can be redacted before an event leaves
// the process. Query strings are removed wholesale below.
var credentialPathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(/sign/)[^/?#]+`),
	regexp.MustCompile(`(/e/o/)[^/?#]+`),
	regexp.MustCompile(`(/webhooks/billing/)[^/?#]+`),
	regexp.MustCompile(`(/qes/callback/)[^/?#]+`),
}

func redactCredentialPath(raw string) string {
	for _, pattern := range credentialPathPatterns {
		raw = pattern.ReplaceAllString(raw, "${1}[redacted]")
	}
	return raw
}

// scrubSensitive removes request material that must never leave Hash. The SDK
// buffers up to 10 KiB of request bodies independently of SendDefaultPII; that
// can contain contract text, comments, typed names, identity data, API-key
// creation inputs, or webhook payloads. Non-sensitive headers can still carry
// customer-specific metadata and forwarding IPs, so retain only the redacted
// method/URL needed to diagnose a failing route. Applied to errors and traces.
func scrubSensitive(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event != nil && event.Request != nil {
		event.Request.QueryString = ""
		event.Request.URL = redactCredentialPath(event.Request.URL)
		event.Request.Data = ""
		event.Request.Cookies = ""
		event.Request.Headers = nil
		event.Request.Env = nil
	}
	return event
}

// InitFlare wires error reporting to the house Flare instance (Sentry-wire
// protocol) when FLARE_DSN is set in the environment. release and environment
// identify the exact deployed artifact and tier in every event. The DSN is
// injected by the deploy pipeline's flare-provision step; without it this is a
// no-op so dev runs and self-hosts boot unchanged.
func InitFlare(service, release, environment string) bool {
	dsn := os.Getenv("FLARE_DSN")
	if dsn == "" {
		return false
	}
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              dsn,
		Release:          release,
		Environment:      environment,
		ServerName:       service,
		EnableTracing:    true,
		TracesSampleRate: tracesSampleRate(),
		BeforeSend:       scrubSensitive,
		// Transaction envelopes route through a SEPARATE hook. Registering only
		// BeforeSend left every traced request unscrubbed, which is the
		// higher-volume half of the traffic on an HTTP service.
		BeforeSendTransaction: scrubSensitive,
	})
	if err != nil {
		slog.Warn("flare: error reporting disabled (sentry init failed)", "error", err)
		return false
	}
	slog.Info("flare: error reporting enabled", "service", service, "release", release, "environment", environment)
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

// CaptureWorkerFatal emits a deliberately data-free fatal signal and waits for
// the Sentry transport before a worker supervisor terminates the process. The
// native slog shipper is asynchronous, so a log followed by os.Exit cannot be
// relied on to leave the process. Never accept the recovered panic value here:
// panic payloads can contain contract data or credentials.
func CaptureWorkerFatal(loop string, panicked bool) {
	failure := "unexpected_return"
	if panicked {
		failure = "panic"
	}
	hub := sentry.CurrentHub().Clone()
	hub.WithScope(func(scope *sentry.Scope) {
		scope.SetLevel(sentry.LevelFatal)
		scope.SetTag("worker_loop", loop)
		scope.SetTag("worker_failure", failure)
		scope.SetFingerprint([]string{"hash-worker-fatal", loop, failure})
		hub.CaptureMessage("critical Hash worker loop stopped")
	})
	// No configured client returns immediately. A configured asynchronous
	// transport gets a bounded chance to deliver before os.Exit skips defers.
	hub.Flush(2 * time.Second)
}
