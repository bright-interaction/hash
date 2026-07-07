package handler

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/go-chi/chi/v5/middleware"
)

// panicMiddleware logs a panic with the full stack trace before chi's
// stdlib Recoverer kicks in. Recoverer returns 500 but writes a thin
// log line; for an e-sign legal record we want the stack on disk so a
// follow-up post-mortem isn't flying blind. Wrapped Recoverer still
// emits the 500 so the contract callers expect is unchanged.
func panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					// chi's Recoverer treats ErrAbortHandler as a
					// deliberate disconnect; propagate so it can do
					// the same.
					panic(rec)
				}
				slog.Error("http handler panicked",
					"err", rec,
					"path", r.URL.Path,
					"method", r.Method,
					"request_id", middleware.GetReqID(r.Context()),
					"stack", string(debug.Stack()),
				)
				// Re-panic so chi.middleware.Recoverer (mounted right
				// after this middleware) writes the standard 500 and
				// resets state.
				panic(rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
