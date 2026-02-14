// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"log/slog"
	"net/http"
)

// authMiddleware is a stub authentication/ABAC middleware.
// It logs incoming requests and passes them through. Full auth enforcement
// (token validation, capability checks) will be implemented as part of the
// security phase — see sigil-9s6.
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("auth stub: passing request through",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		next.ServeHTTP(w, r)
	})
}
