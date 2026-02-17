// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// parseTrustedProxies parses a list of CIDR strings into net.IPNet values.
// Returns an error if any CIDR is invalid.
func parseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, sigilerr.Errorf(sigilerr.CodeServerConfigInvalid,
				"invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}
	if len(nets) == 0 {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid,
			"trusted_proxies must contain at least one valid CIDR range")
	}
	return nets, nil
}

// isTrustedProxy checks whether the given IP is within any of the trusted CIDR ranges.
func isTrustedProxy(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// trustedProxyRealIP returns middleware that rewrites r.RemoteAddr from
// X-Forwarded-For only when the direct connecting IP is in the trusted
// proxy list. If the connecting IP is not trusted, the header is ignored
// and the original RemoteAddr is preserved to prevent IP spoofing.
func trustedProxyRealIP(trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract direct connecting IP from RemoteAddr
			connectingIP, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				// RemoteAddr may not have a port
				connectingIP = r.RemoteAddr
			}

			ip := net.ParseIP(connectingIP)
			if ip == nil {
				// Cannot parse connecting IP; do not trust forwarded headers
				slog.Warn("could not parse connecting IP, ignoring proxy headers",
					"remote_addr", r.RemoteAddr)
				next.ServeHTTP(w, r)
				return
			}

			if !isTrustedProxy(ip, trusted) {
				// Connecting IP is not a trusted proxy; ignore X-Forwarded-For
				slog.Debug("request from untrusted proxy, ignoring X-Forwarded-For",
					"connecting_ip", connectingIP)
				next.ServeHTTP(w, r)
				return
			}

			// Trusted proxy: use the leftmost (client) IP from X-Forwarded-For
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				// X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
				// The leftmost IP is the original client
				parts := strings.Split(xff, ",")
				clientIP := strings.TrimSpace(parts[0])
				if parsedIP := net.ParseIP(clientIP); parsedIP != nil {
					r.RemoteAddr = clientIP + ":0"
				} else {
					slog.Warn("invalid IP in X-Forwarded-For, using connecting IP",
						"xff_value", clientIP,
						"connecting_ip", connectingIP)
				}
			} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
				// Fall back to X-Real-IP if present
				if parsedIP := net.ParseIP(strings.TrimSpace(xri)); parsedIP != nil {
					r.RemoteAddr = strings.TrimSpace(xri) + ":0"
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
