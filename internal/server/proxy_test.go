// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTrustedProxies_Valid(t *testing.T) {
	nets, err := parseTrustedProxies([]string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.1.0/24",
	})
	require.NoError(t, err)
	assert.Len(t, nets, 3)
}

func TestParseTrustedProxies_SkipsEmpty(t *testing.T) {
	nets, err := parseTrustedProxies([]string{
		"10.0.0.0/8",
		"  ",
		"",
		"192.168.1.0/24",
	})
	require.NoError(t, err)
	assert.Len(t, nets, 2)
}

func TestParseTrustedProxies_InvalidCIDR(t *testing.T) {
	_, err := parseTrustedProxies([]string{"not-a-cidr"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid trusted proxy CIDR")
}

func TestParseTrustedProxies_AllEmpty(t *testing.T) {
	_, err := parseTrustedProxies([]string{"", "  "})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one valid CIDR")
}

func TestParseTrustedProxies_IPv6(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"fd00::/8", "10.0.0.0/8"})
	require.NoError(t, err)
	assert.Len(t, nets, 2)
}

func TestIsTrustedProxy(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8", "192.168.0.0/16"})
	require.NoError(t, err)

	tests := []struct {
		name    string
		ip      string
		trusted bool
	}{
		{"in 10.0.0.0/8", "10.1.2.3", true},
		{"in 192.168.0.0/16", "192.168.1.1", true},
		{"outside both ranges", "172.16.0.1", false},
		{"public IP", "8.8.8.8", false},
		{"loopback", "127.0.0.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			require.NotNil(t, ip)
			assert.Equal(t, tt.trusted, isTrustedProxy(ip, nets))
		})
	}
}

func TestTrustedProxyRealIP_TrustedProxy_UsesXFF(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var capturedAddr string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedAddr = r.RemoteAddr
	})

	mw := trustedProxyRealIP(nets)
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.1")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Should use the leftmost XFF IP (the real client)
	assert.Equal(t, "203.0.113.50:0", capturedAddr)
}

func TestTrustedProxyRealIP_UntrustedProxy_IgnoresXFF(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var capturedAddr string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedAddr = r.RemoteAddr
	})

	mw := trustedProxyRealIP(nets)
	wrapped := mw(handler)

	// Attacker at 203.0.113.99 sends spoofed X-Forwarded-For
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "203.0.113.99:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Should preserve original RemoteAddr since connecting IP is untrusted
	assert.Equal(t, "203.0.113.99:54321", capturedAddr)
}

func TestTrustedProxyRealIP_TrustedProxy_NoXFF_Passthrough(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var capturedAddr string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedAddr = r.RemoteAddr
	})

	mw := trustedProxyRealIP(nets)
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	// No X-Forwarded-For header
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Should keep original RemoteAddr when no XFF header present
	assert.Equal(t, "10.0.0.1:12345", capturedAddr)
}

func TestTrustedProxyRealIP_TrustedProxy_XRealIP_Fallback(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var capturedAddr string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedAddr = r.RemoteAddr
	})

	mw := trustedProxyRealIP(nets)
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-IP", "203.0.113.50")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Should fall back to X-Real-IP when no X-Forwarded-For present
	assert.Equal(t, "203.0.113.50:0", capturedAddr)
}

func TestTrustedProxyRealIP_TrustedProxy_InvalidXFF_KeepsConnectingIP(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var capturedAddr string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedAddr = r.RemoteAddr
	})

	mw := trustedProxyRealIP(nets)
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Invalid XFF should leave RemoteAddr unchanged
	assert.Equal(t, "10.0.0.1:12345", capturedAddr)
}

func TestTrustedProxyRealIP_UnparsableRemoteAddr(t *testing.T) {
	nets, err := parseTrustedProxies([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	var capturedAddr string
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		capturedAddr = r.RemoteAddr
	})

	mw := trustedProxyRealIP(nets)
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "not-a-valid-ip"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	// Should pass through with original RemoteAddr if IP is not parseable
	assert.Equal(t, "not-a-valid-ip", capturedAddr)
}
