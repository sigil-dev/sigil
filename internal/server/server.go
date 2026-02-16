// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

// Config holds HTTP server configuration.
type Config struct {
	ListenAddr     string
	CORSOrigins    []string
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	TokenValidator TokenValidator // nil = auth disabled (dev mode)
	EnableHSTS     bool
	RateLimit      RateLimitConfig // per-IP rate limiting
	BehindProxy    bool            // true if behind a reverse proxy (enables RealIP middleware)
	TrustedProxies []string        // CIDR ranges of trusted proxies (required when BehindProxy=true)
	StreamHandler  StreamHandler   // nil = SSE routes return 503 until handler is set
	Services       *Services       // nil = service-dependent routes fail closed
}

// Server wraps a chi router with huma API and HTTP server.
type Server struct {
	router        chi.Router
	api           huma.API
	cfg           Config
	streamHandler StreamHandler
	services      *Services
	rateLimitDone chan struct{}
	closeOnce     sync.Once
}

// New creates a Server with chi router, huma API, health endpoint, and CORS.
// StreamHandler and Services can be nil and set later, but routes requiring them will fail closed.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid, "listen address is required")
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 60 * time.Second
	}

	// Validate rate limit config (applies defaults as a side effect)
	if err := (&cfg.RateLimit).Validate(); err != nil {
		return nil, err
	}

	// Reject CORS wildcard with credentials — reflects any Origin, enabling cross-origin credential theft.
	for _, origin := range cfg.CORSOrigins {
		if origin == "*" {
			return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid,
				`CORS origin "*" cannot be used with credentials; specify explicit origins`)
		}
	}

	// Parse and validate trusted proxy CIDRs when behind a proxy
	var trustedNets []*net.IPNet
	if cfg.BehindProxy {
		if len(cfg.TrustedProxies) == 0 {
			return nil, sigilerr.New(sigilerr.CodeServerConfigInvalid,
				"trusted_proxies must be configured when behind_proxy is true")
		}
		var err error
		trustedNets, err = parseTrustedProxies(cfg.TrustedProxies)
		if err != nil {
			return nil, err
		}
	}

	rateLimitDone := make(chan struct{})

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Recoverer)
	// Only trust proxy headers when connecting IP is from a trusted proxy
	if cfg.BehindProxy {
		r.Use(trustedProxyRealIP(trustedNets))
	}
	r.Use(securityHeadersMiddleware(cfg.EnableHSTS))
	r.Use(corsMiddleware(cfg.CORSOrigins))
	r.Use(rateLimitMiddleware(cfg.RateLimit, rateLimitDone))
	r.Use(authMiddleware(cfg.TokenValidator))

	// Huma API with OpenAPI spec
	humaConfig := huma.DefaultConfig("Sigil Gateway", "0.1.0")
	humaConfig.Info.Description = "Secure AI agent gateway API"
	api := humachi.New(r, humaConfig)

	// Health endpoint
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Health check",
		Tags:        []string{"system"},
	}, func(_ context.Context, _ *struct{}) (*HealthResponse, error) {
		return &HealthResponse{Body: HealthBody{Status: "ok"}}, nil
	})

	srv := &Server{
		router:        r,
		api:           api,
		cfg:           cfg,
		streamHandler: cfg.StreamHandler,
		services:      cfg.Services,
		rateLimitDone: rateLimitDone,
	}

	// Register SSE route (returns 503 if no StreamHandler).
	srv.registerSSERoute()

	// Register REST routes if Services provided.
	if cfg.Services != nil {
		srv.registerRoutes()
	}

	return srv, nil
}

// authDisabled reports whether token-based authentication is disabled (dev mode).
func (s *Server) authDisabled() bool {
	return s.cfg.TokenValidator == nil
}

// Handler returns the underlying http.Handler for testing.
func (s *Server) Handler() http.Handler {
	return s.router
}

// API returns the huma API for registering additional operations.
func (s *Server) API() huma.API {
	return s.api
}

// Close signals cleanup goroutines to exit (e.g., rate limiter cleanup).
// Safe to call multiple times. Users of Handler() without Start() MUST call Close() to prevent goroutine leaks.
// Note: This does not stop the HTTP server if Start() is running - use context cancellation for that.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		close(s.rateLimitDone)
		// Note: We cannot stop httpServer here because it's only created in Start()
		// and stopping it requires the shutdown context. Callers should use ctx
		// cancellation to stop Start()'s HTTP server gracefully.
	})
	return nil
}

// Start runs the HTTP server and blocks until the context is cancelled,
// then performs graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeServerStartFailure, "listening on %s: %w", s.cfg.ListenAddr, err)
	}

	srv := &http.Server{
		Handler:           s.router,
		ReadTimeout:       s.cfg.ReadTimeout,
		WriteTimeout:      s.cfg.WriteTimeout,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return sigilerr.Errorf(sigilerr.CodeServerShutdownFailure, "shutting down: %w", err)
	}

	// Signal rate limiter cleanup goroutine to exit
	_ = s.Close()

	return <-errCh
}

// HealthBody is the JSON body of the health endpoint response.
type HealthBody struct {
	Status string `json:"status" example:"ok" doc:"Health status"`
}

// HealthResponse wraps the health check response.
type HealthResponse struct {
	Body HealthBody
}

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	if len(origins) == 0 {
		slog.Warn("no CORS origins configured — all cross-origin requests will be rejected")
		// go-chi/cors treats empty AllowedOrigins as wildcard, so we return a
		// no-op middleware that does not add any CORS headers.
		return func(next http.Handler) http.Handler { return next }
	}

	return cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	})
}

// securityHeadersMiddleware adds standard security headers to all responses.
func securityHeadersMiddleware(enableHSTS bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-XSS-Protection", "0")
			// CSP nonce support requires per-request nonce generation and template integration.
			// Currently using 'unsafe-inline' for styles until nonce infrastructure is implemented.
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
			if enableHSTS {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
