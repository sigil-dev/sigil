// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
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
	TokenValidator TokenValidator  // nil = auth disabled (dev mode)
	EnableHSTS     bool
	RateLimit      RateLimitConfig // per-IP rate limiting
}

// Server wraps a chi router with huma API and HTTP server.
type Server struct {
	router         chi.Router
	api            huma.API
	cfg            Config
	streamHandler  StreamHandler
	services       *Services
	rateLimitDone  chan struct{}
}

// New creates a Server with chi router, huma API, health endpoint, and CORS.
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

	// Validate rate limit config
	if err := cfg.RateLimit.Validate(); err != nil {
		return nil, err
	}

	rateLimitDone := make(chan struct{})

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(securityHeadersMiddleware(cfg.EnableHSTS))
	r.Use(corsMiddleware(cfg.CORSOrigins))
	r.Use(authMiddleware(cfg.TokenValidator))
	r.Use(rateLimitMiddleware(cfg.RateLimit, rateLimitDone))

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
		rateLimitDone: rateLimitDone,
	}

	// Register SSE route (returns 503 until a StreamHandler is set).
	srv.registerSSERoute()

	return srv, nil
}

// Handler returns the underlying http.Handler for testing.
func (s *Server) Handler() http.Handler {
	return s.router
}

// API returns the huma API for registering additional operations.
func (s *Server) API() huma.API {
	return s.api
}

// Start runs the HTTP server and blocks until the context is cancelled,
// then performs graceful shutdown.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeServerStartFailure, "listening on %s: %w", s.cfg.ListenAddr, err)
	}

	srv := &http.Server{
		Handler:      s.router,
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: s.cfg.WriteTimeout,
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
	close(s.rateLimitDone)

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
		slog.Warn("no CORS origins configured, defaulting to http://localhost:5173 (development only)")
		origins = []string{"http://localhost:5173"}
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
			if enableHSTS {
				w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}
