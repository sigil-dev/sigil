// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// Config holds HTTP server configuration.
type Config struct {
	ListenAddr   string
	CORSOrigins  []string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Server wraps a chi router with huma API and HTTP server.
type Server struct {
	router        chi.Router
	api           huma.API
	cfg           Config
	streamHandler StreamHandler
}

// New creates a Server with chi router, huma API, health endpoint, and CORS.
func New(cfg Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 30 * time.Second
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 60 * time.Second
	}

	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(corsMiddleware(cfg.CORSOrigins))

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
		router: r,
		api:    api,
		cfg:    cfg,
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
		return fmt.Errorf("listening on %s: %w", s.cfg.ListenAddr, err)
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
		return fmt.Errorf("shutting down: %w", err)
	}

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
