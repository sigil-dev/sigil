// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/sigil-dev/sigil/internal/channel/telegram"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
)

const keyringService = "sigil"

// ProviderKeyValidator validates an API key for a given provider.
type ProviderKeyValidator func(ctx context.Context, providerName provider.ProviderName, key string) error

// ChannelTokenValidator validates a bot token for a channel type.
type ChannelTokenValidator func(ctx context.Context, channelType, token string) error

// ConfigDeps holds dependencies for configuration endpoints.
// Separated from Services because config endpoints need secret storage
// and validation functions, not the standard store services.
type ConfigDeps struct {
	Secrets          secrets.Store
	ValidateProvider ProviderKeyValidator
	ValidateChannel  ChannelTokenValidator
}

// DefaultProviderKeyValidator returns a ProviderKeyValidator that uses the real provider API.
func DefaultProviderKeyValidator(client *http.Client) ProviderKeyValidator {
	return func(ctx context.Context, providerName provider.ProviderName, key string) error {
		return provider.ValidateKey(ctx, client, providerName, key)
	}
}

// DefaultChannelTokenValidator returns a ChannelTokenValidator that uses the real channel API.
func DefaultChannelTokenValidator(client *http.Client) ChannelTokenValidator {
	return func(ctx context.Context, channelType, token string) error {
		switch channelType {
		case "telegram":
			return telegram.ValidateToken(ctx, client, token)
		default:
			return sigilerr.Errorf(sigilerr.CodeChannelTokenInvalid, "unsupported channel type: %s", channelType)
		}
	}
}

// --- Request/Response types ---

type configureProviderInput struct {
	Body struct {
		Type   string `json:"type" doc:"Provider type" enum:"anthropic,openai,google,openrouter" required:"true"`
		APIKey string `json:"api_key" doc:"Provider API key" minLength:"1" required:"true"`
	}
}

type configureProviderOutput struct {
	Body struct {
		Status   string `json:"status" doc:"Result status" example:"ok"`
		Provider string `json:"provider" doc:"Configured provider type"`
	}
}

type configureChannelInput struct {
	Body struct {
		Type     string `json:"type" doc:"Channel type" enum:"telegram" required:"true"`
		BotToken string `json:"bot_token" doc:"Channel bot token" minLength:"1" required:"true"`
	}
}

type configureChannelOutput struct {
	Body struct {
		Status  string `json:"status" doc:"Result status" example:"ok"`
		Channel string `json:"channel" doc:"Configured channel type"`
	}
}

// registerConfigRoutes registers onboarding configuration endpoints.
// These are separated from registerRoutes because they depend on ConfigDeps
// rather than Services.
func (s *Server) registerConfigRoutes() {
	huma.Register(s.api, huma.Operation{
		OperationID: "configure-provider",
		Method:      http.MethodPost,
		Path:        "/api/v1/config/providers",
		Summary:     "Configure a provider API key",
		Tags:        []string{"config"},
		Errors:      []int{http.StatusBadRequest, http.StatusBadGateway, http.StatusServiceUnavailable},
	}, s.handleConfigureProvider)

	huma.Register(s.api, huma.Operation{
		OperationID: "configure-channel",
		Method:      http.MethodPost,
		Path:        "/api/v1/config/channels",
		Summary:     "Configure a channel bot token",
		Tags:        []string{"config"},
		Errors:      []int{http.StatusBadRequest, http.StatusBadGateway, http.StatusServiceUnavailable},
	}, s.handleConfigureChannel)
}

func (s *Server) handleConfigureProvider(ctx context.Context, input *configureProviderInput) (*configureProviderOutput, error) {
	if s.configDeps == nil {
		slog.Error("config endpoints called but ConfigDeps not configured")
		return nil, huma.Error503ServiceUnavailable("configuration service not available")
	}

	providerName := provider.ProviderName(input.Body.Type)

	if err := s.configDeps.ValidateProvider(ctx, providerName, input.Body.APIKey); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeProviderKeyInvalid) {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid %s API key", input.Body.Type))
		}
		slog.Error("provider key validation failed",
			"provider", input.Body.Type,
			"error", err,
		)
		return nil, huma.Error502BadGateway(fmt.Sprintf("could not validate %s API key", input.Body.Type))
	}

	// Store key in keyring: keyring://sigil/<type>-api-key
	keyName := input.Body.Type + "-api-key"
	if err := s.configDeps.Secrets.Store(keyringService, keyName, input.Body.APIKey); err != nil {
		slog.Error("failed to store provider key in keyring",
			"provider", input.Body.Type,
			"error", err,
		)
		return nil, huma.Error500InternalServerError("failed to store API key")
	}

	slog.Info("provider API key configured", "provider", input.Body.Type)

	out := &configureProviderOutput{}
	out.Body.Status = "ok"
	out.Body.Provider = input.Body.Type
	return out, nil
}

func (s *Server) handleConfigureChannel(ctx context.Context, input *configureChannelInput) (*configureChannelOutput, error) {
	if s.configDeps == nil {
		slog.Error("config endpoints called but ConfigDeps not configured")
		return nil, huma.Error503ServiceUnavailable("configuration service not available")
	}

	if err := s.configDeps.ValidateChannel(ctx, input.Body.Type, input.Body.BotToken); err != nil {
		if sigilerr.HasCode(err, sigilerr.CodeChannelTokenInvalid) {
			return nil, huma.Error400BadRequest(fmt.Sprintf("invalid %s bot token", input.Body.Type))
		}
		slog.Error("channel token validation failed",
			"channel", input.Body.Type,
			"error", err,
		)
		return nil, huma.Error502BadGateway(fmt.Sprintf("could not validate %s bot token", input.Body.Type))
	}

	// Store token in keyring: keyring://sigil/<type>-bot-token
	keyName := input.Body.Type + "-bot-token"
	if err := s.configDeps.Secrets.Store(keyringService, keyName, input.Body.BotToken); err != nil {
		slog.Error("failed to store channel token in keyring",
			"channel", input.Body.Type,
			"error", err,
		)
		return nil, huma.Error500InternalServerError("failed to store bot token")
	}

	slog.Info("channel bot token configured", "channel", input.Body.Type)

	out := &configureChannelOutput{}
	out.Body.Status = "ok"
	out.Body.Channel = input.Body.Type
	return out, nil
}
