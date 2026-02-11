// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package goplugin

import (
	"context"
	"os/exec"
	"slices"

	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"

	pluginv1 "github.com/sigil-dev/sigil/internal/gen/proto/plugin/v1"
)

const (
	protocolVersion = 1
	magicCookieKey  = "SIGIL_PLUGIN"
	magicCookieVal  = "aGFzaGljb3JwLWdvLXBsdWdpbg==" // "hashicorp-go-plugin" base64
)

func HandshakeConfig() plugin.HandshakeConfig {
	return plugin.HandshakeConfig{
		ProtocolVersion:  protocolVersion,
		MagicCookieKey:   magicCookieKey,
		MagicCookieValue: magicCookieVal,
	}
}

func PluginMap() map[string]plugin.Plugin {
	return map[string]plugin.Plugin{
		"lifecycle": &lifecycleGRPCPlugin{},
		"channel":   &channelGRPCPlugin{},
		"tool":      &toolGRPCPlugin{},
		"provider":  &providerGRPCPlugin{},
	}
}

func ClientConfig(binaryPath string, sandboxCmd []string) *plugin.ClientConfig {
	cmd := buildCommand(binaryPath, sandboxCmd)

	return &plugin.ClientConfig{
		HandshakeConfig:  HandshakeConfig(),
		Plugins:          PluginMap(),
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
	}
}

func buildCommand(binaryPath string, sandboxCmd []string) *exec.Cmd {
	if len(sandboxCmd) == 0 {
		return exec.Command(binaryPath)
	}

	args := append(slices.Clone(sandboxCmd), binaryPath)
	return exec.Command(args[0], args[1:]...)
}

type lifecycleGRPCPlugin struct {
	plugin.NetRPCUnsupportedPlugin
}

func (p *lifecycleGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterPluginLifecycleServer(s, &lifecycleGRPCServer{})
	return nil
}

func (p *lifecycleGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return pluginv1.NewPluginLifecycleClient(c), nil
}

type lifecycleGRPCServer struct {
	pluginv1.UnimplementedPluginLifecycleServer
}

type channelGRPCPlugin struct {
	plugin.NetRPCUnsupportedPlugin
}

func (p *channelGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterChannelServer(s, &channelGRPCServer{})
	return nil
}

func (p *channelGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return pluginv1.NewChannelClient(c), nil
}

type channelGRPCServer struct {
	pluginv1.UnimplementedChannelServer
}

type toolGRPCPlugin struct {
	plugin.NetRPCUnsupportedPlugin
}

func (p *toolGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterToolServer(s, &toolGRPCServer{})
	return nil
}

func (p *toolGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return pluginv1.NewToolClient(c), nil
}

type toolGRPCServer struct {
	pluginv1.UnimplementedToolServer
}

type providerGRPCPlugin struct {
	plugin.NetRPCUnsupportedPlugin
}

func (p *providerGRPCPlugin) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
	pluginv1.RegisterProviderServer(s, &providerGRPCServer{})
	return nil
}

func (p *providerGRPCPlugin) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return pluginv1.NewProviderClient(c), nil
}

type providerGRPCServer struct {
	pluginv1.UnimplementedProviderServer
}
