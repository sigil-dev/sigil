// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/sigil-dev/sigil/internal/channel/telegram"
	"github.com/sigil-dev/sigil/internal/provider"
	"github.com/sigil-dev/sigil/internal/secrets"
	sigilerr "github.com/sigil-dev/sigil/pkg/errors"
	"github.com/spf13/cobra"
)

// initHTTPClient is the HTTP client used for provider/channel validation.
// Exposed as a variable so tests can replace it.
var initHTTPClient = &http.Client{Timeout: 10 * time.Second}

// ProviderType aliases provider.ProviderName for use in the init wizard.
type ProviderType = provider.ProviderName

const (
	ProviderAnthropic  = provider.ProviderAnthropic
	ProviderOpenAI     = provider.ProviderOpenAI
	ProviderGoogle     = provider.ProviderGoogle
	ProviderOpenRouter = provider.ProviderOpenRouter
)

// ChannelType represents a supported messaging channel.
type ChannelType string

const (
	ChannelTelegram ChannelType = "telegram"
)

// initWizardStep tracks which step of the wizard is active.
type initWizardStep int

const (
	stepProvider     initWizardStep = iota // select provider
	stepAPIKey                             // enter API key
	stepValidateKey                        // validating key (spinner)
	stepChannel                            // select channel
	stepChannelToken                       // enter bot token
	stepValidateChan                       // validating channel (spinner)
	stepDone                               // wizard complete
	stepError                              // terminal error
)

// initResult holds the collected wizard configuration.
type initResult struct {
	Provider     ProviderType
	APIKey       string
	Channel      ChannelType
	ChannelToken string
}

// --- bubbletea messages ---

type (
	validationSuccessMsg struct{ step initWizardStep }
	validationErrorMsg   struct {
		step initWizardStep
		err  error
	}
)
type configWrittenMsg struct{ path string }

// --- lipgloss styles ---

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("99"))
	promptStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("212"))
	selectedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	successStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	boxStyle      = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("62")).Padding(0, 1)
)

var supportedProviders = []ProviderType{
	ProviderAnthropic,
	ProviderOpenAI,
	ProviderGoogle,
	ProviderOpenRouter,
}

var supportedChannels = []ChannelType{
	ChannelTelegram,
}

// initModel is the bubbletea model for the init wizard.
type initModel struct {
	step           initWizardStep
	providerIdx    int
	channelIdx     int
	apiKeyInput    textinput.Model
	channelInput   textinput.Model
	spinner        spinner.Model
	result         initResult
	validationErr  string
	configPath     string
	secretStore    secrets.Store
	errFinal       error
	skipChannel    bool
	forceOverwrite bool
}

func newInitModel(store secrets.Store) initModel {
	apiKey := textinput.New()
	apiKey.Placeholder = "paste API key here"
	apiKey.EchoMode = textinput.EchoPassword
	apiKey.EchoCharacter = '•'

	chanToken := textinput.New()
	chanToken.Placeholder = "paste bot token here"
	chanToken.EchoMode = textinput.EchoPassword
	chanToken.EchoCharacter = '•'

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return initModel{
		step:         stepProvider,
		providerIdx:  0,
		channelIdx:   0,
		apiKeyInput:  apiKey,
		channelInput: chanToken,
		spinner:      sp,
		secretStore:  store,
	}
}

func (m initModel) Init() tea.Cmd {
	return nil
}

func (m initModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKey(msg)

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case validationSuccessMsg:
		return m.handleValidationSuccess(msg)

	case validationErrorMsg:
		m.validationErr = msg.err.Error()
		switch msg.step {
		case stepValidateKey:
			m.step = stepAPIKey
			m.apiKeyInput.Focus()
		case stepValidateChan:
			m.step = stepChannelToken
			m.channelInput.Focus()
		}
		return m, nil

	case configWrittenMsg:
		m.step = stepDone
		m.configPath = msg.path
		return m, tea.Quit

	case error:
		m.step = stepError
		m.errFinal = msg
		return m, tea.Quit
	}

	return m.updateInputs(msg)
}

func (m initModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.step {
	case stepProvider:
		return m.handleProviderKey(msg)
	case stepAPIKey:
		return m.handleAPIKeyInput(msg)
	case stepChannel:
		return m.handleChannelKey(msg)
	case stepChannelToken:
		return m.handleChannelTokenInput(msg)
	}
	return m, nil
}

func (m initModel) handleProviderKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.providerIdx > 0 {
			m.providerIdx--
		}
	case "down", "j":
		if m.providerIdx < len(supportedProviders)-1 {
			m.providerIdx++
		}
	case "enter":
		m.result.Provider = supportedProviders[m.providerIdx]
		m.step = stepAPIKey
		m.validationErr = ""
		m.apiKeyInput.SetValue("")
		m.apiKeyInput.Focus()
		return m, textinput.Blink
	case "q", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

func (m initModel) handleAPIKeyInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		key := strings.TrimSpace(m.apiKeyInput.Value())
		if key == "" {
			m.validationErr = "API key must not be empty"
			return m, nil
		}
		m.result.APIKey = key
		m.validationErr = ""
		m.step = stepValidateKey
		return m, tea.Batch(
			m.spinner.Tick,
			validateProviderKeyCmd(m.result.Provider, key),
		)
	case "ctrl+c":
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.apiKeyInput, cmd = m.apiKeyInput.Update(msg)
	return m, cmd
}

func (m initModel) handleChannelKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.channelIdx > 0 {
			m.channelIdx--
		}
	case "down", "j":
		if m.channelIdx < len(supportedChannels)-1 {
			m.channelIdx++
		}
	case "enter":
		m.result.Channel = supportedChannels[m.channelIdx]
		m.step = stepChannelToken
		m.validationErr = ""
		m.channelInput.SetValue("")
		m.channelInput.Focus()
		return m, textinput.Blink
	case "s":
		// Skip channel — proceed directly to config write.
		m.result.Channel = ""
		m.result.ChannelToken = ""
		return m, writeConfigCmd(m.result, m.secretStore, m.forceOverwrite)
	case "q", "ctrl+c":
		return m, tea.Quit
	}
	return m, nil
}

func (m initModel) handleChannelTokenInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		token := strings.TrimSpace(m.channelInput.Value())
		if token == "" {
			m.validationErr = "bot token must not be empty"
			return m, nil
		}
		m.result.ChannelToken = token
		m.validationErr = ""
		m.step = stepValidateChan
		return m, tea.Batch(
			m.spinner.Tick,
			validateTelegramTokenCmd(token),
		)
	case "ctrl+c":
		return m, tea.Quit
	}
	var cmd tea.Cmd
	m.channelInput, cmd = m.channelInput.Update(msg)
	return m, cmd
}

func (m initModel) handleValidationSuccess(msg validationSuccessMsg) (tea.Model, tea.Cmd) {
	switch msg.step {
	case stepValidateKey:
		if m.skipChannel {
			// --skip-channel flag or equivalent: go straight to config write.
			m.result.Channel = ""
			m.result.ChannelToken = ""
			return m, writeConfigCmd(m.result, m.secretStore, m.forceOverwrite)
		}
		m.step = stepChannel
	case stepValidateChan:
		return m, writeConfigCmd(m.result, m.secretStore, m.forceOverwrite)
	}
	return m, nil
}

func (m initModel) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.step {
	case stepAPIKey:
		var cmd tea.Cmd
		m.apiKeyInput, cmd = m.apiKeyInput.Update(msg)
		return m, cmd
	case stepChannelToken:
		var cmd tea.Cmd
		m.channelInput, cmd = m.channelInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m initModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("  Sigil Setup Wizard  ") + "\n\n")

	switch m.step {
	case stepProvider:
		b.WriteString(promptStyle.Render("Step 1/2: Add your first LLM provider") + "\n\n")
		for i, p := range supportedProviders {
			if i == m.providerIdx {
				b.WriteString(selectedStyle.Render("  > "+string(p)) + "\n")
			} else {
				b.WriteString(dimStyle.Render("    "+string(p)) + "\n")
			}
		}
		b.WriteString("\n" + dimStyle.Render("↑/↓ to navigate  enter to select  q to quit"))

	case stepAPIKey:
		b.WriteString(promptStyle.Render("Step 1/2: "+string(m.result.Provider)+" API key") + "\n\n")
		b.WriteString(m.apiKeyInput.View() + "\n")
		if m.validationErr != "" {
			b.WriteString("\n" + errorStyle.Render("  "+m.validationErr) + "\n")
		}
		b.WriteString("\n" + dimStyle.Render("enter to continue  ctrl+c to quit"))

	case stepValidateKey:
		b.WriteString(m.spinner.View() + " Validating " + string(m.result.Provider) + " API key…\n")

	case stepChannel:
		b.WriteString(promptStyle.Render("Step 2/2: Add a messaging channel") + "\n\n")
		for i, ch := range supportedChannels {
			if i == m.channelIdx {
				b.WriteString(selectedStyle.Render("  > "+string(ch)) + "\n")
			} else {
				b.WriteString(dimStyle.Render("    "+string(ch)) + "\n")
			}
		}
		b.WriteString("\n" + dimStyle.Render("↑/↓ to navigate  enter to select  s to skip  q to quit"))

	case stepChannelToken:
		b.WriteString(promptStyle.Render("Step 2/2: Telegram bot token") + "\n\n")
		b.WriteString(m.channelInput.View() + "\n")
		if m.validationErr != "" {
			b.WriteString("\n" + errorStyle.Render("  "+m.validationErr) + "\n")
		}
		b.WriteString("\n" + dimStyle.Render("enter to continue  ctrl+c to quit"))

	case stepValidateChan:
		b.WriteString(m.spinner.View() + " Validating Telegram bot token…\n")

	case stepDone:
		b.WriteString(successStyle.Render("  Setup complete!  ") + "\n\n")
		if m.configPath != "" {
			b.WriteString(dimStyle.Render("Config written to: "+m.configPath) + "\n\n")
		}
		b.WriteString("Run " + promptStyle.Render("sigil start") + " and " + promptStyle.Render("sigil chat") + " to get started.\n")
		b.WriteString("Run " + promptStyle.Render("sigil doctor") + " to verify setup.\n")

	case stepError:
		b.WriteString(errorStyle.Render("Setup failed: "+m.errFinal.Error()) + "\n")
	}

	return boxStyle.Render(b.String())
}

// --- tea.Cmd factories ---

func validateProviderKeyCmd(p ProviderType, key string) tea.Cmd {
	return func() tea.Msg {
		if err := provider.ValidateKey(context.Background(), initHTTPClient, p, key); err != nil {
			return validationErrorMsg{step: stepValidateKey, err: err}
		}
		return validationSuccessMsg{step: stepValidateKey}
	}
}

func validateTelegramTokenCmd(token string) tea.Cmd {
	return func() tea.Msg {
		if err := telegram.ValidateToken(context.Background(), initHTTPClient, token); err != nil {
			return validationErrorMsg{step: stepValidateChan, err: err}
		}
		return validationSuccessMsg{step: stepValidateChan}
	}
}

func writeConfigCmd(result initResult, store secrets.Store, forceOverwrite bool) tea.Cmd {
	return func() tea.Msg {
		path, err := storeSecretAndWriteConfig(result, store, forceOverwrite)
		if err != nil {
			return err
		}
		return configWrittenMsg{path: path}
	}
}

// --- Config generation (exported for tests) ---

// GenerateConfigYAML produces a minimal sigil.yaml from the wizard result.
// API keys are referenced via keyring:// URIs; the actual secrets are stored
// separately via storeSecretAndWriteConfig.
func GenerateConfigYAML(result initResult) string {
	providerKey := fmt.Sprintf("keyring://sigil/%s-api-key", result.Provider)

	// Default model per provider.
	defaultModel := defaultModelForProvider(result.Provider)

	var sb strings.Builder
	sb.WriteString("# Sigil configuration — generated by sigil init\n")
	sb.WriteString("# https://github.com/sigil-dev/sigil\n\n")

	sb.WriteString("networking:\n")
	sb.WriteString("  mode: local\n")
	sb.WriteString("  listen: \"127.0.0.1:18789\"\n\n")

	sb.WriteString("storage:\n")
	sb.WriteString("  backend: sqlite\n\n")

	sb.WriteString("providers:\n")
	sb.WriteString(fmt.Sprintf("  %s:\n", result.Provider))
	sb.WriteString(fmt.Sprintf("    api_key: \"%s\"\n\n", providerKey))

	sb.WriteString("models:\n")
	sb.WriteString(fmt.Sprintf("  default: \"%s\"\n", defaultModel))
	sb.WriteString("  failover:\n")
	sb.WriteString(fmt.Sprintf("    - \"%s\"\n", defaultModel))
	sb.WriteString("  budgets:\n")
	sb.WriteString("    per_session_tokens: 100000\n")
	sb.WriteString("    per_hour_usd: 5.00\n")
	sb.WriteString("    per_day_usd: 50.00\n\n")

	sb.WriteString("sessions:\n")
	sb.WriteString("  memory:\n")
	sb.WriteString("    active_window: 20\n")
	sb.WriteString("    compaction:\n")
	sb.WriteString("      strategy: summarize\n")
	sb.WriteString(fmt.Sprintf("      summary_model: \"%s\"\n", defaultModel))
	sb.WriteString("      batch_size: 50\n\n")

	sb.WriteString("workspaces:\n")
	sb.WriteString("  personal:\n")
	sb.WriteString("    description: \"Default personal workspace\"\n")
	sb.WriteString("    members: []\n")

	// Only include channel binding if a channel was configured.
	if result.Channel != "" {
		channelKey := fmt.Sprintf("keyring://sigil/%s-bot-token", result.Channel)
		sb.WriteString("    bindings:\n")
		sb.WriteString(fmt.Sprintf("      - channel: \"%s\"\n", result.Channel))
		sb.WriteString("        channel_id: \"default\"\n")
		sb.WriteString("    tools:\n")
		sb.WriteString("      allow: [\"*\"]\n")
		sb.WriteString("    skills: []\n\n")
		// Channel plugin configuration hint (comment block).
		sb.WriteString("# Channel plugin configuration\n")
		sb.WriteString(fmt.Sprintf("# %s_bot_token: \"%s\"\n", result.Channel, channelKey))
	} else {
		sb.WriteString("    bindings: []\n")
		sb.WriteString("    tools:\n")
		sb.WriteString("      allow: [\"*\"]\n")
		sb.WriteString("    skills: []\n")
	}

	return sb.String()
}

// defaultModelForProvider returns a sensible default model string for a provider.
func defaultModelForProvider(p ProviderType) string {
	switch p {
	case ProviderAnthropic:
		return "anthropic/claude-sonnet-4-5"
	case ProviderOpenAI:
		return "openai/gpt-4o"
	case ProviderGoogle:
		return "google/gemini-2.0-flash"
	case ProviderOpenRouter:
		return "openrouter/anthropic/claude-sonnet-4-5"
	default:
		return string(p) + "/default"
	}
}

// storeSecretAndWriteConfig saves secrets to the OS keyring and writes the
// config YAML to the default config path.
//
// When forceOverwrite is false and the config file already exists, an error is
// returned asking the user to pass --force. When forceOverwrite is true the
// entire config is overwritten (full re-init). A smarter merge that preserves
// non-secret sections is left as a future enhancement.
func storeSecretAndWriteConfig(result initResult, store secrets.Store, forceOverwrite bool) (string, error) {
	// Store provider API key.
	providerKeyName := string(result.Provider) + "-api-key"
	if err := store.Store("sigil", providerKeyName, result.APIKey); err != nil {
		return "", sigilerr.Errorf(sigilerr.CodeSecretStoreFailure, "storing %s API key: %w", result.Provider, err)
	}

	// Store channel token (skip when channel was not configured).
	// NOTE: If config write fails below, secrets already stored in keyring are
	// not rolled back. This is acceptable — orphaned keyring entries are harmless
	// and will be overwritten on a successful re-run.
	if result.ChannelToken != "" {
		chanKeyName := string(result.Channel) + "-bot-token"
		if err := store.Store("sigil", chanKeyName, result.ChannelToken); err != nil {
			return "", sigilerr.Errorf(sigilerr.CodeSecretStoreFailure, "storing %s bot token: %w", result.Channel, err)
		}
	}

	// Write config file.
	cfgPath, err := configPathForWrite()
	if err != nil {
		return "", err
	}

	// Check for existing config unless --force is set.
	if !forceOverwrite {
		if _, statErr := os.Stat(cfgPath); statErr == nil {
			return "", sigilerr.Errorf(sigilerr.CodeConfigAlreadyExists,
				"config file already exists at %s; use --force to overwrite", cfgPath)
		}
	}

	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "creating config directory %s: %w", dir, err)
	}

	yaml := GenerateConfigYAML(result)
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		return "", sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "writing config to %s: %w", cfgPath, err)
	}

	return cfgPath, nil
}

// configPathForWrite returns the default config path, creating the directory
// if needed. Exported as a variable so tests can override it.
var configPathForWrite = defaultConfigPathForWrite

func defaultConfigPathForWrite() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", sigilerr.Errorf(sigilerr.CodeConfigLoadReadFailure, "resolving home directory: %w", err)
	}
	return filepath.Join(home, ".config", "sigil", "sigil.yaml"), nil
}

// --- Cobra command ---

func newInitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactive setup wizard for Sigil",
		Long: `Run an interactive TUI wizard that walks you through:
  1. Adding your first LLM provider (Anthropic, OpenAI, Google, OpenRouter)
  2. Adding a messaging channel (Telegram)

API keys are stored securely in the OS keyring and referenced via
keyring:// URIs in the config file. No secrets are written in plain text.

After completion, run:
  sigil start    — start the gateway
  sigil chat     — start a chat session
  sigil doctor   — verify your setup`,
		RunE: runInit,
	}

	cmd.Flags().Bool("skip-channel", false, "Skip the messaging channel step (web UI only)")
	cmd.Flags().Bool("force", false, "Overwrite existing config file")

	return cmd
}

func runInit(cmd *cobra.Command, _ []string) error {
	// Check if stdin is a terminal — if not, refuse to run interactively.
	f, ok := cmd.InOrStdin().(*os.File)
	if !ok || !isTerminal(f) {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(),
			"sigil init requires an interactive terminal.\n"+
				"To configure Sigil non-interactively, edit ~/.config/sigil/sigil.yaml directly.")
		return sigilerr.New(sigilerr.CodeCLISetupFailure, "sigil init: not an interactive terminal")
	}

	skipChannel, _ := cmd.Flags().GetBool("skip-channel")
	forceOverwrite, _ := cmd.Flags().GetBool("force")

	store := secrets.NewKeyringStore()
	m := newInitModel(store)
	m.skipChannel = skipChannel
	m.forceOverwrite = forceOverwrite

	p := tea.NewProgram(m, tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "init wizard error: %w", err)
	}

	fm, ok := finalModel.(initModel)
	if !ok {
		return sigilerr.New(sigilerr.CodeCLISetupFailure, "unexpected model type after wizard")
	}

	if fm.errFinal != nil {
		return sigilerr.Errorf(sigilerr.CodeCLISetupFailure, "init failed: %w", fm.errFinal)
	}

	// If user quit early (not done), that's fine — just return.
	return nil
}

// isTerminal reports whether f is a terminal file descriptor.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
