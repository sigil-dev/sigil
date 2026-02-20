// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openrouter

import (
	openaisdk "github.com/openai/openai-go"
	"github.com/sigil-dev/sigil/internal/provider"
)

// ConvertMessages exposes convertMessages for white-box testing.
var ConvertMessages = func(msgs []provider.Message, systemPrompt string, originTagging bool) ([]openaisdk.ChatCompletionMessageParamUnion, error) {
	return convertMessages(msgs, systemPrompt, originTagging)
}
