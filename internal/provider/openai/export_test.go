// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package openai

import (
	openaisdk "github.com/openai/openai-go"
	"github.com/sigil-dev/sigil/internal/provider"
)

// ConvertMessages exposes convertMessages for white-box testing.
var ConvertMessages = func(msgs []provider.Message, systemPrompt string, originTagging bool) ([]openaisdk.ChatCompletionMessageParamUnion, error) {
	return convertMessages(msgs, systemPrompt, originTagging)
}

// BuildParams exposes buildParams for white-box testing.
var BuildParams = func(req provider.ChatRequest) (openaisdk.ChatCompletionNewParams, error) {
	return buildParams(req)
}
