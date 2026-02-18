// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package google

import (
	"github.com/sigil-dev/sigil/internal/provider"
	"google.golang.org/genai"
)

// ConvertMessages exposes convertMessages for white-box testing.
var ConvertMessages = func(msgs []provider.Message, originTagging bool) ([]*genai.Content, error) {
	return convertMessages(msgs, originTagging)
}
