// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package anthropic

import (
	anthropicsdk "github.com/anthropics/anthropic-sdk-go"
	"github.com/sigil-dev/sigil/internal/provider"
)

// ConvertMessages exposes convertMessages for white-box testing.
var ConvertMessages = func(msgs []provider.Message, originTagging bool) ([]anthropicsdk.MessageParam, error) {
	return convertMessages(msgs, originTagging)
}
