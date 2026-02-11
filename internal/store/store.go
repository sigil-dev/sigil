// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

package store

import "context"

// SessionStore manages conversation sessions and the active message window.
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	UpdateSession(ctx context.Context, session *Session) error
	ListSessions(ctx context.Context, workspaceID string, opts ListOpts) ([]*Session, error)
	DeleteSession(ctx context.Context, id string) error

	// Active message window (last N messages in LLM context).
	AppendMessage(ctx context.Context, sessionID string, msg *Message) error
	GetActiveWindow(ctx context.Context, sessionID string, limit int) ([]*Message, error)
}
