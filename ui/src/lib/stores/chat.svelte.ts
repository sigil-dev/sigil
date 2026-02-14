// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Sigil Contributors

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:18789';

/** Role of a chat message */
export type MessageRole = 'user' | 'assistant' | 'tool';

/** A tool call embedded in an assistant message */
export interface ToolCall {
	name: string;
	status: 'pending' | 'running' | 'complete' | 'error';
	input?: unknown;
	result?: unknown;
}

/** A single chat message */
export interface ChatMessage {
	id: string;
	role: MessageRole;
	content: string;
	timestamp: number;
	toolCalls?: ToolCall[];
}

/** A session summary for the sidebar */
export interface SessionEntry {
	id: string;
	workspaceId: string;
	status: string;
}

/** Workspace with its sessions for sidebar grouping */
export interface WorkspaceGroup {
	id: string;
	description: string;
	sessions: SessionEntry[];
}

let nextMessageId = 0;
function generateMessageId(): string {
	return `msg-${Date.now()}-${nextMessageId++}`;
}

/**
 * Chat store using Svelte 5 runes for reactivity.
 * Manages messages, session state, SSE streaming, and sidebar data.
 */
export class ChatStore {
	sessionId = $state<string | null>(null);
	workspaceId = $state<string | null>(null);
	messages = $state<ChatMessage[]>([]);
	loading = $state(false);
	error = $state<string | null>(null);
	workspaceGroups = $state<WorkspaceGroup[]>([]);
	sidebarLoading = $state(false);

	private abortController: AbortController | null = null;

	/** Load workspaces and their sessions for the sidebar */
	async loadSidebar(): Promise<void> {
		this.sidebarLoading = true;
		try {
			const wsRes = await fetch(`${API_BASE}/api/v1/workspaces`);
			if (!wsRes.ok) {
				this.error = 'Failed to load workspaces';
				return;
			}
			const wsData = (await wsRes.json()) as {
				workspaces: { id: string; description: string }[] | null;
			};
			const workspaces = wsData.workspaces ?? [];

			const groups: WorkspaceGroup[] = [];
			for (const ws of workspaces) {
				const sessRes = await fetch(`${API_BASE}/api/v1/workspaces/${ws.id}/sessions`);
				let sessions: SessionEntry[] = [];
				if (sessRes.ok) {
					const sessData = (await sessRes.json()) as {
						sessions: { id: string; status: string; workspace_id: string }[] | null;
					};
					sessions = (sessData.sessions ?? []).map((s) => ({
						id: s.id,
						workspaceId: s.workspace_id,
						status: s.status
					}));
				}
				groups.push({ id: ws.id, description: ws.description, sessions });
			}
			this.workspaceGroups = groups;
		} catch {
			this.error = 'Failed to load sidebar data';
		} finally {
			this.sidebarLoading = false;
		}
	}

	/** Select an existing session */
	selectSession(workspaceId: string, sessionId: string): void {
		this.workspaceId = workspaceId;
		this.sessionId = sessionId;
		this.messages = [];
		this.error = null;
	}

	/** Start a new session in a workspace */
	newSession(workspaceId: string): void {
		this.workspaceId = workspaceId;
		this.sessionId = null;
		this.messages = [];
		this.error = null;
	}

	/** Cancel an in-progress streaming response */
	cancel(): void {
		if (this.abortController) {
			this.abortController.abort();
			this.abortController = null;
		}
		this.loading = false;
	}

	/**
	 * Send a message and stream the response via SSE.
	 * Appends user message immediately, then streams assistant response.
	 */
	async sendMessage(content: string): Promise<void> {
		if (!content.trim() || this.loading) return;

		this.error = null;

		const userMessage: ChatMessage = {
			id: generateMessageId(),
			role: 'user',
			content: content.trim(),
			timestamp: Date.now()
		};
		this.messages = [...this.messages, userMessage];

		const assistantMessage: ChatMessage = {
			id: generateMessageId(),
			role: 'assistant',
			content: '',
			timestamp: Date.now()
		};
		this.messages = [...this.messages, assistantMessage];

		this.loading = true;
		this.abortController = new AbortController();

		try {
			const body: Record<string, unknown> = { content: content.trim() };
			if (this.workspaceId) body.workspace_id = this.workspaceId;
			if (this.sessionId) body.session_id = this.sessionId;

			const response = await fetch(`${API_BASE}/api/v1/chat/stream`, {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					Accept: 'text/event-stream'
				},
				body: JSON.stringify(body),
				signal: this.abortController.signal
			});

			if (!response.ok) {
				const errText = await response.text();
				this.error = `Request failed: ${response.status} ${errText}`;
				this.removeMessage(assistantMessage.id);
				return;
			}

			if (!response.body) {
				this.error = 'No response body';
				this.removeMessage(assistantMessage.id);
				return;
			}

			await this.readSSEStream(response.body, assistantMessage.id);
		} catch (err: unknown) {
			if (err instanceof DOMException && err.name === 'AbortError') {
				return;
			}
			this.error = err instanceof Error ? err.message : 'Stream failed';
			this.removeMessage(assistantMessage.id);
		} finally {
			this.loading = false;
			this.abortController = null;
		}
	}

	/** Parse SSE events from a ReadableStream and update the assistant message */
	private async readSSEStream(body: ReadableStream<Uint8Array>, messageId: string): Promise<void> {
		const reader = body.getReader();
		const decoder = new TextDecoder();
		let buffer = '';

		try {
			while (true) {
				const { done, value } = await reader.read();
				if (done) break;

				buffer += decoder.decode(value, { stream: true });
				const lines = buffer.split('\n');
				buffer = lines.pop() ?? '';

				let eventType = '';
				for (const line of lines) {
					if (line.startsWith('event:')) {
						eventType = line.slice(6).trim();
					} else if (line.startsWith('data:')) {
						const data = line.slice(5).trim();
						this.handleSSEEvent(eventType || 'message', data, messageId);
						eventType = '';
					}
				}
			}

			// Process any remaining buffer
			if (buffer.trim()) {
				const lines = buffer.split('\n');
				let eventType = '';
				for (const line of lines) {
					if (line.startsWith('event:')) {
						eventType = line.slice(6).trim();
					} else if (line.startsWith('data:')) {
						const data = line.slice(5).trim();
						this.handleSSEEvent(eventType || 'message', data, messageId);
						eventType = '';
					}
				}
			}
		} finally {
			reader.releaseLock();
		}
	}

	/** Handle a single SSE event */
	private handleSSEEvent(eventType: string, data: string, messageId: string): void {
		switch (eventType) {
			case 'text_delta': {
				this.appendToMessage(messageId, data);
				break;
			}
			case 'session_id': {
				this.sessionId = data;
				break;
			}
			case 'tool_call': {
				try {
					const toolData = JSON.parse(data) as { name: string; input?: unknown };
					this.addToolCall(messageId, {
						name: toolData.name,
						status: 'running',
						input: toolData.input
					});
				} catch {
					// Ignore malformed tool_call events
				}
				break;
			}
			case 'tool_result': {
				try {
					const resultData = JSON.parse(data) as { name: string; result?: unknown };
					this.updateToolCall(messageId, resultData.name, {
						status: 'complete',
						result: resultData.result
					});
				} catch {
					// Ignore malformed tool_result events
				}
				break;
			}
			case 'error': {
				this.error = data;
				break;
			}
			case 'done': {
				// Stream complete
				break;
			}
			default: {
				// For plain "message" or unknown events, treat as text delta
				if (data) {
					this.appendToMessage(messageId, data);
				}
				break;
			}
		}
	}

	/** Append text content to a message by ID */
	private appendToMessage(messageId: string, text: string): void {
		this.messages = this.messages.map((m) =>
			m.id === messageId ? { ...m, content: m.content + text } : m
		);
	}

	/** Add a tool call to a message */
	private addToolCall(messageId: string, toolCall: ToolCall): void {
		this.messages = this.messages.map((m) => {
			if (m.id !== messageId) return m;
			return { ...m, toolCalls: [...(m.toolCalls ?? []), toolCall] };
		});
	}

	/** Update a tool call's status/result by name */
	private updateToolCall(
		messageId: string,
		toolName: string,
		update: Partial<ToolCall>
	): void {
		this.messages = this.messages.map((m) => {
			if (m.id !== messageId) return m;
			return {
				...m,
				toolCalls: (m.toolCalls ?? []).map((tc) =>
					tc.name === toolName ? { ...tc, ...update } : tc
				)
			};
		});
	}

	/** Remove a message by ID (used when streaming fails) */
	private removeMessage(messageId: string): void {
		this.messages = this.messages.filter((m) => m.id !== messageId);
	}
}

/** Singleton chat store instance */
export const chatStore = new ChatStore();
