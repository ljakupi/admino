export interface ChatRequest {
  message: string;
  session_id: string;
}

export interface ToolCallRecord {
  tool: string;
  action: string;
  permission: 'allow' | 'confirm' | 'deny';
  success: boolean;
}

export interface PendingConfirmationSummary {
  confirmation_id: string;
  tool: string;
  action: string;
  expires_at: string;
}

export type ChatStatus = 'final' | 'awaiting_confirmation' | 'limit_reached' | 'error';

export interface ChatResponse {
  session_id: string;
  response: string;
  tool_calls: ToolCallRecord[];
  status: ChatStatus;
  pending_confirmation: PendingConfirmationSummary | null;
}

export interface ConfirmRequest {
  session_id: string;
  confirmation_id: string;
  approved: boolean;
}

export type SSEEventType =
  | 'status' | 'tool_call' | 'confirm' | 'message' | 'error' | 'done';

export interface SSEEnvelope {
  event: SSEEventType;
  data: string;
}

export interface HealthResponse {
  status: string;
}

/** Chat message for the UI thread */
export type MessageRole = 'user' | 'agent';

export interface ChatMessage {
  id: string;
  role: MessageRole;
  content: string;
  timestamp: Date;
  model?: string;
  streaming?: boolean;
}

/** Tool call with UI state */
export type ToolCallState = 'pending' | 'approved' | 'denied' | 'completed' | 'error';

export interface ToolCallUI {
  id: string;
  tool: string;
  action: string;
  args?: Record<string, unknown>;
  state: ToolCallState;
  confirmationId?: string;
  expiresAt?: string;
  result?: string;
  error?: string;
  timestamp: Date;
}

/** Thread item — union of message and tool call */
export type ThreadItem =
  | { type: 'message'; data: ChatMessage }
  | { type: 'tool_call'; data: ToolCallUI }
  | { type: 'thinking'; data: { id: string } };
