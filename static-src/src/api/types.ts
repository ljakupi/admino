export interface ChatRequest {
  message: string;
  session_id: string;
}

export interface ToolCallRecord {
  tool: string;
  action: string;
  permission: 'allow' | 'confirm' | 'deny';
  success: boolean;
  args?: Record<string, unknown>;
  duration_ms?: number;
}

export interface PendingConfirmationSummary {
  confirmation_id: string;
  tool: string;
  action: string;
  args?: Record<string, unknown>;
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
  resultCount?: number;
  durationMs?: number;
  error?: string;
  timestamp: Date;
}

/** Thread item — union of message and tool call */
export type ThreadItem =
  | { type: 'message'; data: ChatMessage }
  | { type: 'tool_call'; data: ToolCallUI }
  | { type: 'thinking'; data: { id: string } };

// Settings types

export type LLMProviderName = 'ollama' | 'anthropic' | 'openai';
export type AppTheme = 'light' | 'dark' | 'system';

export interface LLMSettings {
  provider: LLMProviderName;
  model: string;
  ollama_url: string;
  anthropic_model: string;
  openai_model: string;
  anthropic_key_configured: boolean;
  openai_key_configured: boolean;
}

export interface AppearanceSettings {
  theme: AppTheme;
}

export interface NotificationSettings {
  enabled: boolean;
}

export interface LimitsSettings {
  max_tool_calls_per_message: number;
  confirmation_timeout_s: number;
  max_message_length: number;
}

export interface ServerSettings {
  host: string;
  port: number;
}

export interface OAuthAccountInfo {
  connected: boolean;
  email: string | null;
  services: string[];
}

export interface ConnectedAccounts {
  google: OAuthAccountInfo;
  microsoft: OAuthAccountInfo;
}

export interface SettingsResponse {
  llm: LLMSettings;
  appearance: AppearanceSettings;
  notifications: NotificationSettings;
  limits: LimitsSettings;
  server: ServerSettings;
  connected_accounts: ConnectedAccounts;
}

export interface LLMSettingsPatch {
  provider?: LLMProviderName;
  model?: string;
  ollama_url?: string;
  anthropic_model?: string;
  openai_model?: string;
}

export interface SettingsPatch {
  llm?: LLMSettingsPatch;
  appearance?: { theme?: AppTheme };
  notifications?: { enabled?: boolean };
}

// Permissions types

export type PermissionState = 'allow' | 'confirm' | 'deny';

export interface PermissionEntry {
  tool: string;
  action: string;
  permission: PermissionState;
}

export interface PermissionsResponse {
  permissions: PermissionEntry[];
}

export interface PermissionPatchRequest {
  tool: string;
  action: string;
  permission: PermissionState;
}
