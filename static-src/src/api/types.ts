export interface ChatRequest {
  message: string;
  session_id: string;
}

// Auth types (issue #155: auth pages and role-aware app shell)

export type UserKind = 'member' | 'super_admin';
export type MemberRole = 'org_admin' | 'editor' | 'viewer';

/** `GET /api/auth/me`. A Super Admin has no org and no role; a member always has both. */
export interface MeResponse {
  user_id: string;
  kind: UserKind;
  org_id: string | null;
  role: MemberRole | null;
  ui_language: string;
  response_language: string | null;
}

/** `GET /api/auth/invitations/{token}`: the invitation's public details. */
export interface InvitationDetails {
  org_name: string;
  role: MemberRole;
  email: string;
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

// Settings types (issue #159: settings split into platform, organization and
// user scopes — the old single `/api/settings` is gone).

export type AppTheme = 'light' | 'dark' | 'system';

export interface AppearanceSettings {
  theme: AppTheme;
}

export interface NotificationSettings {
  enabled: boolean;
}

export interface ToolsSettings {
  gmail: boolean;
  google_calendar: boolean;
  google_drive: boolean;
  outlook: boolean;
  outlook_calendar: boolean;
  onedrive: boolean;
  memory: boolean;
}

/** `GET`/`PATCH /api/me/settings` — the caller's own theme and notifications. */
export interface UserSettingsResponse {
  appearance: AppearanceSettings;
  notifications: NotificationSettings;
}

export interface UserSettingsPatch {
  appearance?: { theme?: AppTheme };
  notifications?: { enabled?: boolean };
}

/** `GET`/`PATCH /api/org/settings` — Org Admin only: which tool services are enabled. */
export interface OrgSettingsResponse {
  tools: ToolsSettings;
}

export interface OrgSettingsPatch {
  tools: Partial<ToolsSettings>;
}

/** `GET /api/oauth/{provider}/status`. */
export interface OAuthConnectionStatus {
  connected: boolean;
  /**
   * True when the stored refresh token is still believed valid. A connected
   * but unhealthy account (dead/revoked refresh token) is shown as "Not
   * connected" — see `effectivelyConnected` on the Tools page.
   */
  healthy: boolean;
  email: string | null;
  services: string[];
}

export interface ConnectedAccounts {
  google: OAuthConnectionStatus;
  microsoft: OAuthConnectionStatus;
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

// Critical Permissions types

export interface CriticalPermissionEntry {
  tool: string;
  action: string;
  state: 'deny' | 'confirm';
  pending_at: string | null;
}

export interface CriticalPermissionsResponse {
  permissions: CriticalPermissionEntry[];
}

export interface CriticalPermissionPatchResponse {
  tool: string;
  action: string;
  state: 'deny' | 'confirm';
  pending_at: string | null;
}
