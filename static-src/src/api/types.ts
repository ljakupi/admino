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
  task_done: boolean;
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
  notifications?: { enabled?: boolean; task_done?: boolean };
}

/** `GET`/`PATCH /api/org/settings` — Org Admin only: which tool services are enabled. */
export interface OrgSettingsResponse {
  tools: ToolsSettings;
  /** The org's data residency policy (read-only here; issue #162). */
  data_residency: boolean;
}

export interface OrgSettingsPatch {
  tools: Partial<ToolsSettings>;
}

// OAuth connections (issue #162: per-user connections, residency gating).

export type OAuthProvider = 'google' | 'microsoft';

export type ConnectorTool =
  | 'gmail'
  | 'google_calendar'
  | 'google_drive'
  | 'outlook'
  | 'outlook_calendar'
  | 'onedrive';

/** One of a provider's services and the org's stored switch for it. */
export interface OAuthServiceStatus {
  tool: ConnectorTool;
  enabled: boolean;
}

/** `GET /api/oauth/{provider}/status`. */
export interface OAuthConnectionStatus {
  connected: boolean;
  /**
   * True when the stored refresh token is still believed valid. A connected
   * but unhealthy account (dead/revoked refresh token) is shown as "Not
   * connected" — see `providerState` in `services/connections.ts`.
   */
  healthy: boolean;
  email: string | null;
  /** True when the caller's org has data residency on (connect refused, connection kept but inactive). */
  data_residency: boolean;
  /** The provider's services, in `PROVIDER_TOOLS` order, each with the org's stored switch. */
  services: OAuthServiceStatus[];
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

// Permissions summary (read-only, issue #161: every member role sees the
// org's effective permission states).

export type PermissionSummaryState = 'allow' | 'confirm' | 'deny' | 'disabled';

export interface PermissionSummaryEntry {
  tool: string;
  action: string;
  state: PermissionSummaryState;
}

export interface PermissionsSummaryResponse {
  permissions: PermissionSummaryEntry[];
}

// Org users and invitations (issue #165: Organization console, users and
// invitations UI; backed by #153's invitations and #164's org users routes).

/** Read-only seat usage of the caller's org, carried on `GET /api/org/users`. */
export interface OrgSeats {
  used: number;
  limit: number;
}

export type OrgUserStatus = 'active' | 'deactivated';

export interface OrgUser {
  id: string;
  name: string | null;
  email: string;
  role: MemberRole;
  status: OrgUserStatus;
  created_at: string;
  last_login_at: string | null;
}

export interface OrgUserListResponse {
  users: OrgUser[];
  seats: OrgSeats;
}

/** `PATCH /api/org/users/{id}` body: only the fields being changed. */
export interface OrgUserPatch {
  role?: MemberRole;
  name?: string;
  email?: string;
}

export interface OrgInvitation {
  id: string;
  email: string;
  role: MemberRole;
  sent_at: string;
  expires_at: string;
  expired: boolean;
}

export interface OrgInvitationListResponse {
  invitations: OrgInvitation[];
}
