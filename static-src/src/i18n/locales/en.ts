/**
 * English catalog (issue #144: PWA internationalization, DE / FR / EN).
 *
 * The SOURCE catalog: it defines the full key set (`MessageKey` in
 * `@/i18n`) and every other locale must translate exactly these keys, with
 * exactly the same `{placeholder}` names per key (`npm run check:i18n`
 * enforces this). Keys are flat, dotted, and grouped by area prefix
 * (`common.*`, `nav.*`, `status.*`, `chat.*`, `toast.*`, `settings.*`,
 * `permissions.*`, `tools.*`, ...) so the three catalogs stay easy to diff.
 * Values are plain string literals or plural objects (`{ one, other }`)
 * only — no template literals, expressions or spreads.
 */
import type { Message } from '../core';

export const en = {
  // --- common ---------------------------------------------------------
  'common.dismiss': 'Dismiss',
  'common.retry': 'Retry',
  'common.cancel': 'Cancel',
  'common.confirm': 'Confirm',
  'common.loading': 'Loading',

  // --- nav (top-level page navigation, issue #15; issue #155: role-aware shell) ---
  'nav.chat': 'Chat',
  'nav.tools': 'Tools',
  'nav.permissions': 'Permissions',
  'nav.organization': 'Organization',
  'nav.settings': 'Settings',
  'nav.platform': 'Platform',
  'nav.logout': 'Log out',
  'nav.mainNavigation': 'Main navigation',

  // --- status (connection state pill) ----------------------------------
  'status.idle': 'Ready',
  'status.working': 'Working…',
  'status.awaiting': 'Waiting for you',
  'status.offline': 'Offline',

  // --- connection (offline banner) --------------------------------------
  'connection.offlineMessage': 'admino cannot reach the LLM backend. Check your provider configuration.',

  // --- chat (chat header, thinking indicator, tool-call state) ---------
  'chat.thinking': 'admino is working…',
  'chat.header.clearChat': 'Clear chat',
  'chat.header.menu': 'Menu',
  'chat.toolCall.expired': 'Expired',

  // --- toast (shared) ----------------------------------------------------
  'toast.common.saved': 'Saved',
  'toast.common.saveFailed.title': 'Save failed',

  // --- toast (chat store) ------------------------------------------------
  'toast.chat.slowDown.title': 'Slow down',
  'toast.chat.slowDown.body': 'admino is rate-limited.',
  'toast.chat.genericError.title': 'Something went wrong',
  'toast.chat.genericError.body': 'Check the server logs.',
  'toast.chat.connectionLost.title': 'Connection lost',
  'toast.chat.connectionLost.body': 'Cannot reach the server.',
  'toast.chat.approvalExpired.title': 'Approval expired',
  'toast.chat.approvalExpired.body': 'Send the message again.',
  'toast.chat.alreadyExpired': 'Already expired',

  // --- toast (settings store) --------------------------------------------
  'toast.settings.connectionFailed.title': 'Connection failed',
  'toast.settings.googleDisconnected': 'Google disconnected',
  'toast.settings.microsoftDisconnected': 'Microsoft disconnected',
  'toast.settings.disconnectFailed.title': 'Disconnect failed',

  // --- toast (critical permissions store) ---------------------------------
  'toast.criticalPermissions.promotionScheduled.title': 'Promotion scheduled',
  'toast.criticalPermissions.promotionScheduled.body': 'Active in {time}',
  'toast.criticalPermissions.promotionFailed.title': 'Promotion failed',
  'toast.criticalPermissions.cancelled.title': 'Pending promotion cancelled',
  'toast.criticalPermissions.cancelFailed.title': 'Cancel failed',
  'toast.criticalPermissions.disabled': 'Disabled: {permission}',
  'toast.criticalPermissions.disableFailed.title': 'Disable failed',

  // --- settings (fallback error strings) ------------------------------------
  'settings.error.loadFailed': 'Failed to load settings',
  'settings.error.saveFailed': 'Failed to save settings',
  'settings.error.unexpectedRedirect': 'Unexpected OAuth redirect URL.',
  'settings.error.oauthStartFailed': 'Failed to start OAuth flow',
  'settings.error.disconnectFailed': 'Failed to disconnect',

  // --- permissions (fallback error strings, critical permission copy) ------
  'permissions.error.loadFailed': 'Failed to load permissions',
  'permissions.error.saveFailed': 'Failed to save permission',
  'permissions.critical.gmailSend.label': 'Send email · Gmail',
  'permissions.critical.outlookSend.label': 'Send email · Outlook',
  'permissions.critical.googleCalendarUpdate.label': 'Update event · Google Calendar',
  'permissions.critical.outlookCalendarUpdate.label': 'Update event · Outlook Calendar',
  'permissions.critical.sendEmail.description':
    'When enabled, the agent can draft emails and ask for your approval before sending.',
  'permissions.critical.updateEvent.description':
    'When enabled, the agent can propose changes to existing events for your approval.',

  // --- criticalPermissions (fallback error string) --------------------------
  'criticalPermissions.error.loadFailed': 'Failed to load critical permissions',
  'criticalPermissions.title': 'Critical Permissions',
  'criticalPermissions.subtitle':
    'Allow the agent to propose these actions. You will still approve each one individually before it executes.',
  'criticalPermissions.activeIn': 'Active in {time}',
  'criticalPermissions.active': 'Active',
  'criticalPermissions.askBeforeEach': 'admino will ask you before each {action}',
  'criticalPermissions.toggle': 'Toggle {permission}',
  'criticalPermissions.footer':
    'Disabling takes effect immediately. Enabling requires re-authentication and a 5-minute cooldown you can cancel.',

  // --- tools (tool metadata shown on the Permissions page) ------------------
  'tools.gmail.label': 'Gmail',
  'tools.gmail.description': 'Read, search, and send from your inbox',
  'tools.gmail.actions.read': 'Read a message body',
  'tools.gmail.actions.list': 'List messages in inbox',
  'tools.gmail.actions.search': 'Find messages by query',
  'tools.gmail.actions.send': 'Send an email on your behalf',
  'tools.gmail.actions.delete': 'Permanently delete a thread',

  'tools.googleCalendar.label': 'Google Calendar',
  'tools.googleCalendar.description': 'Read events, create with approval',
  'tools.googleCalendar.actions.read': 'View event details',
  'tools.googleCalendar.actions.list': 'List upcoming events',
  'tools.googleCalendar.actions.create': 'Create a new event',
  'tools.googleCalendar.actions.update': 'Modify an existing event',
  'tools.googleCalendar.actions.delete': 'Remove an event',

  'tools.googleDrive.label': 'Google Drive',
  'tools.googleDrive.description': 'Search and download your Drive files',
  'tools.googleDrive.actions.read': 'Read file contents',
  'tools.googleDrive.actions.list': 'List files and folders',
  'tools.googleDrive.actions.search': 'Search for files',
  'tools.googleDrive.actions.download': 'Download a file',
  'tools.googleDrive.actions.delete': 'Delete a file',

  'tools.outlook.label': 'Outlook',
  'tools.outlook.description': 'Read, search, and send from your mailbox',
  'tools.outlook.actions.read': 'Read a message body',
  'tools.outlook.actions.list': 'List messages in inbox',
  'tools.outlook.actions.search': 'Find messages by query',
  'tools.outlook.actions.send': 'Send an email on your behalf',
  'tools.outlook.actions.delete': 'Permanently delete a message',

  'tools.outlookCalendar.label': 'Outlook Calendar',
  'tools.outlookCalendar.description': 'Read events, create with approval',
  'tools.outlookCalendar.actions.read': 'View event details',
  'tools.outlookCalendar.actions.list': 'List upcoming events',
  'tools.outlookCalendar.actions.create': 'Create a new event',
  'tools.outlookCalendar.actions.update': 'Modify an existing event',
  'tools.outlookCalendar.actions.delete': 'Remove an event',

  'tools.onedrive.label': 'OneDrive',
  'tools.onedrive.description': 'Search and download your OneDrive files',
  'tools.onedrive.actions.read': 'Read file contents',
  'tools.onedrive.actions.list': 'List files and folders',
  'tools.onedrive.actions.search': 'Search for files',
  'tools.onedrive.actions.download': 'Download a file',
  'tools.onedrive.actions.delete': 'Delete a file',

  'tools.memory.label': 'Memory',
  'tools.memory.description': 'Long-term key-value store',
  'tools.memory.actions.get': 'Retrieve a stored value',
  'tools.memory.actions.set': 'Store a key-value pair',
  'tools.memory.actions.list': 'List all stored keys',
  'tools.memory.actions.delete': 'Delete a stored key',

  'tools.database.label': 'Database',
  'tools.database.description': 'Application database access',
  'tools.database.actions.query': 'Run a read-only query',

  // --- chat page (empty state, suggestions, input bar) -------------------
  'chat.empty.heading': 'How can I help?',
  'chat.empty.subtext': "By default, answers come from Infomaniak's Swiss-hosted AI.",
  'chat.suggestions.searchEmails': 'Search my emails',
  'chat.suggestions.calendarToday': "What's on my calendar today?",
  'chat.suggestions.findFile': 'Find a file',
  'chat.input.attachFile': 'Attach file',
  'chat.input.placeholder': 'Ask admino anything…',
  'chat.input.send': 'Send',

  // --- toolCall (tool-call card and chip) --------------------------------
  'toolCall.approve': 'Approve',
  'toolCall.deny': 'Deny',
  'toolCall.resultCount': {
    one: '{count} result',
    other: '{count} results',
  },
  'toolCall.hideDetails': 'Hide',
  'toolCall.showDetails': 'Details',
  'toolCall.state.pending': 'pending',
  'toolCall.state.approved': 'approved',
  'toolCall.state.denied': 'denied',
  'toolCall.state.completed': 'completed',
  'toolCall.state.error': 'error',

  // --- statusBadge (tool-call and permission status badge) ---------------
  'statusBadge.approved': 'Approved',
  'statusBadge.denied': 'Denied',
  'statusBadge.pending': 'Awaiting approval',
  'statusBadge.hardcodedDeny': 'Hardcoded deny',
  'statusBadge.allowed': 'Allowed',
  'statusBadge.confirm': 'Requires approval',

  // --- permissionState (permission pill and Permissions page filters) ----
  'permissionState.allow': 'Allowed',
  'permissionState.confirm': 'Needs approval',
  'permissionState.deny': 'Denied',
  'permissionPill.promotableHint': 'This permission can be managed from Settings › Danger Zone',
  'permissionPill.hardcodedHint': 'This permission is enforced by security policy and cannot be changed',

  // --- permissions page (header, filters, per-tool summary chips) --------
  'permissions.page.toolCount': {
    one: '{count} tool',
    other: '{count} tools',
  },
  'permissions.page.actionCount': {
    one: '{count} action',
    other: '{count} actions',
  },
  'permissions.page.loading': 'Loading permissions...',
  'permissions.filter.all': 'All',
  'permissions.summary.allowed': {
    one: '{n} allowed',
    other: '{n} allowed',
  },
  'permissions.summary.approval': {
    one: '{n} approval',
    other: '{n} approval',
  },
  'permissions.summary.denied': {
    one: '{n} denied',
    other: '{n} denied',
  },

  // --- toolsPage (connected accounts, local tools, OAuth callback) -------
  'toolsPage.accounts.title': 'Connected accounts',
  'toolsPage.accounts.subtitle': 'Connect a provider once. Toggle individual services any time.',
  'toolsPage.status.connected': 'Connected',
  'toolsPage.status.notConnected': 'Not connected',
  'toolsPage.google.connectHint': 'Connect to use Gmail, Google Calendar, Google Drive.',
  'toolsPage.microsoft.connectHint': 'Connect to use Outlook Mail, Outlook Calendar, OneDrive.',
  'toolsPage.connect': 'Connect',
  'toolsPage.disconnect': 'Disconnect',
  'toolsPage.service.outlookMail': 'Outlook Mail',
  'toolsPage.local.title': 'Local tools',
  'toolsPage.local.subtitle': 'Tools that run on your admino server. No external account needed.',
  'toolsPage.memory.description': 'Persistent key-value notes',
  'toolsPage.disconnectConfirm.heading': 'Disconnect {provider}?',
  'toolsPage.disconnectConfirm.subtext':
    'This will revoke the OAuth refresh token. You can reconnect at any time.',
  'toolsPage.oauth.connected.title': 'Account connected',
  'toolsPage.oauth.connected.body': 'Your account has been linked successfully.',
  'toolsPage.oauth.reason.denied': 'You declined the consent screen.',
  'toolsPage.oauth.reason.invalidState': 'Session expired. Please try again.',
  'toolsPage.oauth.reason.missingCode': 'No authorization code received.',
  'toolsPage.oauth.reason.exchangeFailed': 'Token exchange failed. Check OAuth credentials.',
  'toolsPage.oauth.reason.unexpected': 'An unexpected error occurred.',

  // --- settings page (subnav, sections, danger zone) ---------------------
  'settings.loadingLabel': 'Loading settings',
  'settings.error.loadBanner': 'Failed to load settings: {error}',
  'settings.soonBadge': 'Soon',
  'settings.nav.group.account': 'Account',
  'settings.nav.group.app': 'App',
  'settings.nav.group.system': 'System',
  'settings.nav.session': 'Session',
  'settings.nav.appearance': 'Appearance',
  'settings.nav.notifications': 'Notifications',
  'settings.nav.about': 'About',
  'settings.nav.danger': 'Danger zone',
  'settings.session.subtitle': 'Identifies this conversation thread on the admino backend.',
  'settings.session.id.label': 'Session ID',
  'settings.session.id.hint': 'Alphanumeric, hyphens, underscores. Max 64 chars.',
  'settings.session.new.label': 'New session',
  'settings.session.new.hint': 'Clears the chat thread.',
  'settings.appearance.subtitle': 'How the interface looks. Changes apply immediately.',
  'settings.appearance.theme.label': 'Theme',
  'settings.appearance.theme.hint': 'Dark mode is on the roadmap for v2.',
  'settings.appearance.theme.light': 'Light',
  'settings.appearance.theme.dark': 'Dark',
  'settings.appearance.theme.system': 'System',
  'settings.notifications.subtitle': 'In-app pings. Browser push is opt-in once per device.',
  'settings.notifications.approval.label': 'Tool-approval pings',
  'settings.notifications.approval.hint': 'Ping me when admino needs my approval to run a tool.',
  'settings.notifications.taskDone.label': 'Task-done pings',
  'settings.notifications.taskDone.hint': 'Ping me when a long-running response is ready.',
  'settings.notifications.sound.label': 'Sound',
  'settings.notifications.sound.hint': 'Subtle chime on pings. Respects system Do Not Disturb.',
  'settings.about.subtitle':
    "A privacy- and security-first personal AI agent you run yourself, powered by Infomaniak's Swiss-hosted AI by default.",
  'settings.about.version': 'Version',
  'settings.about.versionValue': 'admino {version} (Alpha)',
  'settings.about.sourceCode': 'Source code',
  'settings.about.license': 'License',
  'settings.danger.subtitle': 'These actions cannot be undone. Each one prompts for confirmation.',
  'settings.danger.clear.label': 'Clear conversation',
  'settings.danger.clear.hint': 'Wipes the current chat thread. Audit log is preserved by design.',
  'settings.danger.clear.button': 'Clear thread',
  'settings.danger.disconnectAll.label': 'Disconnect all accounts',
  'settings.danger.disconnectAll.hint': 'Revokes OAuth refresh tokens for Google and Microsoft.',
  'settings.danger.disconnectAll.button': 'Disconnect all',
  'settings.danger.reset.label': 'Reset settings',
  'settings.danger.reset.hint': 'Resets all settings to defaults. Connected accounts stay connected.',
  'settings.danger.reset.button': 'Reset to defaults',
  'settings.danger.erase.label': 'Erase all data',
  'settings.danger.erase.hint': 'Deletes the audit log, memory, and document store. Cannot be recovered.',
  'settings.danger.erase.button': 'Erase everything',
  'settings.danger.clearConfirm.heading': 'Clear conversation?',
  'settings.danger.clearConfirm.subtext':
    'This will remove all messages and tool call history from the current session.',
  'settings.danger.clearConfirm.confirm': 'Clear',
  'settings.toast.chatCleared': 'Chat cleared',
  'settings.toast.newSession': 'New session started',
  'settings.comingSoon.title': 'Coming soon',
  'settings.comingSoon.resetSettings': 'Reset settings is not yet available.',
  'settings.comingSoon.eraseAll': 'Erase all data is not yet available.',
  'settings.comingSoon.toggle': 'This toggle is not yet available.',
  'settings.session.logout.label': 'Log out',
  'settings.session.logout.hint': 'End your session on this device.',

  // --- auth (session-expired toast, error copy, issue #155) --------------
  'auth.sessionExpired.title': 'Session expired',
  'auth.sessionExpired.body': 'Please log in again.',
  'auth.login.error.invalid': 'Invalid email or password',
  'auth.error.rateLimited': 'Too many attempts. Please wait a moment and try again.',
  'auth.error.generic': 'Something went wrong. Please try again.',
  'auth.reset.error.invalidLink': 'This reset link is invalid or has expired.',
  'auth.invitation.error.invalidLink': 'This invitation link is invalid or has expired.',
  'auth.invitation.error.invalidName': 'Please enter your name.',

  // --- auth.password (password policy, issue #155) -----------------------
  'auth.password.error.tooShort': 'Password is too short.',
  'auth.password.error.tooLong': 'Password is too long.',
  'auth.password.error.common': 'This password is too common.',
  'auth.password.error.equalsEmail': 'Password must not be your email address.',
  'auth.password.error.mismatch': 'Passwords do not match.',
  'auth.password.error.generic': 'This password does not meet the requirements.',
  'auth.password.rule.length': 'Between {min} and {max} characters.',
  'auth.password.rule.common': 'Not a commonly used password.',
  'auth.password.rule.email': 'Not the same as your email address.',

  // --- auth.role (invited role, shown on the Accept invitation page) -----
  'auth.role.orgAdmin': 'Org Admin',
  'auth.role.editor': 'Editor',
  'auth.role.viewer': 'Viewer',

  // --- auth.login (Login page) --------------------------------------------
  'auth.login.title': 'Log in',
  'auth.login.email.label': 'Email',
  'auth.login.password.label': 'Password',
  'auth.login.submit': 'Log in',
  'auth.login.forgotPassword': 'Forgot password?',

  // --- auth.forgotPassword (Forgot password page) -------------------------
  'auth.forgotPassword.title': 'Forgot password',
  'auth.forgotPassword.subtitle': "Enter your email and we'll send you a reset link.",
  'auth.forgotPassword.email.label': 'Email',
  'auth.forgotPassword.submit': 'Send reset link',
  'auth.forgotPassword.success':
    "If an account exists for that address, we've sent a reset link. It's valid for 30 minutes.",
  'auth.forgotPassword.backToLogin': 'Back to log in',

  // --- auth.reset (Reset password page) ------------------------------------
  'auth.reset.title': 'Reset password',
  'auth.reset.invalidLink.heading': 'This link is invalid or has expired.',
  'auth.reset.invalidLink.cta': 'Request a new link',
  'auth.reset.password.label': 'New password',
  'auth.reset.confirm.label': 'Confirm new password',
  'auth.reset.submit': 'Change password',
  'auth.reset.success': 'Password changed. Log in with your new password.',

  // --- auth.invitation (Accept invitation page) ----------------------------
  'auth.invitation.title': 'Accept invitation',
  'auth.invitation.invalidLink.heading': 'This invitation link is invalid or has expired.',
  'auth.invitation.org.label': 'Organization',
  'auth.invitation.role.label': 'Role',
  'auth.invitation.email.label': 'Email',
  'auth.invitation.name.label': 'Full name',
  'auth.invitation.password.label': 'Password',
  'auth.invitation.confirm.label': 'Confirm password',
  'auth.invitation.submit': 'Accept invitation',

  // --- organization page (placeholder, issue #155) --------------------------
  'organization.empty.heading': 'Organization',
  'organization.empty.subtext': 'User management and organization settings will appear here.',

  // --- platform page (placeholder, Super Admin console, issue #155) ---------
  'platform.empty.heading': 'Platform console',
  'platform.empty.subtext': 'The platform console will appear here.',

  // --- chat page (read-only viewer, issue #155) -----------------------------
  'chat.viewerEmpty.heading': 'Nothing shared with you yet',
  'chat.viewerEmpty.subtext': 'Projects that others share with you will appear here.',
} satisfies Record<string, Message>;
