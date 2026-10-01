/**
 * German catalog (Swiss Standard German; issue #144: PWA internationalization).
 *
 * Translates every key of `en` (the source catalog) with identical
 * `{placeholder}` names. Swiss spelling only (never "ß", always "ss") and
 * the formal "Sie". `npm run check:i18n` enforces the key/placeholder
 * parity with `en` and `fr`.
 */
import type { Message } from '../core';
import type { MessageKey } from '../index';

export const de: Record<MessageKey, Message> = {
  // --- common ---------------------------------------------------------
  'common.dismiss': 'Schliessen',
  'common.retry': 'Erneut versuchen',
  'common.cancel': 'Abbrechen',
  'common.confirm': 'Bestätigen',
  'common.loading': 'Wird geladen',

  // --- nav (top-level page navigation, issue #15; issue #155: role-aware shell) ---
  'nav.chat': 'Chat',
  'nav.tools': 'Tools',
  'nav.permissions': 'Berechtigungen',
  'nav.organization': 'Organisation',
  'nav.settings': 'Einstellungen',
  'nav.platform': 'Plattform',
  'nav.logout': 'Abmelden',
  'nav.mainNavigation': 'Hauptnavigation',

  // --- status (connection state pill) ----------------------------------
  'status.idle': 'Bereit',
  'status.working': 'Arbeitet…',
  'status.awaiting': 'Wartet auf Sie',
  'status.offline': 'Offline',

  // --- connection (offline banner) --------------------------------------
  'connection.offlineMessage':
    'admino kann das LLM-Backend nicht erreichen. Prüfen Sie Ihre Anbieterkonfiguration.',

  // --- chat (chat header, thinking indicator, tool-call state) ---------
  'chat.thinking': 'admino arbeitet…',
  'chat.header.clearChat': 'Chat löschen',
  'chat.header.menu': 'Menü',
  'chat.toolCall.expired': 'Abgelaufen',

  // --- toast (shared) ----------------------------------------------------
  'toast.common.saved': 'Gespeichert',
  'toast.common.saveFailed.title': 'Speichern fehlgeschlagen',

  // --- toast (chat store) ------------------------------------------------
  'toast.chat.slowDown.title': 'Bitte langsamer',
  'toast.chat.slowDown.body': 'admino ist aktuell ratenbegrenzt.',
  'toast.chat.genericError.title': 'Etwas ist schiefgelaufen',
  'toast.chat.genericError.body': 'Prüfen Sie die Server-Logs.',
  'toast.chat.connectionLost.title': 'Verbindung verloren',
  'toast.chat.connectionLost.body': 'Der Server ist nicht erreichbar.',
  'toast.chat.approvalExpired.title': 'Genehmigung abgelaufen',
  'toast.chat.approvalExpired.body': 'Senden Sie die Nachricht erneut.',
  'toast.chat.alreadyExpired': 'Bereits abgelaufen',

  // --- toast (settings store) --------------------------------------------
  'toast.settings.connectionFailed.title': 'Verbindung fehlgeschlagen',
  'toast.settings.googleDisconnected': 'Google getrennt',
  'toast.settings.microsoftDisconnected': 'Microsoft getrennt',
  'toast.settings.disconnectFailed.title': 'Trennen fehlgeschlagen',
  'toast.settings.settingsReset': 'Einstellungen zurückgesetzt',
  'toast.settings.resetFailed.title': 'Zurücksetzen fehlgeschlagen',

  // --- toast (critical permissions store) ---------------------------------
  'toast.criticalPermissions.promotionScheduled.title': 'Aktivierung geplant',
  'toast.criticalPermissions.promotionScheduled.body': 'Aktiv in {time}',
  'toast.criticalPermissions.promotionFailed.title': 'Aktivierung fehlgeschlagen',
  'toast.criticalPermissions.cancelled.title': 'Geplante Aktivierung abgebrochen',
  'toast.criticalPermissions.cancelFailed.title': 'Abbrechen fehlgeschlagen',
  'toast.criticalPermissions.disabled': 'Deaktiviert: {permission}',
  'toast.criticalPermissions.disableFailed.title': 'Deaktivieren fehlgeschlagen',

  // --- settings (fallback error strings) ------------------------------------
  'settings.error.loadFailed': 'Einstellungen konnten nicht geladen werden',
  'settings.error.saveFailed': 'Einstellungen konnten nicht gespeichert werden',
  'settings.error.unexpectedRedirect': 'Unerwartete OAuth-Weiterleitungs-URL.',
  'settings.error.oauthStartFailed': 'OAuth-Vorgang konnte nicht gestartet werden',
  'settings.error.disconnectFailed': 'Trennen fehlgeschlagen',
  'settings.error.resetFailed': 'Ihre Einstellungen konnten nicht zurückgesetzt werden.',

  // --- permissions (fallback error strings, critical permission copy) ------
  'permissions.error.loadFailed': 'Berechtigungen konnten nicht geladen werden',
  'permissions.error.saveFailed': 'Berechtigung konnte nicht gespeichert werden',
  'permissions.critical.gmailSend.label': 'E-Mail senden · Gmail',
  'permissions.critical.outlookSend.label': 'E-Mail senden · Outlook',
  'permissions.critical.googleCalendarUpdate.label': 'Termin aktualisieren · Google Kalender',
  'permissions.critical.outlookCalendarUpdate.label': 'Termin aktualisieren · Outlook-Kalender',
  'permissions.critical.sendEmail.description':
    'Wenn aktiviert, kann der Agent E-Mails entwerfen und vor dem Senden um Ihre Genehmigung bitten.',
  'permissions.critical.updateEvent.description':
    'Wenn aktiviert, kann der Agent Änderungen an bestehenden Terminen zur Genehmigung vorschlagen.',

  // --- criticalPermissions (fallback error string) --------------------------
  'criticalPermissions.error.loadFailed': 'Kritische Berechtigungen konnten nicht geladen werden',
  'criticalPermissions.title': 'Kritische Berechtigungen',
  'criticalPermissions.subtitle':
    'Erlauben Sie dem Agenten, diese Aktionen vorzuschlagen. Sie genehmigen trotzdem jede einzeln, bevor sie ausgeführt wird.',
  'criticalPermissions.activeIn': 'Aktiv in {time}',
  'criticalPermissions.active': 'Aktiv',
  'criticalPermissions.askBeforeEach': 'admino fragt Sie vor jeder Aktion {action}',
  'criticalPermissions.toggle': '{permission} umschalten',
  'criticalPermissions.footer':
    'Das Deaktivieren wirkt sofort. Das Aktivieren erfordert eine erneute Anmeldung und eine Wartezeit von 5 Minuten, die Sie abbrechen können.',

  // --- tools (tool metadata shown on the Permissions page) ------------------
  'tools.gmail.label': 'Gmail',
  'tools.gmail.description': 'Lesen, durchsuchen und aus Ihrem Posteingang senden',
  'tools.gmail.actions.read': 'Eine Nachricht lesen',
  'tools.gmail.actions.list': 'Nachrichten im Posteingang auflisten',
  'tools.gmail.actions.search': 'Nachrichten per Suchanfrage finden',
  'tools.gmail.actions.send': 'Eine E-Mail in Ihrem Namen senden',
  'tools.gmail.actions.delete': 'Einen Thread endgültig löschen',

  'tools.googleCalendar.label': 'Google Kalender',
  'tools.googleCalendar.description': 'Termine lesen, mit Genehmigung erstellen',
  'tools.googleCalendar.actions.read': 'Termindetails anzeigen',
  'tools.googleCalendar.actions.list': 'Anstehende Termine auflisten',
  'tools.googleCalendar.actions.create': 'Einen neuen Termin erstellen',
  'tools.googleCalendar.actions.update': 'Einen bestehenden Termin ändern',
  'tools.googleCalendar.actions.delete': 'Einen Termin entfernen',

  'tools.googleDrive.label': 'Google Drive',
  'tools.googleDrive.description': 'Ihre Drive-Dateien durchsuchen und herunterladen',
  'tools.googleDrive.actions.read': 'Dateiinhalt lesen',
  'tools.googleDrive.actions.list': 'Dateien und Ordner auflisten',
  'tools.googleDrive.actions.search': 'Nach Dateien suchen',
  'tools.googleDrive.actions.download': 'Eine Datei herunterladen',
  'tools.googleDrive.actions.delete': 'Eine Datei löschen',

  'tools.outlook.label': 'Outlook',
  'tools.outlook.description': 'Lesen, durchsuchen und aus Ihrem Postfach senden',
  'tools.outlook.actions.read': 'Eine Nachricht lesen',
  'tools.outlook.actions.list': 'Nachrichten im Posteingang auflisten',
  'tools.outlook.actions.search': 'Nachrichten per Suchanfrage finden',
  'tools.outlook.actions.send': 'Eine E-Mail in Ihrem Namen senden',
  'tools.outlook.actions.delete': 'Eine Nachricht endgültig löschen',

  'tools.outlookCalendar.label': 'Outlook-Kalender',
  'tools.outlookCalendar.description': 'Termine lesen, mit Genehmigung erstellen',
  'tools.outlookCalendar.actions.read': 'Termindetails anzeigen',
  'tools.outlookCalendar.actions.list': 'Anstehende Termine auflisten',
  'tools.outlookCalendar.actions.create': 'Einen neuen Termin erstellen',
  'tools.outlookCalendar.actions.update': 'Einen bestehenden Termin ändern',
  'tools.outlookCalendar.actions.delete': 'Einen Termin entfernen',

  'tools.onedrive.label': 'OneDrive',
  'tools.onedrive.description': 'Ihre OneDrive-Dateien durchsuchen und herunterladen',
  'tools.onedrive.actions.read': 'Dateiinhalt lesen',
  'tools.onedrive.actions.list': 'Dateien und Ordner auflisten',
  'tools.onedrive.actions.search': 'Nach Dateien suchen',
  'tools.onedrive.actions.download': 'Eine Datei herunterladen',
  'tools.onedrive.actions.delete': 'Eine Datei löschen',

  'tools.memory.label': 'Gedächtnis',
  'tools.memory.description': 'Langzeitspeicher für Schlüssel-Wert-Paare',
  'tools.memory.actions.get': 'Einen gespeicherten Wert abrufen',
  'tools.memory.actions.set': 'Ein Schlüssel-Wert-Paar speichern',
  'tools.memory.actions.list': 'Alle gespeicherten Schlüssel auflisten',
  'tools.memory.actions.delete': 'Einen gespeicherten Schlüssel löschen',

  'tools.database.label': 'Datenbank',
  'tools.database.description': 'Zugriff auf die Anwendungsdatenbank',
  'tools.database.actions.query': 'Eine lesende Abfrage ausführen',

  // --- chat page (empty state, suggestions, input bar) -------------------
  'chat.empty.heading': 'Wie kann ich helfen?',
  'chat.empty.subtext': 'Standardmässig antwortet die in der Schweiz gehostete KI von Infomaniak.',
  'chat.suggestions.searchEmails': 'Meine E-Mails durchsuchen',
  'chat.suggestions.calendarToday': 'Was steht heute in meinem Kalender?',
  'chat.suggestions.findFile': 'Eine Datei finden',
  'chat.input.attachFile': 'Datei anhängen',
  'chat.input.placeholder': 'Fragen Sie admino etwas…',
  'chat.input.send': 'Senden',

  // --- toolCall (tool-call card and chip) --------------------------------
  'toolCall.approve': 'Genehmigen',
  'toolCall.deny': 'Ablehnen',
  'toolCall.resultCount': {
    one: '{count} Ergebnis',
    other: '{count} Ergebnisse',
  },
  'toolCall.hideDetails': 'Ausblenden',
  'toolCall.showDetails': 'Details',
  'toolCall.state.pending': 'ausstehend',
  'toolCall.state.approved': 'genehmigt',
  'toolCall.state.denied': 'abgelehnt',
  'toolCall.state.completed': 'abgeschlossen',
  'toolCall.state.error': 'Fehler',

  // --- statusBadge (tool-call and permission status badge) ---------------
  'statusBadge.approved': 'Genehmigt',
  'statusBadge.denied': 'Abgelehnt',
  'statusBadge.pending': 'Wartet auf Genehmigung',
  'statusBadge.hardcodedDeny': 'Fest gesperrt',
  'statusBadge.allowed': 'Erlaubt',
  'statusBadge.confirm': 'Genehmigung erforderlich',

  // --- permissionState (permission pill and Permissions page filters) ----
  'permissionState.allow': 'Erlaubt',
  'permissionState.confirm': 'Genehmigung nötig',
  'permissionState.deny': 'Abgelehnt',
  'permissionPill.promotableHint':
    'Diese Berechtigung kann unter Einstellungen › Gefahrenzone verwaltet werden',
  'permissionPill.hardcodedHint':
    'Diese Berechtigung ist durch die Sicherheitsrichtlinie festgelegt und kann nicht geändert werden',

  // --- permissions page (header, filters, per-tool summary chips) --------
  'permissions.page.toolCount': {
    one: '{count} Tool',
    other: '{count} Tools',
  },
  'permissions.page.actionCount': {
    one: '{count} Aktion',
    other: '{count} Aktionen',
  },
  'permissions.page.loading': 'Berechtigungen werden geladen...',
  'permissions.filter.all': 'Alle',
  'permissions.summary.allowed': {
    one: '{n} erlaubt',
    other: '{n} erlaubt',
  },
  'permissions.summary.approval': {
    one: '{n} Genehmigung',
    other: '{n} Genehmigungen',
  },
  'permissions.summary.denied': {
    one: '{n} abgelehnt',
    other: '{n} abgelehnt',
  },

  // --- toolsPage (connected accounts, local tools, OAuth callback) -------
  'toolsPage.accounts.title': 'Verbundene Konten',
  'toolsPage.accounts.subtitle':
    'Verbinden Sie einen Anbieter einmal. Einzelne Dienste können Sie jederzeit ein- und ausschalten.',
  'toolsPage.status.connected': 'Verbunden',
  'toolsPage.status.notConnected': 'Nicht verbunden',
  'toolsPage.google.connectHint': 'Verbinden, um Gmail, Google Kalender und Google Drive zu nutzen.',
  'toolsPage.microsoft.connectHint': 'Verbinden, um Outlook Mail, Outlook-Kalender und OneDrive zu nutzen.',
  'toolsPage.connect': 'Verbinden',
  'toolsPage.disconnect': 'Trennen',
  'toolsPage.service.outlookMail': 'Outlook Mail',
  'toolsPage.local.title': 'Lokale Tools',
  'toolsPage.local.subtitle': 'Tools, die auf Ihrem admino-Server laufen. Kein externes Konto nötig.',
  'toolsPage.memory.description': 'Dauerhafte Schlüssel-Wert-Notizen',
  'toolsPage.disconnectConfirm.heading': '{provider} trennen?',
  'toolsPage.disconnectConfirm.subtext':
    'Dadurch wird das OAuth-Refresh-Token widerrufen. Sie können sich jederzeit wieder verbinden.',
  'toolsPage.oauth.connected.title': 'Konto verbunden',
  'toolsPage.oauth.connected.body': 'Ihr Konto wurde erfolgreich verknüpft.',
  'toolsPage.oauth.reason.denied': 'Sie haben die Zustimmung abgelehnt.',
  'toolsPage.oauth.reason.invalidState': 'Sitzung abgelaufen. Bitte versuchen Sie es erneut.',
  'toolsPage.oauth.reason.missingCode': 'Kein Autorisierungscode erhalten.',
  'toolsPage.oauth.reason.exchangeFailed':
    'Token-Austausch fehlgeschlagen. Prüfen Sie die OAuth-Zugangsdaten.',
  'toolsPage.oauth.reason.unexpected': 'Ein unerwarteter Fehler ist aufgetreten.',

  // --- settings page (subnav, sections, danger zone) ---------------------
  'settings.loadingLabel': 'Einstellungen werden geladen',
  'settings.error.loadBanner': 'Einstellungen konnten nicht geladen werden: {error}',
  'settings.soonBadge': 'Bald',
  'settings.nav.group.account': 'Konto',
  'settings.nav.group.app': 'App',
  'settings.nav.group.system': 'System',
  'settings.nav.session': 'Sitzung',
  'settings.nav.appearance': 'Darstellung',
  'settings.nav.notifications': 'Benachrichtigungen',
  'settings.nav.about': 'Über',
  'settings.nav.danger': 'Gefahrenzone',
  'settings.session.subtitle': 'Identifiziert diesen Gesprächsverlauf im admino-Backend.',
  'settings.session.id.label': 'Sitzungs-ID',
  'settings.session.id.hint': 'Buchstaben, Ziffern, Bindestriche, Unterstriche. Max. 64 Zeichen.',
  'settings.session.new.label': 'Neue Sitzung',
  'settings.session.new.hint': 'Leert den Chatverlauf.',
  'settings.appearance.subtitle': 'So sieht die Oberfläche aus. Änderungen gelten sofort.',
  'settings.appearance.theme.label': 'Design',
  'settings.appearance.theme.hint': 'Der dunkle Modus ist für v2 geplant.',
  'settings.appearance.theme.light': 'Hell',
  'settings.appearance.theme.dark': 'Dunkel',
  'settings.appearance.theme.system': 'System',
  'settings.notifications.subtitle': 'Hinweise in der App. Browser-Push aktivieren Sie einmal pro Gerät.',
  'settings.notifications.approval.label': 'Hinweise zu Tool-Genehmigungen',
  'settings.notifications.approval.hint':
    'Benachrichtigen, wenn admino meine Genehmigung für ein Tool braucht.',
  'settings.notifications.taskDone.label': 'Hinweise zu erledigten Aufgaben',
  'settings.notifications.taskDone.hint': 'Benachrichtigen, wenn eine länger dauernde Antwort bereit ist.',
  'settings.about.subtitle':
    'Ein datenschutz- und sicherheitsorientierter persönlicher KI-Agent, den Sie selbst betreiben – standardmässig mit der in der Schweiz gehosteten KI von Infomaniak.',
  'settings.about.version': 'Version',
  'settings.about.versionValue': 'admino {version} (Alpha)',
  'settings.about.sourceCode': 'Quellcode',
  'settings.about.license': 'Lizenz',
  'settings.danger.subtitle':
    'Diese Aktionen können nicht rückgängig gemacht werden. Jede verlangt eine Bestätigung.',
  'settings.danger.reset.label': 'Meine Einstellungen zurücksetzen',
  'settings.danger.reset.hint':
    'Setzt Ihr Design und Ihre Benachrichtigungen auf die Standardwerte zurück. Verbundene Konten, Sprachen und Organisationseinstellungen bleiben unverändert.',
  'settings.danger.reset.button': 'Auf Standard zurücksetzen',
  'settings.danger.resetConfirm.heading': 'Einstellungen zurücksetzen?',
  'settings.danger.resetConfirm.subtext':
    'Das Design wird wieder hell, Hinweise zu Tool-Genehmigungen werden eingeschaltet und Hinweise zu erledigten Aufgaben ausgeschaltet. Verbundene Konten, Sprachen und Organisationseinstellungen bleiben unverändert.',
  'settings.danger.resetConfirm.confirm': 'Zurücksetzen',
  'settings.toast.newSession': 'Neue Sitzung gestartet',
  'settings.session.logout.label': 'Abmelden',
  'settings.session.logout.hint': 'Beendet Ihre Sitzung auf diesem Gerät.',

  // --- auth (session-expired toast, error copy, issue #155) --------------
  'auth.sessionExpired.title': 'Sitzung abgelaufen',
  'auth.sessionExpired.body': 'Bitte melden Sie sich erneut an.',
  'auth.login.error.invalid': 'E-Mail oder Passwort ungültig',
  'auth.error.rateLimited': 'Zu viele Versuche. Bitte warten Sie einen Moment und versuchen Sie es erneut.',
  'auth.error.generic': 'Etwas ist schiefgelaufen. Bitte versuchen Sie es erneut.',
  'auth.reset.error.invalidLink': 'Dieser Link zum Zurücksetzen ist ungültig oder abgelaufen.',
  'auth.invitation.error.invalidLink': 'Dieser Einladungslink ist ungültig oder abgelaufen.',
  'auth.invitation.error.invalidName': 'Bitte geben Sie Ihren Namen ein.',

  // --- auth.password (password policy, issue #155) -----------------------
  'auth.password.error.tooShort': 'Das Passwort ist zu kurz.',
  'auth.password.error.tooLong': 'Das Passwort ist zu lang.',
  'auth.password.error.common': 'Dieses Passwort ist zu gebräuchlich.',
  'auth.password.error.equalsEmail': 'Das Passwort darf nicht Ihrer E-Mail-Adresse entsprechen.',
  'auth.password.error.mismatch': 'Die Passwörter stimmen nicht überein.',
  'auth.password.error.generic': 'Dieses Passwort erfüllt die Anforderungen nicht.',
  'auth.password.rule.length': 'Zwischen {min} und {max} Zeichen.',
  'auth.password.rule.common': 'Kein häufig verwendetes Passwort.',
  'auth.password.rule.email': 'Nicht identisch mit Ihrer E-Mail-Adresse.',

  // --- auth.role (invited role, shown on the Accept invitation page) -----
  'auth.role.orgAdmin': 'Organisations-Admin',
  'auth.role.editor': 'Bearbeiter',
  'auth.role.viewer': 'Betrachter',

  // --- auth.login (Login page) --------------------------------------------
  'auth.login.title': 'Anmelden',
  'auth.login.email.label': 'E-Mail',
  'auth.login.password.label': 'Passwort',
  'auth.login.submit': 'Anmelden',
  'auth.login.forgotPassword': 'Passwort vergessen?',

  // --- auth.forgotPassword (Forgot password page) -------------------------
  'auth.forgotPassword.title': 'Passwort vergessen',
  'auth.forgotPassword.subtitle':
    'Geben Sie Ihre E-Mail-Adresse ein, wir senden Ihnen einen Link zum Zurücksetzen.',
  'auth.forgotPassword.email.label': 'E-Mail',
  'auth.forgotPassword.submit': 'Link senden',
  'auth.forgotPassword.success':
    'Falls für diese Adresse ein Konto besteht, haben wir einen Link zum Zurücksetzen gesendet. Er ist 30 Minuten gültig.',
  'auth.forgotPassword.backToLogin': 'Zurück zur Anmeldung',

  // --- auth.reset (Reset password page) ------------------------------------
  'auth.reset.title': 'Passwort zurücksetzen',
  'auth.reset.invalidLink.heading': 'Dieser Link ist ungültig oder abgelaufen.',
  'auth.reset.invalidLink.cta': 'Neuen Link anfordern',
  'auth.reset.password.label': 'Neues Passwort',
  'auth.reset.confirm.label': 'Neues Passwort bestätigen',
  'auth.reset.submit': 'Passwort ändern',
  'auth.reset.success': 'Passwort geändert. Melden Sie sich mit Ihrem neuen Passwort an.',

  // --- auth.invitation (Accept invitation page) ----------------------------
  'auth.invitation.title': 'Einladung annehmen',
  'auth.invitation.invalidLink.heading': 'Dieser Einladungslink ist ungültig oder abgelaufen.',
  'auth.invitation.org.label': 'Organisation',
  'auth.invitation.role.label': 'Rolle',
  'auth.invitation.email.label': 'E-Mail',
  'auth.invitation.name.label': 'Vollständiger Name',
  'auth.invitation.password.label': 'Passwort',
  'auth.invitation.confirm.label': 'Passwort bestätigen',
  'auth.invitation.submit': 'Einladung annehmen',

  // --- organization page (placeholder, issue #155) --------------------------
  'organization.empty.heading': 'Organisation',
  'organization.empty.subtext':
    'Benutzerverwaltung und Organisationseinstellungen werden hier erscheinen.',

  // --- platform page (placeholder, Super Admin console, issue #155) ---------
  'platform.empty.heading': 'Plattform-Konsole',
  'platform.empty.subtext': 'Die Plattform-Konsole wird hier erscheinen.',

  // --- chat page (read-only viewer, issue #155) -----------------------------
  'chat.viewerEmpty.heading': 'Noch nichts mit Ihnen geteilt',
  'chat.viewerEmpty.subtext': 'Projekte, die andere mit Ihnen teilen, erscheinen hier.',
};
