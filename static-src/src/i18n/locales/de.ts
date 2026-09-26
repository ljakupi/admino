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

  // --- nav (top-level page navigation, issue #15) ----------------------
  'nav.chat': 'Chat',
  'nav.tools': 'Tools',
  'nav.permissions': 'Berechtigungen',
  'nav.settings': 'Einstellungen',
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
  'toast.chat.authRequired': 'Authentifizierung erforderlich',
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

  // --- toast (critical permissions store) ---------------------------------
  'toast.criticalPermissions.promotionScheduled.title': 'Aktivierung geplant',
  'toast.criticalPermissions.promotionScheduled.body': 'Aktiv in {time}',
  'toast.criticalPermissions.authFailed.title': 'Authentifizierung fehlgeschlagen',
  'toast.criticalPermissions.authFailed.body': 'Das eingegebene Token ist ungültig.',
  'toast.criticalPermissions.promotionFailed.title': 'Aktivierung fehlgeschlagen',
  'toast.criticalPermissions.cancelled.title': 'Geplante Aktivierung abgebrochen',
  'toast.criticalPermissions.cancelFailed.title': 'Abbrechen fehlgeschlagen',
  'toast.criticalPermissions.disabled': 'Deaktiviert: {permission}',
  'toast.criticalPermissions.disableFailed.title': 'Deaktivieren fehlgeschlagen',

  // --- settings (fallback error strings, agent trust note) -----------------
  'settings.error.loadFailed': 'Einstellungen konnten nicht geladen werden',
  'settings.error.saveFailed': 'Einstellungen konnten nicht gespeichert werden',
  'settings.error.unexpectedRedirect': 'Unerwartete OAuth-Weiterleitungs-URL.',
  'settings.error.oauthStartFailed': 'OAuth-Vorgang konnte nicht gestartet werden',
  'settings.error.disconnectFailed': 'Trennen fehlgeschlagen',
  'settings.agent.trustNote':
    'Einstellungen, Audit-Log und Gedächtnis werden auf Ihrem admino-Server gespeichert. Nur {provider} verarbeitet die Konversationsinhalte.',

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

  // --- auth (access-token dialog) ----------------------------------------
  'auth.welcome': 'Willkommen',
  'auth.intro':
    'Geben Sie Ihr Zugriffstoken ein, um sich zu verbinden, oder überspringen Sie diesen Schritt in einem privaten Netzwerk.',
  'auth.tokenLabel': 'Zugriffstoken',
  'auth.tokenPlaceholder': 'Token einfügen',
  'auth.skip': 'Überspringen',
  'auth.connect': 'Verbinden',
  'auth.error.tokenRequired': 'Token ist erforderlich',
  'auth.error.tokenFormat': 'Das Token muss aus 8–512 druckbaren ASCII-Zeichen bestehen',
  'auth.error.invalidToken': 'Ungültiges Token. Bitte prüfen und erneut versuchen.',
  'auth.error.tokenRequiredByServer': 'Dieser Server erfordert ein Token. Überspringen ist nicht möglich.',

  // --- reauth (re-authentication dialog for critical permissions) --------
  'reauth.title': 'Zum Aktivieren erneut anmelden',
  'reauth.body':
    'Sie erlauben admino, {action} für {tool} vorzuschlagen. Geben Sie zur Bestätigung Ihr Auth-Token ein. Die Änderung wird nach einer Wartezeit von 5 Minuten wirksam, die Sie abbrechen können.',
  'reauth.tokenLabel': 'Auth-Token',
  'reauth.tokenPlaceholder': 'Bearer-Token erneut eingeben',
  'reauth.tokenHint': 'Wird nie protokolliert. Wird gegen Ihre aktive Sitzung geprüft.',
  'reauth.submit': 'Aktivieren & Wartezeit starten',

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
  'settings.nav.agent': 'Agent',
  'settings.nav.appearance': 'Darstellung',
  'settings.nav.notifications': 'Benachrichtigungen',
  'settings.nav.about': 'Über',
  'settings.nav.danger': 'Gefahrenzone',
  'settings.session.subtitle': 'Identifiziert diesen Gesprächsverlauf im admino-Backend.',
  'settings.session.token.label': 'Bearer-Token',
  'settings.session.token.hint': 'Nur erforderlich, wenn der Server mit {config} läuft.',
  'settings.session.token.placeholder': 'Bearer-Token eingeben',
  'settings.session.id.label': 'Sitzungs-ID',
  'settings.session.id.hint': 'Buchstaben, Ziffern, Bindestriche, Unterstriche. Max. 64 Zeichen.',
  'settings.session.new.label': 'Neue Sitzung',
  'settings.session.new.hint': 'Leert den Chatverlauf.',
  'settings.agent.subtitle':
    'Mit welchem LLM admino arbeitet. Infomaniak ist der Standard; vLLM (lokaler CPU-Container), Claude und OpenAI sind optionale Alternativen.',
  'settings.agent.provider.label': 'Anbieter',
  'settings.agent.provider.hint':
    'Infomaniak, Claude und OpenAI senden Ihre Nachrichten zur Verarbeitung an ihre Server. vLLM ist eine lokale, optionale Alternative, die Sie selbst betreiben.',
  'settings.agent.model.label': 'Modell',
  'settings.agent.model.placeholder': 'z. B. {example}',
  'settings.agent.model.emptyError': 'Der Modellname darf nicht leer sein',
  'settings.agent.model.exactIdHint': 'Exakte Modell-ID, z. B. {example}. Siehe {link}.',
  'settings.agent.anthropic.modelList': 'Modellliste von Anthropic',
  'settings.agent.openai.modelList': 'Modellliste von OpenAI',
  'settings.agent.infomaniak.noModels':
    'Keine Modelle aufgelistet – setzen Sie {env} auf dem Server, um sie zu laden.',
  'settings.agent.infomaniak.privacy':
    'Verarbeitung in der Schweiz; Anfragen werden weder gespeichert noch für Training verwendet (Infomaniak).',
  'settings.agent.vllm.noModels':
    'Kein bereitgestelltes Modell erkannt – der lokale vLLM-Container ist optional: Starten Sie ihn mit {cmd}.',
  'settings.agent.vllm.modelHint':
    'Die HuggingFace-Repo-ID des Modells, das der lokale vLLM-CPU-Container bereitstellt.',
  'settings.agent.apiToken.label': 'API-Token',
  'settings.agent.apiKey.label': 'API-Schlüssel',
  'settings.agent.secretHint':
    '{env} · Wird auf dem Server als Umgebungsvariable gesetzt. Nie an Ihren Browser gesendet.',
  'settings.agent.secret.configured': 'Konfiguriert',
  'settings.agent.secret.notConfigured': 'Nicht konfiguriert',
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
  'settings.notifications.sound.label': 'Ton',
  'settings.notifications.sound.hint':
    'Dezenter Ton bei Hinweisen. Beachtet den Modus «Nicht stören» des Systems.',
  'settings.about.subtitle':
    'Ein datenschutz- und sicherheitsorientierter persönlicher KI-Agent, den Sie selbst betreiben – standardmässig mit der in der Schweiz gehosteten KI von Infomaniak.',
  'settings.about.version': 'Version',
  'settings.about.versionValue': 'admino {version} (Alpha)',
  'settings.about.sourceCode': 'Quellcode',
  'settings.about.license': 'Lizenz',
  'settings.about.trustTitle': 'Ihr admino-Server',
  'settings.danger.subtitle':
    'Diese Aktionen können nicht rückgängig gemacht werden. Jede verlangt eine Bestätigung.',
  'settings.danger.clear.label': 'Gespräch leeren',
  'settings.danger.clear.hint': 'Löscht den aktuellen Chatverlauf. Das Audit-Log bleibt bewusst erhalten.',
  'settings.danger.clear.button': 'Verlauf leeren',
  'settings.danger.disconnectAll.label': 'Alle Konten trennen',
  'settings.danger.disconnectAll.hint': 'Widerruft die OAuth-Refresh-Tokens für Google und Microsoft.',
  'settings.danger.disconnectAll.button': 'Alle trennen',
  'settings.danger.reset.label': 'Einstellungen zurücksetzen',
  'settings.danger.reset.hint':
    'Setzt alle Einstellungen auf die Standardwerte zurück. Verbundene Konten bleiben verbunden.',
  'settings.danger.reset.button': 'Auf Standard zurücksetzen',
  'settings.danger.erase.label': 'Alle Daten löschen',
  'settings.danger.erase.hint':
    'Löscht Audit-Log, Gedächtnis und Dokumentenspeicher. Nicht wiederherstellbar.',
  'settings.danger.erase.button': 'Alles löschen',
  'settings.danger.clearConfirm.heading': 'Gespräch leeren?',
  'settings.danger.clearConfirm.subtext':
    'Dadurch werden alle Nachrichten und der Tool-Aufrufverlauf der aktuellen Sitzung entfernt.',
  'settings.danger.clearConfirm.confirm': 'Leeren',
  'settings.toast.tokenSaved': 'Token gespeichert',
  'settings.toast.chatCleared': 'Chat geleert',
  'settings.toast.newSession': 'Neue Sitzung gestartet',
  'settings.comingSoon.title': 'Demnächst verfügbar',
  'settings.comingSoon.resetSettings': 'Das Zurücksetzen der Einstellungen ist noch nicht verfügbar.',
  'settings.comingSoon.eraseAll': 'Das Löschen aller Daten ist noch nicht verfügbar.',
  'settings.comingSoon.toggle': 'Dieser Schalter ist noch nicht verfügbar.',
};
