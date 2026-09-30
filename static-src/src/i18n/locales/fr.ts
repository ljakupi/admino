/**
 * French catalog (Swiss French; issue #144: PWA internationalization).
 *
 * Translates every key of `en` (the source catalog) with identical
 * `{placeholder}` names. Formal "vous" throughout. `npm run check:i18n`
 * enforces the key/placeholder parity with `en` and `de`.
 */
import type { Message } from '../core';
import type { MessageKey } from '../index';

export const fr: Record<MessageKey, Message> = {
  // --- common ---------------------------------------------------------
  'common.dismiss': 'Fermer',
  'common.retry': 'Réessayer',
  'common.cancel': 'Annuler',
  'common.confirm': 'Confirmer',
  'common.loading': 'Chargement',

  // --- nav (top-level page navigation, issue #15; issue #155: role-aware shell) ---
  'nav.chat': 'Discussion',
  'nav.tools': 'Outils',
  'nav.permissions': 'Autorisations',
  'nav.organization': 'Organisation',
  'nav.settings': 'Paramètres',
  'nav.platform': 'Plateforme',
  'nav.logout': 'Se déconnecter',
  'nav.mainNavigation': 'Navigation principale',

  // --- status (connection state pill) ----------------------------------
  'status.idle': 'Prêt',
  'status.working': 'En cours…',
  'status.awaiting': 'En attente de vous',
  'status.offline': 'Hors ligne',

  // --- connection (offline banner) --------------------------------------
  'connection.offlineMessage':
    'admino ne parvient pas à joindre le backend LLM. Vérifiez la configuration de votre fournisseur.',

  // --- chat (chat header, thinking indicator, tool-call state) ---------
  'chat.thinking': 'admino travaille…',
  'chat.header.clearChat': 'Effacer la discussion',
  'chat.header.menu': 'Menu',
  'chat.toolCall.expired': 'Expiré',

  // --- toast (shared) ----------------------------------------------------
  'toast.common.saved': 'Enregistré',
  'toast.common.saveFailed.title': "Échec de l'enregistrement",

  // --- toast (chat store) ------------------------------------------------
  'toast.chat.slowDown.title': 'Ralentissez',
  'toast.chat.slowDown.body': 'admino est actuellement limité en débit.',
  'toast.chat.genericError.title': 'Un problème est survenu',
  'toast.chat.genericError.body': 'Consultez les journaux du serveur.',
  'toast.chat.connectionLost.title': 'Connexion perdue',
  'toast.chat.connectionLost.body': 'Impossible de joindre le serveur.',
  'toast.chat.approvalExpired.title': 'Approbation expirée',
  'toast.chat.approvalExpired.body': 'Renvoyez le message.',
  'toast.chat.alreadyExpired': 'Déjà expiré',

  // --- toast (settings store) --------------------------------------------
  'toast.settings.connectionFailed.title': 'Connexion échouée',
  'toast.settings.googleDisconnected': 'Google déconnecté',
  'toast.settings.microsoftDisconnected': 'Microsoft déconnecté',
  'toast.settings.disconnectFailed.title': 'Déconnexion échouée',

  // --- toast (critical permissions store) ---------------------------------
  'toast.criticalPermissions.promotionScheduled.title': 'Activation planifiée',
  'toast.criticalPermissions.promotionScheduled.body': 'Actif dans {time}',
  'toast.criticalPermissions.promotionFailed.title': "Échec de l'activation",
  'toast.criticalPermissions.cancelled.title': 'Activation planifiée annulée',
  'toast.criticalPermissions.cancelFailed.title': "Échec de l'annulation",
  'toast.criticalPermissions.disabled': 'Désactivé : {permission}',
  'toast.criticalPermissions.disableFailed.title': 'Échec de la désactivation',

  // --- settings (fallback error strings) ------------------------------------
  'settings.error.loadFailed': 'Impossible de charger les paramètres',
  'settings.error.saveFailed': "Impossible d'enregistrer les paramètres",
  'settings.error.unexpectedRedirect': 'URL de redirection OAuth inattendue.',
  'settings.error.oauthStartFailed': 'Impossible de démarrer le processus OAuth',
  'settings.error.disconnectFailed': 'Échec de la déconnexion',

  // --- permissions (fallback error strings, critical permission copy) ------
  'permissions.error.loadFailed': 'Impossible de charger les autorisations',
  'permissions.error.saveFailed': "Impossible d'enregistrer l'autorisation",
  'permissions.critical.gmailSend.label': 'Envoyer un e-mail · Gmail',
  'permissions.critical.outlookSend.label': 'Envoyer un e-mail · Outlook',
  'permissions.critical.googleCalendarUpdate.label': 'Modifier un événement · Google Agenda',
  'permissions.critical.outlookCalendarUpdate.label': 'Modifier un événement · Calendrier Outlook',
  'permissions.critical.sendEmail.description':
    "Une fois activé, l'agent peut rédiger des e-mails et demander votre approbation avant de les envoyer.",
  'permissions.critical.updateEvent.description':
    "Une fois activé, l'agent peut proposer des modifications à des événements existants, soumises à votre approbation.",

  // --- criticalPermissions (fallback error string) --------------------------
  'criticalPermissions.error.loadFailed': 'Impossible de charger les autorisations critiques',
  'criticalPermissions.title': 'Autorisations critiques',
  'criticalPermissions.subtitle':
    "Autorisez l'agent à proposer ces actions. Vous approuverez toujours chacune d'elles avant son exécution.",
  'criticalPermissions.activeIn': 'Actif dans {time}',
  'criticalPermissions.active': 'Actif',
  'criticalPermissions.askBeforeEach': 'admino vous demandera avant chaque action {action}',
  'criticalPermissions.toggle': 'Basculer {permission}',
  'criticalPermissions.footer':
    "La désactivation prend effet immédiatement. L'activation nécessite une réauthentification et un délai de 5 minutes que vous pouvez annuler.",

  // --- tools (tool metadata shown on the Permissions page) ------------------
  'tools.gmail.label': 'Gmail',
  'tools.gmail.description': 'Lire, rechercher et envoyer depuis votre boîte de réception',
  'tools.gmail.actions.read': "Lire le contenu d'un message",
  'tools.gmail.actions.list': 'Lister les messages de la boîte de réception',
  'tools.gmail.actions.search': 'Rechercher des messages par requête',
  'tools.gmail.actions.send': 'Envoyer un e-mail en votre nom',
  'tools.gmail.actions.delete': 'Supprimer définitivement une conversation',

  'tools.googleCalendar.label': 'Google Agenda',
  'tools.googleCalendar.description': 'Lire les événements, créer avec approbation',
  'tools.googleCalendar.actions.read': "Afficher les détails d'un événement",
  'tools.googleCalendar.actions.list': 'Lister les événements à venir',
  'tools.googleCalendar.actions.create': 'Créer un nouvel événement',
  'tools.googleCalendar.actions.update': 'Modifier un événement existant',
  'tools.googleCalendar.actions.delete': 'Supprimer un événement',

  'tools.googleDrive.label': 'Google Drive',
  'tools.googleDrive.description': 'Rechercher et télécharger vos fichiers Drive',
  'tools.googleDrive.actions.read': 'Lire le contenu du fichier',
  'tools.googleDrive.actions.list': 'Lister les fichiers et dossiers',
  'tools.googleDrive.actions.search': 'Rechercher des fichiers',
  'tools.googleDrive.actions.download': 'Télécharger un fichier',
  'tools.googleDrive.actions.delete': 'Supprimer un fichier',

  'tools.outlook.label': 'Outlook',
  'tools.outlook.description': 'Lire, rechercher et envoyer depuis votre messagerie',
  'tools.outlook.actions.read': "Lire le contenu d'un message",
  'tools.outlook.actions.list': 'Lister les messages de la boîte de réception',
  'tools.outlook.actions.search': 'Rechercher des messages par requête',
  'tools.outlook.actions.send': 'Envoyer un e-mail en votre nom',
  'tools.outlook.actions.delete': 'Supprimer définitivement un message',

  'tools.outlookCalendar.label': 'Calendrier Outlook',
  'tools.outlookCalendar.description': 'Lire les événements, créer avec approbation',
  'tools.outlookCalendar.actions.read': "Afficher les détails d'un événement",
  'tools.outlookCalendar.actions.list': 'Lister les événements à venir',
  'tools.outlookCalendar.actions.create': 'Créer un nouvel événement',
  'tools.outlookCalendar.actions.update': 'Modifier un événement existant',
  'tools.outlookCalendar.actions.delete': 'Supprimer un événement',

  'tools.onedrive.label': 'OneDrive',
  'tools.onedrive.description': 'Rechercher et télécharger vos fichiers OneDrive',
  'tools.onedrive.actions.read': 'Lire le contenu du fichier',
  'tools.onedrive.actions.list': 'Lister les fichiers et dossiers',
  'tools.onedrive.actions.search': 'Rechercher des fichiers',
  'tools.onedrive.actions.download': 'Télécharger un fichier',
  'tools.onedrive.actions.delete': 'Supprimer un fichier',

  'tools.memory.label': 'Mémoire',
  'tools.memory.description': 'Stockage clé-valeur à long terme',
  'tools.memory.actions.get': 'Récupérer une valeur stockée',
  'tools.memory.actions.set': 'Stocker une paire clé-valeur',
  'tools.memory.actions.list': 'Lister toutes les clés stockées',
  'tools.memory.actions.delete': 'Supprimer une clé stockée',

  'tools.database.label': 'Base de données',
  'tools.database.description': "Accès à la base de données de l'application",
  'tools.database.actions.query': 'Exécuter une requête en lecture seule',

  // --- chat page (empty state, suggestions, input bar) -------------------
  'chat.empty.heading': 'Comment puis-je vous aider?',
  'chat.empty.subtext': "Par défaut, les réponses proviennent de l'IA d'Infomaniak hébergée en Suisse.",
  'chat.suggestions.searchEmails': 'Rechercher dans mes e-mails',
  'chat.suggestions.calendarToday': "Qu'y a-t-il dans mon agenda aujourd'hui?",
  'chat.suggestions.findFile': 'Trouver un fichier',
  'chat.input.attachFile': 'Joindre un fichier',
  'chat.input.placeholder': 'Posez une question à admino…',
  'chat.input.send': 'Envoyer',

  // --- toolCall (tool-call card and chip) --------------------------------
  'toolCall.approve': 'Approuver',
  'toolCall.deny': 'Refuser',
  'toolCall.resultCount': {
    one: '{count} résultat',
    other: '{count} résultats',
  },
  'toolCall.hideDetails': 'Masquer',
  'toolCall.showDetails': 'Détails',
  'toolCall.state.pending': 'en attente',
  'toolCall.state.approved': 'approuvé',
  'toolCall.state.denied': 'refusé',
  'toolCall.state.completed': 'terminé',
  'toolCall.state.error': 'erreur',

  // --- statusBadge (tool-call and permission status badge) ---------------
  'statusBadge.approved': 'Approuvé',
  'statusBadge.denied': 'Refusé',
  'statusBadge.pending': "En attente d'approbation",
  'statusBadge.hardcodedDeny': 'Refus imposé',
  'statusBadge.allowed': 'Autorisé',
  'statusBadge.confirm': 'Approbation requise',

  // --- permissionState (permission pill and Permissions page filters) ----
  'permissionState.allow': 'Autorisé',
  'permissionState.confirm': 'Approbation requise',
  'permissionState.deny': 'Refusé',
  'permissionPill.promotableHint': 'Cette autorisation peut être gérée dans Paramètres › Zone de danger',
  'permissionPill.hardcodedHint':
    'Cette autorisation est imposée par la politique de sécurité et ne peut pas être modifiée',

  // --- permissions page (header, filters, per-tool summary chips) --------
  'permissions.page.toolCount': {
    one: '{count} outil',
    other: '{count} outils',
  },
  'permissions.page.actionCount': {
    one: '{count} action',
    other: '{count} actions',
  },
  'permissions.page.loading': 'Chargement des autorisations...',
  'permissions.filter.all': 'Toutes',
  'permissions.summary.allowed': {
    one: '{n} autorisée',
    other: '{n} autorisées',
  },
  'permissions.summary.approval': {
    one: '{n} approbation',
    other: '{n} approbations',
  },
  'permissions.summary.denied': {
    one: '{n} refusée',
    other: '{n} refusées',
  },

  // --- toolsPage (connected accounts, local tools, OAuth callback) -------
  'toolsPage.accounts.title': 'Comptes connectés',
  'toolsPage.accounts.subtitle':
    'Connectez un fournisseur une seule fois. Activez ou désactivez chaque service à tout moment.',
  'toolsPage.status.connected': 'Connecté',
  'toolsPage.status.notConnected': 'Non connecté',
  'toolsPage.google.connectHint': 'Connectez-vous pour utiliser Gmail, Google Agenda et Google Drive.',
  'toolsPage.microsoft.connectHint':
    'Connectez-vous pour utiliser Outlook Mail, Calendrier Outlook et OneDrive.',
  'toolsPage.connect': 'Connecter',
  'toolsPage.disconnect': 'Déconnecter',
  'toolsPage.service.outlookMail': 'Outlook Mail',
  'toolsPage.local.title': 'Outils locaux',
  'toolsPage.local.subtitle':
    'Outils qui fonctionnent sur votre serveur admino. Aucun compte externe requis.',
  'toolsPage.memory.description': 'Notes clé-valeur persistantes',
  'toolsPage.disconnectConfirm.heading': 'Déconnecter {provider}?',
  'toolsPage.disconnectConfirm.subtext':
    "Le jeton d'actualisation OAuth sera révoqué. Vous pouvez vous reconnecter à tout moment.",
  'toolsPage.oauth.connected.title': 'Compte connecté',
  'toolsPage.oauth.connected.body': 'Votre compte a été associé avec succès.',
  'toolsPage.oauth.reason.denied': "Vous avez refusé l'écran de consentement.",
  'toolsPage.oauth.reason.invalidState': 'Session expirée. Veuillez réessayer.',
  'toolsPage.oauth.reason.missingCode': "Aucun code d'autorisation reçu.",
  'toolsPage.oauth.reason.exchangeFailed': "Échec de l'échange de jetons. Vérifiez les identifiants OAuth.",
  'toolsPage.oauth.reason.unexpected': 'Une erreur inattendue est survenue.',

  // --- settings page (subnav, sections, danger zone) ---------------------
  'settings.loadingLabel': 'Chargement des paramètres',
  'settings.error.loadBanner': 'Impossible de charger les paramètres : {error}',
  'settings.soonBadge': 'Bientôt',
  'settings.nav.group.account': 'Compte',
  'settings.nav.group.app': 'Application',
  'settings.nav.group.system': 'Système',
  'settings.nav.session': 'Session',
  'settings.nav.appearance': 'Apparence',
  'settings.nav.notifications': 'Notifications',
  'settings.nav.about': 'À propos',
  'settings.nav.danger': 'Zone de danger',
  'settings.session.subtitle': 'Identifie ce fil de conversation sur le serveur admino.',
  'settings.session.id.label': 'ID de session',
  'settings.session.id.hint': 'Lettres, chiffres, tirets, traits de soulignement. 64 caractères max.',
  'settings.session.new.label': 'Nouvelle session',
  'settings.session.new.hint': 'Vide le fil de discussion.',
  'settings.appearance.subtitle':
    "L'apparence de l'interface. Les modifications s'appliquent immédiatement.",
  'settings.appearance.theme.label': 'Thème',
  'settings.appearance.theme.hint': 'Le mode sombre est prévu pour la v2.',
  'settings.appearance.theme.light': 'Clair',
  'settings.appearance.theme.dark': 'Sombre',
  'settings.appearance.theme.system': 'Système',
  'settings.notifications.subtitle':
    "Alertes dans l'application. Les notifications push du navigateur s'activent une fois par appareil.",
  'settings.notifications.approval.label': "Alertes d'approbation d'outil",
  'settings.notifications.approval.hint':
    "M'alerter quand admino a besoin de mon approbation pour exécuter un outil.",
  'settings.notifications.taskDone.label': 'Alertes de tâche terminée',
  'settings.notifications.taskDone.hint': "M'alerter quand une réponse longue est prête.",
  'settings.notifications.sound.label': 'Son',
  'settings.notifications.sound.hint':
    'Carillon discret lors des alertes. Respecte le mode « Ne pas déranger » du système.',
  'settings.about.subtitle':
    "Un agent IA personnel axé sur la confidentialité et la sécurité, que vous hébergez vous-même, propulsé par défaut par l'IA d'Infomaniak hébergée en Suisse.",
  'settings.about.version': 'Version',
  'settings.about.versionValue': 'admino {version} (Alpha)',
  'settings.about.sourceCode': 'Code source',
  'settings.about.license': 'Licence',
  'settings.danger.subtitle': 'Ces actions sont irréversibles. Chacune demande une confirmation.',
  'settings.danger.clear.label': 'Effacer la conversation',
  'settings.danger.clear.hint':
    "Efface le fil de discussion actuel. Le journal d'audit est conservé par conception.",
  'settings.danger.clear.button': 'Effacer le fil',
  'settings.danger.disconnectAll.label': 'Déconnecter tous les comptes',
  'settings.danger.disconnectAll.hint': "Révoque les jetons d'actualisation OAuth de Google et Microsoft.",
  'settings.danger.disconnectAll.button': 'Tout déconnecter',
  'settings.danger.reset.label': 'Réinitialiser les paramètres',
  'settings.danger.reset.hint':
    'Rétablit tous les paramètres par défaut. Les comptes connectés restent connectés.',
  'settings.danger.reset.button': 'Rétablir les valeurs par défaut',
  'settings.danger.erase.label': 'Effacer toutes les données',
  'settings.danger.erase.hint':
    "Supprime le journal d'audit, la mémoire et le stockage de documents. Irrécupérable.",
  'settings.danger.erase.button': 'Tout effacer',
  'settings.danger.clearConfirm.heading': 'Effacer la conversation?',
  'settings.danger.clearConfirm.subtext':
    "Tous les messages et l'historique des appels d'outils de la session actuelle seront supprimés.",
  'settings.danger.clearConfirm.confirm': 'Effacer',
  'settings.toast.chatCleared': 'Discussion effacée',
  'settings.toast.newSession': 'Nouvelle session démarrée',
  'settings.comingSoon.title': 'Bientôt disponible',
  'settings.comingSoon.resetSettings': "La réinitialisation des paramètres n'est pas encore disponible.",
  'settings.comingSoon.eraseAll': "L'effacement de toutes les données n'est pas encore disponible.",
  'settings.comingSoon.toggle': "Cette option n'est pas encore disponible.",
  'settings.session.logout.label': 'Se déconnecter',
  'settings.session.logout.hint': 'Met fin à votre session sur cet appareil.',

  // --- auth (session-expired toast, error copy, issue #155) --------------
  'auth.sessionExpired.title': 'Session expirée',
  'auth.sessionExpired.body': 'Veuillez vous reconnecter.',
  'auth.login.error.invalid': 'E-mail ou mot de passe invalide',
  'auth.error.rateLimited': "Trop de tentatives. Veuillez patienter un instant et réessayer.",
  'auth.error.generic': "Un problème est survenu. Veuillez réessayer.",
  'auth.reset.error.invalidLink': 'Ce lien de réinitialisation est invalide ou a expiré.',
  'auth.invitation.error.invalidLink': "Ce lien d'invitation est invalide ou a expiré.",
  'auth.invitation.error.invalidName': 'Veuillez saisir votre nom.',

  // --- auth.password (password policy, issue #155) -----------------------
  'auth.password.error.tooShort': 'Le mot de passe est trop court.',
  'auth.password.error.tooLong': 'Le mot de passe est trop long.',
  'auth.password.error.common': 'Ce mot de passe est trop courant.',
  'auth.password.error.equalsEmail': "Le mot de passe ne doit pas être votre adresse e-mail.",
  'auth.password.error.mismatch': 'Les mots de passe ne correspondent pas.',
  'auth.password.error.generic': 'Ce mot de passe ne respecte pas les exigences.',
  'auth.password.rule.length': 'Entre {min} et {max} caractères.',
  'auth.password.rule.common': 'Pas un mot de passe courant.',
  'auth.password.rule.email': "Différent de votre adresse e-mail.",

  // --- auth.role (invited role, shown on the Accept invitation page) -----
  'auth.role.orgAdmin': "Administrateur de l'organisation",
  'auth.role.editor': 'Éditeur',
  'auth.role.viewer': 'Lecteur',

  // --- auth.login (Login page) --------------------------------------------
  'auth.login.title': 'Connexion',
  'auth.login.email.label': 'E-mail',
  'auth.login.password.label': 'Mot de passe',
  'auth.login.submit': 'Se connecter',
  'auth.login.forgotPassword': 'Mot de passe oublié?',

  // --- auth.forgotPassword (Forgot password page) -------------------------
  'auth.forgotPassword.title': 'Mot de passe oublié',
  'auth.forgotPassword.subtitle': 'Saisissez votre e-mail et nous vous enverrons un lien de réinitialisation.',
  'auth.forgotPassword.email.label': 'E-mail',
  'auth.forgotPassword.submit': 'Envoyer le lien',
  'auth.forgotPassword.success':
    "Si un compte existe pour cette adresse, nous avons envoyé un lien de réinitialisation. Il est valable 30 minutes.",
  'auth.forgotPassword.backToLogin': 'Retour à la connexion',

  // --- auth.reset (Reset password page) ------------------------------------
  'auth.reset.title': 'Réinitialiser le mot de passe',
  'auth.reset.invalidLink.heading': 'Ce lien est invalide ou a expiré.',
  'auth.reset.invalidLink.cta': 'Demander un nouveau lien',
  'auth.reset.password.label': 'Nouveau mot de passe',
  'auth.reset.confirm.label': 'Confirmer le nouveau mot de passe',
  'auth.reset.submit': 'Changer le mot de passe',
  'auth.reset.success': 'Mot de passe modifié. Connectez-vous avec votre nouveau mot de passe.',

  // --- auth.invitation (Accept invitation page) ----------------------------
  'auth.invitation.title': "Accepter l'invitation",
  'auth.invitation.invalidLink.heading': "Ce lien d'invitation est invalide ou a expiré.",
  'auth.invitation.org.label': 'Organisation',
  'auth.invitation.role.label': 'Rôle',
  'auth.invitation.email.label': 'E-mail',
  'auth.invitation.name.label': 'Nom complet',
  'auth.invitation.password.label': 'Mot de passe',
  'auth.invitation.confirm.label': 'Confirmer le mot de passe',
  'auth.invitation.submit': "Accepter l'invitation",

  // --- organization page (placeholder, issue #155) --------------------------
  'organization.empty.heading': 'Organisation',
  'organization.empty.subtext':
    "La gestion des utilisateurs et les paramètres de l'organisation apparaîtront ici.",

  // --- platform page (placeholder, Super Admin console, issue #155) ---------
  'platform.empty.heading': 'Console de la plateforme',
  'platform.empty.subtext': 'La console de la plateforme apparaîtra ici.',

  // --- chat page (read-only viewer, issue #155) -----------------------------
  'chat.viewerEmpty.heading': "Rien n'a encore été partagé avec vous",
  'chat.viewerEmpty.subtext': "Les projets que d'autres partagent avec vous apparaîtront ici.",
};
