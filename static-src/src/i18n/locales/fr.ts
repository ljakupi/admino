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

  // --- chat errors (issue #242: V1 model policy, decision D3 — affiché à la
  // place de la réponse anglaise de secours du backend pour une réponse d'erreur) ---
  'chat.error.not_configured':
    "Ce modèle d'IA n'est pas encore configuré. Demandez à votre administrateur de le configurer.",
  'chat.error.missing_model':
    "Le modèle d'IA configuré n'est pas disponible. Demandez à votre administrateur de vérifier la configuration.",
  'chat.error.provider_unavailable':
    "Le service d'IA est temporairement indisponible. Veuillez patienter un instant et réessayer.",
  'chat.error.rate_limited': 'Trop de demandes pour le moment. Veuillez patienter un instant et réessayer.',
  'chat.error.timeout': "Le service d'IA a mis trop de temps à répondre. Veuillez réessayer.",
  'chat.error.residency_blocked':
    "La politique de résidence des données de votre organisation n'autorise pas le modèle d'IA actuel. Demandez à votre administrateur de passer à un modèle autorisé.",
  'chat.error.context_too_long':
    "Cette conversation est devenue trop longue pour le modèle d'IA. Démarrez une nouvelle discussion.",
  'chat.error.generic': 'Une erreur est survenue en répondant à ce message. Veuillez réessayer.',

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
  'toast.settings.settingsReset': 'Paramètres réinitialisés',
  'toast.settings.resetFailed.title': 'Réinitialisation échouée',

  // --- toast (critical permissions store) ---------------------------------
  'toast.criticalPermissions.promotionScheduled.title': 'Activation planifiée',
  'toast.criticalPermissions.promotionScheduled.body': 'Actif dans {time}',
  'toast.criticalPermissions.promotionFailed.title': "Échec de l'activation",
  'toast.criticalPermissions.cancelled.title': 'Activation planifiée annulée',
  'toast.criticalPermissions.cancelFailed.title': "Échec de l'annulation",
  'toast.criticalPermissions.disabled': 'Désactivé : {permission}',
  'toast.criticalPermissions.disableFailed.title': 'Échec de la désactivation',

  // --- toast.orgUsers (Organization console's Users tab, issue #165) ------
  'toast.orgUsers.invited': 'Invitation envoyée',
  'toast.orgUsers.roleChanged': 'Rôle modifié',
  'toast.orgUsers.profileSaved': 'Modifications enregistrées',
  'toast.orgUsers.deactivated': 'Utilisateur désactivé',
  'toast.orgUsers.reactivated': 'Utilisateur réactivé',
  'toast.orgUsers.deleted': 'Utilisateur supprimé',
  'toast.orgUsers.passwordResetSent': 'E-mail de réinitialisation du mot de passe envoyé',
  'toast.orgUsers.loggedOut': 'Utilisateur déconnecté partout',
  'toast.orgUsers.invitationResent': 'Invitation renvoyée',
  'toast.orgUsers.invitationRevoked': 'Invitation révoquée',
  'toast.orgUsers.failed': "Échec de l'action",

  // --- settings (fallback error strings) ------------------------------------
  'settings.error.loadFailed': 'Impossible de charger les paramètres',
  'settings.error.saveFailed': "Impossible d'enregistrer les paramètres",
  'settings.error.unexpectedRedirect': 'URL de redirection OAuth inattendue.',
  'settings.error.oauthStartFailed': 'Impossible de démarrer le processus OAuth',
  'settings.error.disconnectFailed': 'Échec de la déconnexion',
  'settings.error.resetFailed': 'Impossible de réinitialiser vos paramètres.',

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

  // --- reauth (password re-auth prompt, issue #161: promoting a critical ---
  // permission needs the Org Admin's password)
  'reauth.title': 'Confirmez votre mot de passe',
  'reauth.body': "Saisissez votre mot de passe pour autoriser l'agent à proposer {action} pour {tool}.",
  'reauth.passwordLabel': 'Mot de passe',
  'reauth.submit': 'Confirmer',
  'reauth.error.wrongPassword': 'Mot de passe incorrect. Veuillez réessayer.',
  'reauth.error.failed': "Une erreur s'est produite. Veuillez réessayer.",

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
  'permissionState.disabled': 'Service désactivé',
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

  // --- permissions summary page (read-only, issue #161: Editor/Viewer) ----
  'permissions.summary.subtitle': "Ce que l'agent peut faire dans l'espace de travail de votre organisation.",
  'permissions.summary.empty': 'Aucune autorisation configurée pour le moment.',

  // --- organization permissions (editable matrix, Org Admin, issue #161) --
  'organization.permissions.title': 'Matrice des autorisations',
  'organization.permissions.subtitle':
    "Choisissez ce que l'agent peut faire dans cette organisation, par outil et par action.",

  // --- organization services (Org Admin's tool switches, issue #162) -----
  'organization.services.title': 'Services',
  'organization.services.subtitle':
    'Activez ou désactivez les services pour tous les membres de cette organisation.',
  'organization.services.residencyLocked':
    "La politique de résidence des données de votre organisation conserve les données en Suisse, les comptes Google et Microsoft ne peuvent donc pas être utilisés.",

  // --- organization tabs (Users | Permissions & services, issue #165) -----
  'organization.tabs.users': 'Utilisateurs',
  'organization.tabs.permissions': 'Autorisations et services',

  // --- orgUsers (Organization console's Users tab, issue #165) ------------
  'orgUsers.title': 'Utilisateurs',
  'orgUsers.search.label': 'Rechercher',
  'orgUsers.search.placeholder': 'Rechercher par nom ou e-mail',
  'orgUsers.filter.label': 'Statut',
  'orgUsers.filter.all': 'Tous',
  'orgUsers.filter.active': 'Actifs',
  'orgUsers.filter.deactivated': 'Désactivés',
  'orgUsers.filter.invited': 'Invités',
  'orgUsers.seats': '{used} / {limit} sièges',
  'orgUsers.seatsFull':
    "Plus aucun siège disponible. Désactivez un utilisateur ou passez à un forfait supérieur pour inviter davantage de personnes.",
  'orgUsers.status.active': 'Actif',
  'orgUsers.status.deactivated': 'Désactivé',
  'orgUsers.status.invited': 'Invité',
  'orgUsers.status.expired': 'Expiré',
  'orgUsers.you': 'Vous',
  'orgUsers.lastLogin': 'Dernière connexion : {date}',
  'orgUsers.neverLoggedIn': 'Jamais connecté',
  'orgUsers.invitations.title': 'Invitations en attente',
  'orgUsers.invitations.sent': 'Envoyée le {date}',
  'orgUsers.invitations.expires': 'Expire le {date}',
  'orgUsers.empty.users': "Aucun utilisateur ne correspond à votre recherche.",
  'orgUsers.empty.invitations': 'Aucune invitation en attente.',
  'orgUsers.actions.menu': 'Actions pour {name}',
  'orgUsers.actions.changeRole': 'Changer le rôle',
  'orgUsers.actions.edit': "Modifier le nom et l'e-mail",
  'orgUsers.actions.deactivate': 'Désactiver',
  'orgUsers.actions.reactivate': 'Réactiver',
  'orgUsers.actions.resetPassword': 'Réinitialiser le mot de passe',
  'orgUsers.actions.forceLogout': 'Déconnecter partout',
  'orgUsers.actions.delete': 'Supprimer',
  'orgUsers.actions.resend': 'Renvoyer',
  'orgUsers.actions.revoke': 'Révoquer',

  // --- orgUsers.invite (invite sheet, issue #165) --------------------------
  'orgUsers.invite.button': 'Inviter un utilisateur',
  'orgUsers.invite.heading': 'Inviter un utilisateur',
  'orgUsers.invite.email.label': 'E-mail',
  'orgUsers.invite.role.label': 'Rôle',
  'orgUsers.invite.submit': "Envoyer l'invitation",

  // --- orgUsers.edit (edit name/email sheet, issue #165) -------------------
  'orgUsers.edit.heading': "Modifier l'utilisateur",
  'orgUsers.edit.name.label': 'Nom complet',
  'orgUsers.edit.email.label': 'E-mail',
  'orgUsers.edit.emailHint':
    "La modification de l'e-mail change l'identifiant de connexion de cette personne ; elle devra utiliser la nouvelle adresse la prochaine fois.",
  'orgUsers.edit.submit': 'Enregistrer les modifications',

  // --- orgUsers.confirm (confirm sheet copy per row action, issue #165) ----
  'orgUsers.confirm.role.heading': 'Changer le rôle ?',
  'orgUsers.confirm.role.subtext': '{name} deviendra {role}.',
  'orgUsers.confirm.role.confirm': 'Changer le rôle',
  'orgUsers.confirm.deactivate.heading': 'Désactiver {name} ?',
  'orgUsers.confirm.deactivate.subtext':
    "Cette personne perdra l'accès immédiatement et pourra être réactivée plus tard.",
  'orgUsers.confirm.deactivate.confirm': 'Désactiver',
  'orgUsers.confirm.reactivate.heading': 'Réactiver {name} ?',
  'orgUsers.confirm.reactivate.subtext': "Cette personne retrouvera l'accès et un siège sera utilisé.",
  'orgUsers.confirm.reactivate.confirm': 'Réactiver',
  'orgUsers.confirm.resetPassword.heading': 'Réinitialiser le mot de passe ?',
  'orgUsers.confirm.resetPassword.subtext':
    "{name} recevra un e-mail avec les instructions pour définir un nouveau mot de passe.",
  'orgUsers.confirm.resetPassword.confirm': "Envoyer l'e-mail de réinitialisation",
  'orgUsers.confirm.forceLogout.heading': 'Déconnecter {name} partout ?',
  'orgUsers.confirm.forceLogout.subtext': 'Cela met fin immédiatement à toutes les sessions actives.',
  'orgUsers.confirm.forceLogout.confirm': 'Déconnecter',
  'orgUsers.confirm.delete.heading': 'Supprimer {name} ?',
  'orgUsers.confirm.delete.subtext': 'Cela supprime définitivement le compte. Cette action est irréversible.',
  'orgUsers.confirm.delete.confirm': 'Supprimer',
  'orgUsers.confirm.revoke.heading': 'Révoquer cette invitation ?',
  'orgUsers.confirm.revoke.subtext': "{name} ne pourra plus l'accepter.",
  'orgUsers.confirm.revoke.confirm': 'Révoquer',
  'orgUsers.confirm.selfWarning': "Il s'agit de votre propre compte.",

  // --- orgUsers.error (translated messages; a backend detail is never shown, issue #165) --
  'orgUsers.error.lastAdmin':
    "Une organisation a besoin d'au moins un administrateur actif. Faites d'abord d'une autre personne un administrateur de l'organisation.",
  'orgUsers.error.emailTaken': 'Cette adresse e-mail est déjà utilisée par une personne de cette organisation.',
  'orgUsers.error.seatLimit': "Votre organisation n'a plus de siège disponible.",
  'orgUsers.error.invalidStatus': "Cette action ne s'applique pas au statut actuel de cette personne.",
  'orgUsers.error.userNotFound': 'Cet utilisateur est introuvable.',
  'orgUsers.error.invitationNotFound': 'Cette invitation est introuvable.',
  'orgUsers.error.invalidInput': 'Certaines informations saisies ne sont pas valides.',
  'orgUsers.error.invalidEmail': 'Saisissez une adresse e-mail valide.',
  'orgUsers.error.rateLimited': 'Trop de tentatives. Veuillez patienter un instant puis réessayer.',
  'orgUsers.error.forbidden': "Vous n'avez pas la permission d'effectuer cette action.",
  'orgUsers.error.generic': "Une erreur s'est produite. Veuillez réessayer.",

  // --- toolsPage (my connections, OAuth callback, issue #162) ------------
  'toolsPage.accounts.title': 'Mes connexions',
  'toolsPage.accounts.subtitle':
    'Connectez vos propres comptes Google et Microsoft. Déconnectez-les à tout moment.',
  'toolsPage.status.connected': 'Connecté',
  'toolsPage.status.notConnected': 'Non connecté',
  'toolsPage.status.residency': 'Restreint',
  'toolsPage.google.connectHint': 'Connectez-vous pour utiliser Gmail, Google Agenda et Google Drive.',
  'toolsPage.microsoft.connectHint':
    'Connectez-vous pour utiliser Outlook Mail, Calendrier Outlook et OneDrive.',
  'toolsPage.connect': 'Connecter',
  'toolsPage.disconnect': 'Déconnecter',
  'toolsPage.service.outlookMail': 'Outlook Mail',
  'toolsPage.service.state.active': 'Actif',
  'toolsPage.service.state.orgDisabled': 'Désactivé par votre organisation',
  'toolsPage.service.state.residency': 'Restreint par la résidence des données',
  'toolsPage.service.state.notConnected': 'Non connecté',
  'toolsPage.residency.explanation':
    "La politique de résidence des données de votre organisation conserve les données en Suisse, les comptes Google et Microsoft ne peuvent donc pas être utilisés.",
  'toolsPage.residency.connectBlocked':
    "La politique de résidence des données de votre organisation n'autorise pas les comptes Google ou Microsoft.",
  'toolsPage.disconnectConfirm.heading': 'Déconnecter {provider}?',
  'toolsPage.disconnectConfirm.subtext':
    "Le jeton d'actualisation OAuth sera révoqué. Vous pouvez vous reconnecter à tout moment.",
  'toolsPage.oauth.connected.title': 'Compte connecté',
  'toolsPage.oauth.connected.body': 'Votre compte a été associé avec succès.',
  'toolsPage.oauth.reason.denied': "Vous avez refusé l'écran de consentement.",
  'toolsPage.oauth.reason.invalidState': 'Session expirée. Veuillez réessayer.',
  'toolsPage.oauth.reason.missingCode': "Aucun code d'autorisation reçu.",
  'toolsPage.oauth.reason.exchangeFailed': "Échec de l'échange de jetons. Vérifiez les identifiants OAuth.",
  'toolsPage.oauth.reason.forbidden': "Vous n'êtes pas autorisé à connecter des comptes.",
  'toolsPage.oauth.reason.residency':
    "La politique de résidence des données de votre organisation n'autorise pas les comptes Google ou Microsoft.",
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
  'settings.about.subtitle':
    "Un agent IA personnel axé sur la confidentialité et la sécurité, que vous hébergez vous-même, propulsé par défaut par l'IA d'Infomaniak hébergée en Suisse.",
  'settings.about.version': 'Version',
  'settings.about.versionValue': 'admino {version} (Alpha)',
  'settings.about.sourceCode': 'Code source',
  'settings.about.license': 'Licence',
  'settings.danger.subtitle': 'Ces actions sont irréversibles. Chacune demande une confirmation.',
  'settings.danger.reset.label': 'Réinitialiser mes paramètres',
  'settings.danger.reset.hint':
    "Rétablit votre thème et vos notifications par défaut. Les comptes connectés, les langues et les paramètres de l'organisation restent inchangés.",
  'settings.danger.reset.button': 'Rétablir les valeurs par défaut',
  'settings.danger.resetConfirm.heading': 'Réinitialiser vos paramètres ?',
  'settings.danger.resetConfirm.subtext':
    "Cela rétablit le thème clair, active les alertes d'approbation d'outil et désactive les alertes de tâche terminée. Les comptes connectés, les langues et les paramètres de l'organisation restent inchangés.",
  'settings.danger.resetConfirm.confirm': 'Réinitialiser',
  'settings.toast.newSession': 'Nouvelle session démarrée',
  'settings.session.logout.label': 'Se déconnecter',
  'settings.session.logout.hint': 'Met fin à votre session sur cet appareil.',

  // --- account (My account settings section, issue #166) ------------------
  'settings.nav.account': 'Mon compte',
  'account.title': 'Mon compte',
  'account.subtitle': 'Votre profil, vos langues, votre fuseau horaire et votre mot de passe.',
  'account.profile.title': 'Profil',
  'account.profile.name.label': 'Votre nom',
  'account.profile.email.label': 'Adresse e-mail',
  'account.profile.email.hint': 'Demandez à un administrateur de modifier votre adresse e-mail.',
  'account.profile.save': 'Enregistrer',
  'account.languages.title': 'Langues',
  'account.languages.ui.label': "Langue de l'interface",
  'account.languages.ui.hint': "Change la langue de l'application immédiatement.",
  'account.languages.response.label': 'Langue des réponses',
  'account.languages.response.hint': "La langue dans laquelle admino répond, indépendamment de la langue de l'interface.",
  'account.languages.response.orgDefault': "Valeur par défaut de l'organisation",
  'account.language.de': 'Deutsch',
  'account.language.fr': 'Français',
  'account.language.it': 'Italiano',
  'account.language.en': 'English',
  'account.timezone.label': 'Fuseau horaire',
  'account.timezone.hint': 'Utilisé pour les dates et heures que vous montre admino.',
  'account.instructions.label': 'Instructions personnelles',
  'account.instructions.hint': 'Votre nom et votre rôle, votre entreprise, le ton souhaité, comment vous signez',
  'account.instructions.remaining': '{count} caractères restants',
  'account.instructions.placeholder': "Par ex. Je suis cheffe de projet chez Acme SA. Réponses courtes, signe par « Cordialement, Alex ».",
  'account.password.title': 'Mot de passe',
  'account.password.subtitle': 'Changer votre mot de passe mettra fin à toutes les sessions, y compris celle-ci.',
  'account.password.current': 'Mot de passe actuel',
  'account.password.new': 'Nouveau mot de passe',
  'account.password.confirm': 'Confirmer le nouveau mot de passe',
  'account.password.submit': 'Changer le mot de passe',
  'account.password.notice': 'Changer votre mot de passe mettra fin à toutes les sessions, y compris celle-ci. Vous devrez vous reconnecter.',
  'account.password.error.current': 'Votre mot de passe actuel est incorrect.',
  'account.password.error.currentRequired': 'Saisissez votre mot de passe actuel.',
  'account.toast.passwordChanged': 'Mot de passe modifié. Reconnectez-vous avec votre nouveau mot de passe.',
  'account.sessions.title': 'Sessions actives',
  'account.sessions.subtitle': 'Où vous êtes actuellement connecté.',
  'account.sessions.current': 'Cet appareil',
  'account.sessions.lastSeen': 'Vu pour la dernière fois le {date}',
  'account.sessions.ip': 'Adresse IP : {ip}',
  'account.sessions.ipUnknown': 'IP inconnue',
  'account.sessions.device': '{browser} sous {os}',
  'account.sessions.unknownDevice': 'Appareil inconnu',
  'account.sessions.revoke': 'Révoquer',
  'account.sessions.revokeConfirm.heading': 'Révoquer cette session ?',
  'account.sessions.revokeConfirm.subtext': 'Cet appareil sera déconnecté immédiatement.',
  'account.sessions.revokeConfirm.confirm': 'Révoquer',
  'account.sessions.empty': 'Aucune session active.',
  'account.sessions.error.load': "Impossible de charger vos sessions.",
  'account.sessions.error.revoke': 'Impossible de révoquer cette session.',
  'account.error.load': 'Impossible de charger votre compte.',
  'account.error.generic': "Un problème est survenu. Veuillez réessayer.",
  'account.error.invalid': "Certaines informations saisies ne sont pas valides.",
  'account.error.nameRequired': 'Saisissez votre nom.',
  'account.error.nameTooLong': 'Le nom doit comporter au plus {max} caractères.',
  'account.error.instructionsTooLong': 'Les instructions personnelles doivent comporter au plus {max} caractères.',
  'account.toast.saved': 'Enregistré',

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

  // --- platform defaults: residency confirmation (issue #242, D1; #168 renders the dialog) ---
  'platform.defaults.residencyConfirm.title': 'Confirmer un hébergement hors de Suisse',
  'platform.defaults.residencyConfirm.body': {
    one: '{count} organisation exige actuellement une résidence des données en Suisse et sera concernée par ce changement.',
    other:
      '{count} organisations exigent actuellement une résidence des données en Suisse et seront concernées par ce changement.',
  },
  'platform.defaults.residencyConfirm.confirm': 'Changer quand même',

  // --- chat page (read-only viewer, issue #155) -----------------------------
  'chat.viewerEmpty.heading': "Rien n'a encore été partagé avec vous",
  'chat.viewerEmpty.subtext': "Les projets que d'autres partagent avec vous apparaîtront ici.",
};
