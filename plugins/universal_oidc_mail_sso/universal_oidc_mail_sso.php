<?php

declare(strict_types=1);

use UniversalOidcMailSso\Lib\Crypto;
use UniversalOidcMailSso\Lib\OidcClient;
use UniversalOidcMailSso\Lib\Storage;

require_once __DIR__ . '/lib/Crypto.php';
require_once __DIR__ . '/lib/JwksValidator.php';
require_once __DIR__ . '/lib/OidcClient.php';
require_once __DIR__ . '/lib/Storage.php';

class universal_oidc_mail_sso extends rcube_plugin
{
    public $task = 'login|mail|settings|logout';

    private const SESSION_OIDC_SUB = 'universal_oidc_mail_sso_oidc_sub';
    private const SESSION_OIDC_EMAIL = 'universal_oidc_mail_sso_oidc_email';
    private const SESSION_OIDC_NONCE = 'universal_oidc_mail_sso_oidc_nonce';
    private const SESSION_OIDC_STATE = 'universal_oidc_mail_sso_oidc_state';
    private const SESSION_OIDC_CODE_VERIFIER = 'universal_oidc_mail_sso_oidc_code_verifier';
    private const SESSION_OIDC_GROUPS = 'universal_oidc_mail_sso_oidc_groups';
    private const SESSION_OIDC_ID_TOKEN = 'universal_oidc_mail_sso_id_token';
    private const SESSION_OIDC_ACCESS_TOKEN = 'universal_oidc_mail_sso_access_token';
    private const SESSION_OIDC_REFRESH_TOKEN = 'universal_oidc_mail_sso_refresh_token';
    private const SESSION_OIDC_LOGIN_AT = 'universal_oidc_mail_sso_login_at';
    private const SESSION_OIDC_LAST_ACTIVITY = 'universal_oidc_mail_sso_last_activity';
    private const SESSION_ALLOW_STANDARD_LOGIN = 'universal_oidc_mail_sso_allow_standard_login';
    private const SESSION_POST_LOGIN_ACTION = 'universal_oidc_mail_sso_post_login_action';
    private const SESSION_CLIENT_WRAP_PASSWORD = 'universal_oidc_mail_sso_client_wrap_password';
    private const SESSION_CLIENT_WRAP_UNLOCKED_AT = 'universal_oidc_mail_sso_client_wrap_unlocked_at';
    private const SESSION_AUTLOGIN = 'universal_oidc_mail_sso_autologin';
    private const SESSION_SETUP_RATE = 'universal_oidc_mail_sso_setup_rate';
    private const PREF_OIDC_GROUPS = 'universal_oidc_mail_sso_groups';
    private const ACTION_LOGIN = 'plugin.universal_oidc_mail_sso_login';
    private const ACTION_CALLBACK = 'plugin.universal_oidc_mail_sso_callback';
    private const ACTION_AUTOLOGIN = 'plugin.universal_oidc_mail_sso_autologin';
    private const ACTION_CONNECT = 'plugin.universal_oidc_mail_sso_connect';
    private const ACTION_SAVE_MAILBOX = 'plugin.universal_oidc_mail_sso_save_mailbox';
    private const ACTION_BOOTSTRAP = 'plugin.universal_oidc_mail_sso_bootstrap';
    private const ACTION_BOOTSTRAP_SAVE = 'plugin.universal_oidc_mail_sso_bootstrap_save';
    private const ACTION_ENTRY = 'plugin.universal_oidc_mail_sso_entry';
    private const ACTION_STANDARD_LOGIN = 'plugin.universal_oidc_mail_sso_standard_login';
    private const ACTION_UNLOCK = 'plugin.universal_oidc_mail_sso_unlock';
    private const ACTION_UNLOCK_SUBMIT = 'plugin.universal_oidc_mail_sso_unlock_submit';
    private const ACTION_ADMIN = 'plugin.universal_oidc_mail_sso_admin';
    private const ACTION_ADMIN_SAVE_POLICY = 'plugin.universal_oidc_mail_sso_admin_save_policy';
    private const ACTION_ADMIN_DELETE_USER = 'plugin.universal_oidc_mail_sso_admin_delete_user';
    private const ACTION_ADMIN_SET_USER_STATUS = 'plugin.universal_oidc_mail_sso_admin_set_user_status';
    private const ACTION_ADMIN_CLEAR_MAILBOX = 'plugin.universal_oidc_mail_sso_admin_clear_mailbox';
    private const ACTION_ADMIN_SET_NOTE = 'plugin.universal_oidc_mail_sso_admin_set_note';
    private const ACTION_ADMIN_LOGOUT = 'plugin.universal_oidc_mail_sso_admin_logout';
    private const ACTION_USER_SETTINGS = 'plugin.universal_oidc_mail_sso_user_settings';
    private const ACTION_USER_TEST_MAILBOX = 'plugin.universal_oidc_mail_sso_user_test_mailbox';
    private const ACTION_USER_TEST_IMAP = 'plugin.universal_oidc_mail_sso_user_test_imap';
    private const ACTION_USER_TEST_SMTP = 'plugin.universal_oidc_mail_sso_user_test_smtp';
    private const ACTION_USER_CLEAR_MAILBOX = 'plugin.universal_oidc_mail_sso_user_clear_mailbox';
    private const ACTION_USER_DOWNLOAD_RECOVERY = 'plugin.universal_oidc_mail_sso_user_download_recovery';
    private const ACTION_USER_DOWNLOAD_SUPPORT = 'plugin.universal_oidc_mail_sso_user_download_support';
    private const ACTION_USER_REQUEST_EMAIL = 'plugin.universal_oidc_mail_sso_user_request_email';
    private const PREF_SECTION_USER = 'sso_mailbox';

    private rcmail $rc;
    private Storage $storage;
    private ?Crypto $crypto = null;
    private ?string $cryptoInitError = null;
    private ?array $policyCache = null;
    private ?string $pendingLogoutIdToken = null;
    private ?string $pendingLogoutAccessToken = null;
    private ?string $pendingLogoutRefreshToken = null;
    private ?string $requestId = null;

    public function init(): void
    {
        $this->rc = rcmail::get_instance();
        $this->load_config();

        $this->storage = new Storage($this->rc);
        $this->storage->ensureSchema();
        $this->enforceClientWrapModeSwitch();
        try {
            $this->crypto = new Crypto($this->cfg('mailbox_key'));
        } catch (Throwable $e) {
            $this->cryptoInitError = $e->getMessage();
            $this->log('crypto_init_failed', ['err' => $e->getMessage()]);
        }

        $this->enforceSessionSecurityDefaults();

        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('template_object_loginform', [$this, 'templateLoginForm']);
        $this->add_hook('settings_actions', [$this, 'settingsActions']);
        $this->add_hook('preferences_sections_list', [$this, 'preferencesSectionsList']);
        $this->add_hook('preferences_list', [$this, 'preferencesList']);
        $this->add_hook('preferences_save', [$this, 'preferencesSave']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
        $this->add_hook('storage_connect', [$this, 'storageConnect']);
        $this->add_hook('smtp_connect', [$this, 'smtpConnect']);
        $this->add_hook('message_sent', [$this, 'messageSent']);
        $this->add_hook('logout_after', [$this, 'logoutAfter']);

        $this->register_action(self::ACTION_LOGIN, [$this, 'actionLogin']);
        $this->register_action(self::ACTION_CALLBACK, [$this, 'actionCallback']);
        $this->register_action(self::ACTION_AUTOLOGIN, [$this, 'actionAutologin']);
        $this->register_action(self::ACTION_CONNECT, [$this, 'actionConnect']);
        $this->register_action(self::ACTION_SAVE_MAILBOX, [$this, 'actionSaveMailbox']);
        $this->register_action(self::ACTION_BOOTSTRAP, [$this, 'actionBootstrap']);
        $this->register_action(self::ACTION_BOOTSTRAP_SAVE, [$this, 'actionBootstrapSave']);
        $this->register_action(self::ACTION_ENTRY, [$this, 'actionEntry']);
        $this->register_action(self::ACTION_STANDARD_LOGIN, [$this, 'actionStandardLogin']);
        $this->register_action(self::ACTION_UNLOCK, [$this, 'actionUnlock']);
        $this->register_action(self::ACTION_UNLOCK_SUBMIT, [$this, 'actionUnlockSubmit']);
        $this->register_action(self::ACTION_ADMIN, [$this, 'actionAdminDashboard']);
        $this->register_action(self::ACTION_ADMIN_SAVE_POLICY, [$this, 'actionAdminSavePolicy']);
        $this->register_action(self::ACTION_ADMIN_DELETE_USER, [$this, 'actionAdminDeleteUser']);
        $this->register_action(self::ACTION_ADMIN_SET_USER_STATUS, [$this, 'actionAdminSetUserStatus']);
        $this->register_action(self::ACTION_ADMIN_CLEAR_MAILBOX, [$this, 'actionAdminClearMailbox']);
        $this->register_action(self::ACTION_ADMIN_SET_NOTE, [$this, 'actionAdminSetNote']);
        $this->register_action(self::ACTION_ADMIN_LOGOUT, [$this, 'actionAdminLogout']);
        $this->register_action(self::ACTION_USER_SETTINGS, [$this, 'actionUserSettings']);
        $this->register_action(self::ACTION_USER_TEST_MAILBOX, [$this, 'actionUserTestMailbox']);
        $this->register_action(self::ACTION_USER_TEST_IMAP, [$this, 'actionUserTestImap']);
        $this->register_action(self::ACTION_USER_TEST_SMTP, [$this, 'actionUserTestSmtp']);
        $this->register_action(self::ACTION_USER_CLEAR_MAILBOX, [$this, 'actionUserClearMailbox']);
        $this->register_action(self::ACTION_USER_DOWNLOAD_RECOVERY, [$this, 'actionUserDownloadRecovery']);
        $this->register_action(self::ACTION_USER_DOWNLOAD_SUPPORT, [$this, 'actionUserDownloadSupport']);
        $this->register_action(self::ACTION_USER_REQUEST_EMAIL, [$this, 'actionUserRequestEmail']);
    }

    public function startup(array $args): array
    {
        $action = rcube_utils::get_input_value('_action', rcube_utils::INPUT_GPC);
        $adminActions = $this->adminActions();
        $userActions = [
            self::ACTION_USER_SETTINGS,
            self::ACTION_USER_TEST_MAILBOX,
            self::ACTION_USER_TEST_IMAP,
            self::ACTION_USER_TEST_SMTP,
            self::ACTION_USER_CLEAR_MAILBOX,
            self::ACTION_USER_DOWNLOAD_RECOVERY,
            self::ACTION_USER_DOWNLOAD_SUPPORT,
            self::ACTION_USER_REQUEST_EMAIL,
        ];

        $this->enforceSessionTimeouts();

        if ($this->cfgBool('disable_password_login', true)
            && empty($_SESSION['user_id'])
            && $this->rc->task !== 'logout'
            && $this->rc->task !== 'login'
        ) {
            $hasOidcIdentity = !empty($_SESSION[self::SESSION_OIDC_SUB]) || !empty($_SESSION[self::SESSION_OIDC_EMAIL]);
            $isAdminAction = is_string($action) && in_array($action, $adminActions, true);
            $allowAdminWithoutMailboxSession = $this->rc->task === 'settings'
                && $isAdminAction
                && $hasOidcIdentity
                && $this->isAdminUser();

            if (!$allowAdminWithoutMailboxSession) {
                $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
            }
        }

        // Canonical plugin-action auth gate:
        // unauthenticated requests go to OIDC login and then resume via session.
        if (is_string($action) && (in_array($action, $adminActions, true) || in_array($action, $userActions, true))) {
            $hasOidcIdentity = !empty($_SESSION[self::SESSION_OIDC_SUB]) || !empty($_SESSION[self::SESSION_OIDC_EMAIL]);
            $isAdminAction = in_array($action, $adminActions, true);
            if (empty($_SESSION['user_id'])) {
                if ($isAdminAction && $hasOidcIdentity && !$this->isAdminUser()) {
                    $this->audit('admin_dashboard', 'error', 'admin access denied after OIDC login', [
                        'admin_group_name' => (string) $this->cfg('admin_group_name', 'webmail_admin'),
                        'effective_groups' => implode(',', $this->currentUserGroups()),
                    ]);
                    $this->fail('Admin access denied. Your OIDC account is not in the configured admin group.');
                }
                if (!$hasOidcIdentity) {
                    if ($action === self::ACTION_ADMIN) {
                        $_SESSION[self::SESSION_POST_LOGIN_ACTION] = self::ACTION_ADMIN;
                    }
                    $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
                }
            }
        }

        // Capture id_token on logout request. We'll redirect to OIDC
        // end_session_endpoint in logoutAfter(), after local logout completes.
        if ($this->rc->task === 'logout') {
            $idToken = $_SESSION[self::SESSION_OIDC_ID_TOKEN] ?? null;
            $accessToken = $_SESSION[self::SESSION_OIDC_ACCESS_TOKEN] ?? null;
            $refreshToken = $_SESSION[self::SESSION_OIDC_REFRESH_TOKEN] ?? null;
            if (is_string($idToken) && $idToken !== '') {
                $this->pendingLogoutIdToken = $idToken;
            }
            if (is_string($accessToken) && $accessToken !== '') {
                $this->pendingLogoutAccessToken = $accessToken;
            }
            if (is_string($refreshToken) && $refreshToken !== '') {
                $this->pendingLogoutRefreshToken = $refreshToken;
            }
        }

        if ($this->rc->task !== 'login' || !empty($_SESSION['user_id'])) {
            return $args;
        }

        if (is_string($action) && strpos($action, 'plugin.universal_oidc_mail_sso_') === 0) {
            // Fallback direct dispatcher for environments where register_action
            // doesn't route plugin actions in login task as expected.
            if ($action === self::ACTION_LOGIN) {
                $this->actionLogin();
            } elseif ($action === self::ACTION_ENTRY) {
                $this->actionEntry();
            } elseif ($action === self::ACTION_STANDARD_LOGIN) {
                $this->actionStandardLogin();
            } elseif ($action === self::ACTION_UNLOCK) {
                $this->actionUnlock();
            } elseif ($action === self::ACTION_UNLOCK_SUBMIT) {
                $this->actionUnlockSubmit();
            } elseif ($action === self::ACTION_CALLBACK) {
                $this->actionCallback();
            } elseif ($action === self::ACTION_AUTOLOGIN) {
                $this->actionAutologin();
            } elseif ($action === self::ACTION_CONNECT) {
                $this->actionConnect();
            } elseif ($action === self::ACTION_SAVE_MAILBOX) {
                $this->actionSaveMailbox();
            } elseif ($action === self::ACTION_BOOTSTRAP) {
                $this->actionBootstrap();
            } elseif ($action === self::ACTION_BOOTSTRAP_SAVE) {
                $this->actionBootstrapSave();
            } elseif ($action === self::ACTION_ADMIN) {
                $this->actionAdminDashboard();
            } elseif ($action === self::ACTION_ADMIN_SAVE_POLICY) {
                $this->actionAdminSavePolicy();
            } elseif ($action === self::ACTION_ADMIN_DELETE_USER) {
                $this->actionAdminDeleteUser();
            } elseif ($action === self::ACTION_ADMIN_SET_USER_STATUS) {
                $this->actionAdminSetUserStatus();
            } elseif ($action === self::ACTION_ADMIN_CLEAR_MAILBOX) {
                $this->actionAdminClearMailbox();
            } elseif ($action === self::ACTION_ADMIN_SET_NOTE) {
                $this->actionAdminSetNote();
            } elseif ($action === self::ACTION_ADMIN_LOGOUT) {
                $this->actionAdminLogout();
            }

            return $args;
        }

        if (!$this->cfgBool('disable_password_login', true)) {
            return $args;
        }

        if (!empty($_SESSION[self::SESSION_ALLOW_STANDARD_LOGIN])) {
            unset($_SESSION[self::SESSION_ALLOW_STANDARD_LOGIN]);
            return $args;
        }

        if ($this->loginMode() === 'button') {
            // Render native Roundcube login page; button is injected via
            // template_object_loginform hook for a seamless in-page UX.
            return $args;
        }

        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if ($oidcSub) {
            $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
            if ($mailbox) {
                if ($this->isClientWrapMailbox($mailbox) && !$this->hasUnlockedClientWrapPassword()) {
                    $this->redirectTo($this->urlForAction(self::ACTION_UNLOCK));
                }
                $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
            }

            $this->redirectTo($this->urlForAction(self::ACTION_CONNECT));
        }

        $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        return $args;
    }

    public function authenticate(array $args): array
    {
        if (empty($_SESSION[self::SESSION_AUTLOGIN])) {
            return $args;
        }

        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if (!$oidcSub) {
            $this->log('autologin_failed_missing_oidc_sub');
            return $args;
        }

        $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
        if (!$mailbox) {
            $this->log('autologin_failed_missing_mailbox', ['oidc_sub' => (string) $oidcSub]);
            return $args;
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            $this->log('autologin_failed_decrypt', ['err' => 'mailbox password unavailable']);
            throw new rcube_exception('Unable to use mailbox credentials. Unlock is required.');
        }

        $args['user'] = (string) $mailbox['email'];
        $args['pass'] = $password;
        $args['host'] = $this->formatServer((string) $mailbox['imap_host'], (int) $mailbox['imap_port'], (string) $mailbox['imap_security']);
        $args['valid'] = true;

        return $args;
    }

    public function storageConnect(array $args): array
    {
        $mailbox = $this->loadMailboxFromSession();
        if (!$mailbox) {
            return $args;
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            $this->log('storage_connect_decrypt_failed', ['err' => 'mailbox password unavailable']);
            $this->audit('imap_auth', 'error', 'decrypt failed');
            return $args;
        }

        $args['user'] = (string) $mailbox['email'];
        $args['pass'] = $password;
        $args['host'] = (string) $mailbox['imap_host'];
        $args['port'] = (int) $mailbox['imap_port'];
        $args['ssl_mode'] = $this->imapSslMode((string) $mailbox['imap_security']);

        return $args;
    }

    public function smtpConnect(array $args): array
    {
        $mailbox = $this->loadMailboxFromSession();
        if (!$mailbox) {
            $this->log('smtp_connect_missing_mailbox_context', [
                'has_user_id' => !empty($_SESSION['user_id']) ? '1' : '0',
                'has_oidc_sub' => !empty($_SESSION[self::SESSION_OIDC_SUB]) ? '1' : '0',
                'rc_user' => !empty($this->rc->user) ? (string) $this->rc->user->get_username() : '',
            ]);
            return $args;
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            $this->log('smtp_connect_decrypt_failed', ['err' => 'mailbox password unavailable']);
            $this->audit('smtp_auth', 'error', 'decrypt failed');
            return $args;
        }

        $smtpUri = $this->formatServer((string) $mailbox['smtp_host'], (int) $mailbox['smtp_port'], (string) $mailbox['smtp_security']);

        $smtpAuth = !empty($mailbox['smtp_auth']);
        $smtpUser = (string) ($mailbox['smtp_user'] ?? '');
        if ($smtpAuth && $smtpUser === '') {
            $smtpUser = (string) ($mailbox['email'] ?? '');
        }

        $args['smtp_user'] = $smtpAuth ? $smtpUser : '';
        $args['smtp_pass'] = $smtpAuth ? $password : '';
        // Roundcube smtp_connect expects smtp_host as a URI-like value,
        // e.g. ssl://host:465 or tls://host:587.
        $args['smtp_host'] = $smtpUri;
        $args['smtp_port'] = (int) $mailbox['smtp_port'];
        $args['smtp_server'] = $smtpUri;
        $args['smtp_auth'] = $smtpAuth ? 1 : 0;
        // Compatibility: some Roundcube paths/hooks read `user`/`pass` keys.
        $args['user'] = $smtpAuth ? $smtpUser : '';
        $args['pass'] = $smtpAuth ? $password : '';

        // Force runtime SMTP settings so Roundcube doesn't fall back
        // to default/identity SMTP credentials.
        $this->rc->config->set('smtp_server', $smtpUri);
        $this->rc->config->set('smtp_host', $smtpUri);
        $this->rc->config->set('smtp_user', $smtpAuth ? $smtpUser : '');
        $this->rc->config->set('smtp_pass', $smtpAuth ? $password : '');
        $this->rc->config->set('smtp_auth_type', null);

        $this->log('smtp_connect_applied', [
            'smtp_host' => (string) $mailbox['smtp_host'],
            'smtp_port' => (string) $mailbox['smtp_port'],
            'smtp_security' => (string) $mailbox['smtp_security'],
            'smtp_auth' => $smtpAuth ? '1' : '0',
            'smtp_user' => $smtpAuth ? $smtpUser : '',
        ]);

        return $args;
    }

    public function messageSent(array $args): array
    {
        try {
            $this->audit('smtp_send', 'ok', 'message sent');
        } catch (Throwable $e) {
            // no-op
        }

        return $args;
    }

    public function actionLogin(): void
    {
        if (!$this->consumeRateLimit('login_init', $this->clientIp(), 300, $this->cfgInt('login_rate_limit_per_5m', 20))) {
            $this->audit('rate_limit', 'error', 'login init rate limit exceeded');
            $this->fail('Too many login attempts. Please wait and retry.');
        }

        try {
            $issuer = (string) $this->cfg('issuer', '');
            $clientId = (string) $this->cfg('client_id', '');
            $clientSecret = (string) $this->cfg('client_secret', '');
            $redirectUri = (string) $this->cfg('redirect_uri', $this->defaultRedirectUri());

            if ($issuer === '' || $clientId === '') {
                $this->fail(
                    'OIDC config missing: issuer=' . ($issuer !== '' ? 'yes' : 'no')
                    . ' client_id=' . ($clientId !== '' ? 'yes' : 'no')
                    . ' client_secret=' . ($clientSecret !== '' ? 'yes' : 'no')
                    . ' redirect_uri=' . ($redirectUri !== '' ? $redirectUri : 'empty')
                );
            }

            $oidc = $this->oidcClient();
            $discovery = $oidc->discover();

            $state = $this->randomB64Url(32);
            $nonce = $this->randomB64Url(32);
            $codeVerifier = $this->randomB64Url(64);
            $codeChallenge = $this->pkceChallenge($codeVerifier);

            $_SESSION[self::SESSION_OIDC_STATE] = $state;
            $_SESSION[self::SESSION_OIDC_NONCE] = $nonce;
            $_SESSION[self::SESSION_OIDC_CODE_VERIFIER] = $codeVerifier;

            $url = $oidc->buildAuthorizationUrl($discovery, $state, $nonce, $codeChallenge);
            $this->redirectTo($url);
        } catch (Throwable $e) {
            $this->log('oidc_login_init_failed', ['err' => $e->getMessage()]);
            $this->audit('oidc_login_init', 'error', $e->getMessage());
            $this->fail('OIDC init failed: ' . $e->getMessage());
        }
    }

    public function actionEntry(): void
    {
        $templateFile = __DIR__ . '/skins/elastic/templates/login_entry.html';
        $template = file_get_contents($templateFile);
        if ($template === false) {
            $this->fail('Unable to load login entry template.');
        }

        $showStandard = !$this->isStandardLoginHidden();
        $standardUrl = $this->rc->url(['task' => 'login', 'action' => self::ACTION_STANDARD_LOGIN]);
        $html = strtr($template, [
            '{{oidc_url}}' => htmlspecialchars($this->urlForAction(self::ACTION_LOGIN), ENT_QUOTES, 'UTF-8'),
            '{{button_text}}' => htmlspecialchars($this->loginButtonText(), ENT_QUOTES, 'UTF-8'),
            '{{standard_login_link}}' => $showStandard
                ? '<a class="secondary" href="' . htmlspecialchars($standardUrl, ENT_QUOTES, 'UTF-8') . '">Use standard login</a>'
                : '',
        ]);

        header('Content-Type: text/html; charset=UTF-8');
        echo $html;
        exit;
    }

    public function actionStandardLogin(): void
    {
        if ($this->isStandardLoginHidden()) {
            $this->fail('Standard login is disabled by administrator.');
        }

        $_SESSION[self::SESSION_ALLOW_STANDARD_LOGIN] = true;
        $this->redirectTo($this->rc->url(['task' => 'login']));
    }

    public function actionUnlock(): void
    {
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        if ($oidcSub === '') {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox || !$this->isClientWrapMailbox($mailbox)) {
            $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
        }

        $this->renderUnlockPage('');
    }

    public function actionUnlockSubmit(): void
    {
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        if ($oidcSub === '') {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->renderUnlockPage('Invalid CSRF token.', true);
            return;
        }

        $passphrase = (string) rcube_utils::get_input_value('client_wrap_passphrase', rcube_utils::INPUT_POST);
        if (trim($passphrase) === '') {
            $this->renderUnlockPage('Passphrase is required.', true);
            return;
        }

        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox || !$this->isClientWrapMailbox($mailbox)) {
            $this->renderUnlockPage('No encrypted mailbox profile found.', true);
            return;
        }

        $password = $this->decryptClientWrappedPassword($mailbox, $passphrase);
        if ($password === null || $password === '') {
            $this->renderUnlockPage('Invalid passphrase. Please try again.', true);
            return;
        }

        $_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD] = $password;
        $_SESSION[self::SESSION_CLIENT_WRAP_UNLOCKED_AT] = time();
        $this->audit('client_wrap_unlock', 'ok', 'mailbox credentials unlocked for session');
        $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
    }

    public function templateLoginForm(array $args): array
    {
        if ($this->rc->task !== 'login' || !empty($_SESSION['user_id'])) {
            return $args;
        }

        if ($this->loginMode() !== 'button') {
            return $args;
        }

        $action = (string) rcube_utils::get_input_value('_action', rcube_utils::INPUT_GPC);
        if ($action !== '' && strpos($action, 'plugin.universal_oidc_mail_sso_') === 0) {
            return $args;
        }

        $oidcUrl = htmlspecialchars($this->urlForAction(self::ACTION_LOGIN), ENT_QUOTES, 'UTF-8');
        $buttonText = htmlspecialchars($this->loginButtonText(), ENT_QUOTES, 'UTF-8');
        $showStandard = !$this->isStandardLoginHidden();

        $content = '<style>'
            . '.pizsso-inline{display:flex;flex-direction:column;gap:10px;margin-bottom:10px;}'
            . '.pizsso-inline .button{display:block;text-align:center;width:100%;box-sizing:border-box;}'
            . '.pizsso-inline .pizsso-cta{display:block;width:100%;box-sizing:border-box;padding:12px 14px;border-radius:8px;background:#0b6fa4;border:1px solid #28b8ff;color:#ffffff !important;text-decoration:none !important;font-weight:700;letter-spacing:.2px;}'
            . '.pizsso-inline .pizsso-cta:hover{background:#0a638f;color:#ffffff !important;}'
            . '.pizsso-inline .hint{font-size:12px;opacity:.8;text-align:center;}'
            . '.pizsso-inline .sep{font-size:12px;opacity:.65;text-align:center;margin:2px 0;}'
            . '</style>'
            . '<div class="pizsso-inline">'
            . '<a class="button mainaction pizsso-cta" href="' . $oidcUrl . '">' . $buttonText . '</a>'
            . '<div class="hint">Sign in with your identity provider</div>';

        if ($showStandard) {
            $content .= '<div class="sep">or use standard login below</div>';
        }

        $content .= '</div>';

        if ($showStandard) {
            $content .= (string) ($args['content'] ?? '');
        }

        $args['content'] = $content;
        return $args;
    }

    public function settingsActions(array $args): array
    {
        // Keep top-level settings tabs unchanged. User panel is integrated as a
        // native Preferences section via preferences_* hooks.
        return $args;
    }

    public function preferencesSectionsList(array $args): array
    {
        if ($this->rc->task !== 'settings' || empty($_SESSION['user_id'])) {
            return $args;
        }

        if (!$this->isUserSelfServiceAllowed()) {
            return $args;
        }

        $list = isset($args['list']) && is_array($args['list']) ? $args['list'] : [];
        $list[self::PREF_SECTION_USER] = [
            'id' => self::PREF_SECTION_USER,
            'section' => 'SSO Mailbox',
            'class' => 'server',
        ];
        $args['list'] = $list;

        return $args;
    }

    public function preferencesList(array $args): array
    {
        if (($args['section'] ?? '') !== self::PREF_SECTION_USER) {
            return $args;
        }

        if (empty($_SESSION['user_id']) || !$this->isUserSelfServiceAllowed()) {
            return $args;
        }

        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $mailbox = $oidcSub !== '' ? $this->storage->getMailboxBySub($oidcSub) : null;
        $statusMessage = (string) ($_SESSION['universal_oidc_mail_sso_user_status'] ?? '');
        unset($_SESSION['universal_oidc_mail_sso_user_status']);

        $connectUrl = $this->rc->url(['task' => 'settings', 'action' => self::ACTION_CONNECT, '_force_setup' => 1]);
        $requestEmailAction = $this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_REQUEST_EMAIL]);
        $allowCustomEmail = !$this->isStrictOidcEmailBinding();
        $oidcEmail = (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '');
        $lastImapLogin = $this->findRecentAuditTimestamp(['imap_auth'], ['ok']);
        $lastSmtpSend = $this->findRecentAuditTimestamp(['smtp_send'], ['ok']);
        $loginMode = $this->loginMode();

        $statusText = $statusMessage !== ''
            ? htmlspecialchars($statusMessage, ENT_QUOTES, 'UTF-8')
            : 'No recent action.';

        $actionsHtml = '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">'
            . '<a class="button mainaction" href="' . htmlspecialchars($connectUrl, ENT_QUOTES, 'UTF-8') . '" target="_blank" rel="noopener">Open Mailbox Setup</a>'
            . '<a class="button" href="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]), ENT_QUOTES, 'UTF-8') . '">Open Advanced Self-Service</a>'
            . '</div>';

        $emailChangeHtml = '';
        if ($allowCustomEmail) {
            $emailChangeHtml = '<div style="margin-top:8px;">'
                . '<label for="rcmfd_sso_new_mailbox_email" style="display:block;margin:0 0 4px 0;">Mailbox email override</label>'
                . '<form method="post" action="' . htmlspecialchars($requestEmailAction, ENT_QUOTES, 'UTF-8') . '" style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">'
                . '<input type="hidden" name="_token" value="' . $token . '">'
                . '<input id="rcmfd_sso_new_mailbox_email" type="email" name="new_mailbox_email" value="' . htmlspecialchars((string) ($mailbox['email'] ?? $oidcEmail), ENT_QUOTES, 'UTF-8') . '" style="min-width:280px;max-width:420px;">'
                . '<button class="button" type="submit">Apply in Setup</button>'
                . '</form>'
                . '</div>';
        }

        $mailboxEmail = htmlspecialchars((string) ($mailbox['email'] ?? ''), ENT_QUOTES, 'UTF-8');
        $imap = htmlspecialchars(isset($mailbox['imap_host']) ? ((string) $mailbox['imap_host'] . ':' . (string) $mailbox['imap_port'] . ' (' . (string) $mailbox['imap_security'] . ')') : '', ENT_QUOTES, 'UTF-8');
        $smtp = htmlspecialchars(isset($mailbox['smtp_host']) ? ((string) $mailbox['smtp_host'] . ':' . (string) $mailbox['smtp_port'] . ' (' . (string) $mailbox['smtp_security'] . ')') : '', ENT_QUOTES, 'UTF-8');
        $smtpUser = htmlspecialchars((string) ($mailbox['smtp_user'] ?? ''), ENT_QUOTES, 'UTF-8');
        $updatedAt = htmlspecialchars((string) ($mailbox['updated_at'] ?? ''), ENT_QUOTES, 'UTF-8');
        $clientWrap = $mailbox && $this->isClientWrapMailbox($mailbox) ? 'Enabled' : 'Disabled';
        $loginModeLabel = $loginMode === 'button' ? 'In-page SSO button' : 'Auto-redirect to IdP';
        $lastSeen = trim(implode(' | ', array_filter([
            $lastImapLogin !== 'n/a' ? ('Last IMAP: ' . $lastImapLogin) : '',
            $lastSmtpSend !== 'n/a' ? ('Last SMTP send: ' . $lastSmtpSend) : '',
        ])));
        if ($lastSeen === '') {
            $lastSeen = 'No successful IMAP/SMTP activity yet.';
        }

        $blocks = isset($args['blocks']) && is_array($args['blocks']) ? $args['blocks'] : [];
        $blocks['sso_mailbox'] = [
            'name' => rcube::Q('SSO Mailbox'),
            'options' => [
                'status' => ['title' => 'Status', 'content' => $statusText],
                'login_mode' => ['title' => 'Login UX mode', 'content' => htmlspecialchars($loginModeLabel, ENT_QUOTES, 'UTF-8')],
                'mailbox_email' => ['title' => 'Mailbox email', 'content' => $mailboxEmail],
                'imap' => ['title' => 'IMAP', 'content' => $imap],
                'smtp' => ['title' => 'SMTP', 'content' => $smtp],
                'smtp_user' => ['title' => 'SMTP user', 'content' => $smtpUser],
                'client_wrap' => ['title' => 'Zero-knowledge mode (client-side)', 'content' => htmlspecialchars($clientWrap, ENT_QUOTES, 'UTF-8')],
                'last_seen' => ['title' => 'Activity', 'content' => htmlspecialchars($lastSeen, ENT_QUOTES, 'UTF-8')],
                'updated_at' => ['title' => 'Updated', 'content' => $updatedAt],
                'actions' => [
                    'title' => 'Actions',
                    'content' => $actionsHtml . $emailChangeHtml,
                ],
            ],
        ];
        $args['blocks'] = $blocks;

        return $args;
    }

    public function preferencesSave(array $args): array
    {
        if (($args['section'] ?? '') === self::PREF_SECTION_USER) {
            $args['prefs'] = [];
        }

        return $args;
    }

    public function actionCallback(): void
    {
        if (!$this->consumeRateLimit('oidc_callback', $this->clientIp(), 300, $this->cfgInt('callback_rate_limit_per_5m', 30))) {
            $this->audit('rate_limit', 'error', 'callback rate limit exceeded');
            $this->fail('Too many callback attempts. Please wait and retry.');
        }

        $state = (string) rcube_utils::get_input_value('state', rcube_utils::INPUT_GPC);
        $code = (string) rcube_utils::get_input_value('code', rcube_utils::INPUT_GPC);

        if (!$state || !$code || $state !== ($_SESSION[self::SESSION_OIDC_STATE] ?? null)) {
            $this->log('oidc_callback_invalid_state');
            $this->audit('oidc_callback', 'error', 'state validation failed');
            $this->fail('OIDC state validation failed.');
        }

        $nonce = (string) ($_SESSION[self::SESSION_OIDC_NONCE] ?? '');
        $verifier = (string) ($_SESSION[self::SESSION_OIDC_CODE_VERIFIER] ?? '');

        unset($_SESSION[self::SESSION_OIDC_STATE], $_SESSION[self::SESSION_OIDC_NONCE], $_SESSION[self::SESSION_OIDC_CODE_VERIFIER]);

        try {
            $oidc = $this->oidcClient();
            $discovery = $oidc->discover();
            $token = $oidc->exchangeCode($discovery, $code, $verifier);
            $claims = $oidc->validateIdToken($discovery, (string) $token['id_token'], $nonce);
            if (!empty($token['access_token'])) {
                try {
                    $userinfo = $oidc->fetchUserinfo($discovery, (string) $token['access_token']);
                    if (is_array($userinfo)) {
                        $claims = array_merge($claims, $userinfo);
                    }
                } catch (Throwable $ue) {
                    $this->log('oidc_userinfo_fetch_failed', ['err' => $ue->getMessage()]);
                }
            }
        } catch (Throwable $e) {
            $this->log('oidc_callback_failed', ['err' => $e->getMessage()]);
            $this->audit('oidc_callback', 'error', $e->getMessage());
            $this->fail('OIDC login failed: ' . $e->getMessage());
        }

        $sub = (string) ($claims['sub'] ?? '');
        $email = strtolower((string) ($claims['email'] ?? ''));

        if ($sub === '' || $email === '') {
            $this->log('oidc_claim_missing_email_or_sub');
            $this->audit('oidc_claims', 'error', 'missing sub/email');
            $this->fail('Your account is missing required OIDC claims.');
        }

        if (!$this->isAllowedEmailDomain($email)) {
            $this->log('oidc_domain_mismatch', ['email' => $email]);
            $this->audit('oidc_domain', 'error', 'email domain is not allowed', ['email' => $email]);
            $this->fail('Your email domain is not allowed.');
        }

        $groups = $this->extractGroups($claims);

        $_SESSION[self::SESSION_OIDC_SUB] = $sub;
        $_SESSION[self::SESSION_OIDC_EMAIL] = $email;
        $_SESSION[self::SESSION_OIDC_GROUPS] = $groups;
        $_SESSION[self::SESSION_OIDC_ID_TOKEN] = (string) ($token['id_token'] ?? '');
        $_SESSION[self::SESSION_OIDC_ACCESS_TOKEN] = (string) ($token['access_token'] ?? '');
        $_SESSION[self::SESSION_OIDC_REFRESH_TOKEN] = (string) ($token['refresh_token'] ?? '');
        $_SESSION[self::SESSION_OIDC_LOGIN_AT] = time();
        $_SESSION[self::SESSION_OIDC_LAST_ACTIVITY] = time();

        if ($this->isBootstrapPending()) {
            if (!$this->isBootstrapAdminCandidate()) {
                $this->audit('bootstrap_gate', 'warn', 'non-admin blocked until first admin onboarding is complete');
                $this->renderBootstrapBlockedPage();
            }
            $this->claimBootstrapOwner((string) $sub, (string) $email);
            if ($this->isBootstrapOwner((string) $sub)) {
                $this->redirectTo($this->urlForAction(self::ACTION_BOOTSTRAP));
            }
        }

        $existingIdentity = $this->storage->getIdentityBySub($sub);
        if (!empty($existingIdentity['is_disabled'])) {
            $this->audit('oidc_login', 'error', 'blocked: account disabled by admin', ['oidc_sub' => $sub, 'email' => $email]);
            $this->fail('This account is disabled by administrator.');
        }

        $this->storage->upsertIdentity($sub, $email, null);
        $this->storage->setIdentitySeenIp($sub, $this->clientIp());
        $this->storage->clearAuthLock($sub);
        $this->log('oidc_login_success', ['sub' => $sub, 'email' => $email]);
        $this->audit('oidc_login', 'ok', 'OIDC login success', [
            'groups_count' => count($groups),
            'groups' => implode(',', $groups),
            'claim_keys' => implode(',', array_keys($claims)),
            'scope' => (string) $this->cfg('scopes', 'openid email profile groups'),
        ]);

        $postAction = (string) ($_SESSION[self::SESSION_POST_LOGIN_ACTION] ?? '');
        if (in_array($postAction, $this->adminActions(), true) && $this->isAdminUser()) {
            unset($_SESSION[self::SESSION_POST_LOGIN_ACTION]);
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => $postAction]));
        }

        $mailbox = $this->storage->getMailboxBySub($sub);
        if (!$mailbox) {
            $this->log('mailbox_missing_provisioning', ['sub' => $sub]);
            $this->audit('mailbox_provisioning', 'warn', 'mailbox profile missing');
            $this->redirectTo($this->urlForAction(self::ACTION_CONNECT));
        }
        if ($this->isClientWrapMailbox($mailbox) && !$this->hasUnlockedClientWrapPassword()) {
            $this->redirectTo($this->urlForAction(self::ACTION_UNLOCK));
        }

        $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
    }

    public function logoutAfter(array $args): array
    {
        unset($_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD], $_SESSION[self::SESSION_CLIENT_WRAP_UNLOCKED_AT]);
        try {
            $oidc = $this->oidcClient();
            $discovery = $oidc->discover();

            if (is_string($this->pendingLogoutAccessToken) && $this->pendingLogoutAccessToken !== '') {
                $oidc->revokeToken($discovery, $this->pendingLogoutAccessToken, 'access_token');
            }
            if (is_string($this->pendingLogoutRefreshToken) && $this->pendingLogoutRefreshToken !== '') {
                $oidc->revokeToken($discovery, $this->pendingLogoutRefreshToken, 'refresh_token');
            }

            $this->audit('oidc_logout', 'ok', 'local+provider logout requested');

            if ($this->pendingLogoutIdToken === null || $this->pendingLogoutIdToken === '') {
                return $args;
            }

            $postLogoutRedirect = (string) $this->cfg('post_logout_redirect_uri', $this->externalBaseUrl() . '/');
            $url = $oidc->buildEndSessionUrl($discovery, $this->pendingLogoutIdToken, $postLogoutRedirect);
            if ($url !== '') {
                $this->redirectTo($url);
            }
        } catch (Throwable $e) {
            $this->log('oidc_logout_redirect_failed', ['err' => $e->getMessage()]);
            $this->audit('oidc_logout', 'error', 'provider logout failed', ['err' => $e->getMessage()]);
        }

        return $args;
    }

    public function actionAutologin(): void
    {
        if ($this->isBootstrapPending()) {
            if (!$this->isBootstrapAdminCandidate()) {
                $this->audit('bootstrap_gate', 'warn', 'non-admin blocked during bootstrap');
                $this->renderBootstrapBlockedPage();
            }
            if (!$this->isBootstrapOwner((string) ($_SESSION[self::SESSION_OIDC_SUB] ?? ''))) {
                $this->renderBootstrapOwnerBlockedPage();
            }
            $this->redirectTo($this->urlForAction(self::ACTION_BOOTSTRAP));
        }

        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        $email = $_SESSION[self::SESSION_OIDC_EMAIL] ?? null;

        if (!$oidcSub || !$email) {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        $identity = $this->storage->getIdentityBySub((string) $oidcSub);
        if (!empty($identity['is_disabled'])) {
            $this->audit('imap_auth', 'error', 'blocked: account disabled by admin', ['oidc_sub' => (string) $oidcSub]);
            $this->fail('This account is disabled by administrator.');
        }
        $lockUntil = isset($identity['lock_until']) ? (string) $identity['lock_until'] : '';
        if ($lockUntil !== '' && strtotime($lockUntil) !== false && strtotime($lockUntil) > time()) {
            $this->audit('imap_auth', 'error', 'blocked: account temporarily locked', ['oidc_sub' => (string) $oidcSub, 'lock_until' => $lockUntil]);
            $this->fail('This account is temporarily locked due to failed login attempts.');
        }

        $postAction = (string) ($_SESSION[self::SESSION_POST_LOGIN_ACTION] ?? '');
        if (in_array($postAction, $this->adminActions(), true) && $this->isAdminUser()) {
            unset($_SESSION[self::SESSION_POST_LOGIN_ACTION]);
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => $postAction]));
        }

        $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
        if (!$mailbox) {
            $this->redirectTo($this->urlForAction(self::ACTION_CONNECT));
        }
        if ($this->isClientWrapMailbox($mailbox) && !$this->hasUnlockedClientWrapPassword()) {
            $this->redirectTo($this->urlForAction(self::ACTION_UNLOCK));
        }

        if (!$this->isHostAllowed('imap', (string) $mailbox['imap_host']) || !$this->isHostAllowed('smtp', (string) $mailbox['smtp_host'])) {
            $this->audit('policy_block', 'error', 'autologin blocked by host policy', [
                'imap_host' => (string) $mailbox['imap_host'],
                'smtp_host' => (string) $mailbox['smtp_host'],
            ]);
            $this->fail('Mailbox profile blocked by admin host policy.');
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            if ($this->isClientWrapMailbox($mailbox)) {
                $this->redirectTo($this->urlForAction(self::ACTION_UNLOCK));
            }
            $this->audit('imap_auth', 'error', 'autologin password unavailable');
            $this->fail('Mailbox password unavailable. Please run setup again.');
        }

        $ok = false;
        $ok = $this->rc->login(
            (string) $email,
            $password,
            $this->formatServer((string) $mailbox['imap_host'], (int) $mailbox['imap_port'], (string) $mailbox['imap_security'])
        );

        if (!$ok || empty($_SESSION['user_id'])) {
            $this->storage->incrementFailedAuth((string) $oidcSub, $this->cfgInt('auth_lock_seconds', 600));
            $this->log('imap_auth_failure', [
                'sub' => (string) $oidcSub,
                'email' => (string) $email,
                'login_ok' => $ok ? '1' : '0',
                'has_user_id' => !empty($_SESSION['user_id']) ? '1' : '0',
            ]);
            $this->audit('imap_auth', 'error', 'autologin failed', [
                'login_ok' => $ok ? 1 : 0,
                'has_user_id' => !empty($_SESSION['user_id']) ? 1 : 0,
            ]);
            $this->fail('Mailbox auth/session setup failed. Please re-check app-password and retry.');
        }

        // Mirror Roundcube core login flow to make auth cookie/session durable
        // across subsequent requests (prevents "session invalid or expired").
        $this->rc->session->remove('temp');
        $this->rc->session->regenerate_id(false);
        $this->rc->session->set_auth_cookie();

        $this->storage->updateUserIdBySub((string) $oidcSub, (int) $_SESSION['user_id']);
        $this->storage->setIdentitySeenIp((string) $oidcSub, $this->clientIp());
        $this->storage->clearAuthLock((string) $oidcSub);
        $this->storage->upsertIdentity((string) $oidcSub, (string) $email, (int) $_SESSION['user_id']);
        $this->persistGroupsToPrefs();
        $this->audit('imap_auth', 'ok', 'autologin succeeded');

        $this->storage->touchMailboxUsage((string) $oidcSub);
        if (in_array($postAction, $this->adminActions(), true)) {
            unset($_SESSION[self::SESSION_POST_LOGIN_ACTION]);
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => $postAction]));
        }

        $this->redirectTo($this->rc->url(['task' => 'mail', 'mbox' => 'INBOX']));
    }

    public function actionConnect(): void
    {
        $forceSetup = $this->inputTruthy('force_setup');
        $prefillEmail = strtolower(trim((string) rcube_utils::get_input_value('_prefill_email', rcube_utils::INPUT_GPC)));

        if ($this->isBootstrapPending()) {
            if (!$this->isBootstrapAdminCandidate()) {
                $this->audit('bootstrap_gate', 'warn', 'non-admin blocked during bootstrap');
                $this->renderBootstrapBlockedPage();
            }
            $this->claimBootstrapOwner((string) ($_SESSION[self::SESSION_OIDC_SUB] ?? ''), (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? ''));
            if (!$this->isBootstrapOwner((string) ($_SESSION[self::SESSION_OIDC_SUB] ?? ''))) {
                $this->renderBootstrapOwnerBlockedPage();
            }
        }

        unset($_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD], $_SESSION[self::SESSION_CLIENT_WRAP_UNLOCKED_AT]);
        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if (!$oidcSub) {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        $identity = $this->storage->getIdentityBySub((string) $oidcSub);
        if (!empty($identity['is_disabled'])) {
            $this->fail('This account is disabled by administrator.');
        }

        $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
        if ($mailbox && !$forceSetup) {
            if ($this->isBootstrapPending()) {
                $this->redirectTo($this->urlForAction(self::ACTION_BOOTSTRAP));
            }
            if ($this->isClientWrapMailbox($mailbox) && !$this->hasUnlockedClientWrapPassword()) {
                $this->redirectTo($this->urlForAction(self::ACTION_UNLOCK));
            }
            $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
        }

        if ($mailbox && $forceSetup) {
            $this->renderConnectMailboxPage('', false, [
                'email' => $prefillEmail !== '' ? $prefillEmail : (string) ($mailbox['email'] ?? ''),
                'imap_host' => (string) ($mailbox['imap_host'] ?? ''),
                'imap_port' => (string) ($mailbox['imap_port'] ?? ''),
                'imap_security' => (string) ($mailbox['imap_security'] ?? 'ssl'),
                'smtp_host' => (string) ($mailbox['smtp_host'] ?? ''),
                'smtp_port' => (string) ($mailbox['smtp_port'] ?? ''),
                'smtp_security' => (string) ($mailbox['smtp_security'] ?? 'tls'),
                'smtp_user' => (string) ($mailbox['smtp_user'] ?? ''),
                'smtp_auth' => !empty($mailbox['smtp_auth']) ? '1' : '0',
            ]);
            return;
        }

        $renderValues = [];
        if ($prefillEmail !== '') {
            $renderValues['email'] = $prefillEmail;
        }
        $this->renderConnectMailboxPage('', false, $renderValues);
    }

    public function actionSaveMailbox(): void
    {
        if ($this->isBootstrapPending()) {
            if (!$this->isBootstrapAdminCandidate()) {
                $this->audit('bootstrap_gate', 'warn', 'non-admin save blocked during bootstrap');
                $this->renderBootstrapBlockedPage();
            }
            if (!$this->isBootstrapOwner((string) ($_SESSION[self::SESSION_OIDC_SUB] ?? ''))) {
                $this->renderBootstrapOwnerBlockedPage();
            }
        }

        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        $oidcEmail = $_SESSION[self::SESSION_OIDC_EMAIL] ?? null;

        if (!$oidcSub || !$oidcEmail) {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        $identity = $this->storage->getIdentityBySub((string) $oidcSub);
        if (!empty($identity['is_disabled'])) {
            $this->fail('This account is disabled by administrator.');
        }

        if (!$this->checkSetupRateLimit()) {
            $this->renderConnectMailboxPage('Too many attempts. Please wait and try again.');
            return;
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->renderConnectMailboxPage('Invalid CSRF token.');
            return;
        }

        $email = strtolower(trim((string) rcube_utils::get_input_value('email', rcube_utils::INPUT_POST)));
        $password = (string) rcube_utils::get_input_value('app_password', rcube_utils::INPUT_POST);
        $imapHost = trim((string) rcube_utils::get_input_value('imap_host', rcube_utils::INPUT_POST));
        $imapPort = (int) rcube_utils::get_input_value('imap_port', rcube_utils::INPUT_POST);
        $imapSecurity = strtolower(trim((string) rcube_utils::get_input_value('imap_security', rcube_utils::INPUT_POST)));
        $smtpHost = trim((string) rcube_utils::get_input_value('smtp_host', rcube_utils::INPUT_POST));
        $smtpPort = (int) rcube_utils::get_input_value('smtp_port', rcube_utils::INPUT_POST);
        $smtpSecurity = strtolower(trim((string) rcube_utils::get_input_value('smtp_security', rcube_utils::INPUT_POST)));
        $smtpUser = trim((string) rcube_utils::get_input_value('smtp_user', rcube_utils::INPUT_POST));
        $smtpAuth = rcube_utils::get_input_value('smtp_auth', rcube_utils::INPUT_POST) ? 1 : 0;
        $intent = strtolower(trim((string) rcube_utils::get_input_value('intent', rcube_utils::INPUT_POST)));
        $clientWrapEnabled = $this->isClientWrapEnabled();
        $clientWrapBlobB64 = trim((string) rcube_utils::get_input_value('client_wrap_blob', rcube_utils::INPUT_POST));
        $clientWrapNonceB64 = trim((string) rcube_utils::get_input_value('client_wrap_nonce', rcube_utils::INPUT_POST));
        $clientWrapSaltB64 = trim((string) rcube_utils::get_input_value('client_wrap_salt', rcube_utils::INPUT_POST));
        $clientWrapKdf = strtolower(trim((string) rcube_utils::get_input_value('client_wrap_kdf', rcube_utils::INPUT_POST)));
        $clientWrapVersion = trim((string) rcube_utils::get_input_value('client_wrap_version', rcube_utils::INPUT_POST));
        $clientWrapIters = (int) rcube_utils::get_input_value('client_wrap_iters', rcube_utils::INPUT_POST);
        $lockedImapHost = $this->getLockedHostPolicy('imap');
        $lockedSmtpHost = $this->getLockedHostPolicy('smtp');

        if ($email === '' || (!$clientWrapEnabled && $password === '')) {
            $this->renderConnectMailboxPage('Email and app-password are required.');
            return;
        }
        if ($clientWrapEnabled && $intent === 'test') {
            $this->renderConnectMailboxPage('Connection test is disabled in client-side encryption mode. Save and continue.');
            return;
        }

        if ($this->isStrictOidcEmailBinding() && $email !== strtolower((string) $oidcEmail)) {
            $this->renderConnectMailboxPage('Email must match your OIDC account.');
            return;
        }

        if (!$this->isAllowedEmailDomain($email)) {
            $this->renderConnectMailboxPage('Email domain is not allowed.');
            return;
        }

        if (!in_array($imapSecurity, ['ssl', 'tls', 'starttls', 'none'], true) || !in_array($smtpSecurity, ['ssl', 'tls', 'starttls', 'none'], true)) {
            $this->renderConnectMailboxPage('Invalid security mode.');
            return;
        }

        if ($lockedImapHost !== null) {
            $imapHost = $lockedImapHost;
        }
        if ($lockedSmtpHost !== null) {
            $smtpHost = $lockedSmtpHost;
        }

        $imapHost = $imapHost !== '' ? $imapHost : $this->cfg('default_imap_host', 'imap.example.com');
        $imapPort = $imapPort > 0 ? $imapPort : (int) $this->cfg('default_imap_port', '993');
        $smtpHost = $smtpHost !== '' ? $smtpHost : $this->cfg('default_smtp_host', 'smtp.example.com');
        $smtpPort = $smtpPort > 0 ? $smtpPort : (int) $this->cfg('default_smtp_port', '587');
        if (!$this->isHostAllowed('imap', $imapHost) || !$this->isHostAllowed('smtp', $smtpHost)) {
            $this->renderConnectMailboxPage('Host is not allowed by admin policy.');
            return;
        }
        if ($intent === '') {
            $intent = 'save';
        }
        $smtpUser = $smtpUser !== '' ? $smtpUser : $email;
        if (!$smtpAuth) {
            $smtpUser = '';
        }
        if ($clientWrapEnabled) {
            if ($clientWrapBlobB64 === '' || $clientWrapNonceB64 === '' || $clientWrapSaltB64 === '') {
                $this->renderConnectMailboxPage('Client-side encryption payload missing. Please retry setup.');
                return;
            }
            if ($clientWrapKdf === '') {
                $clientWrapKdf = 'pbkdf2-sha256';
            }
            if ($clientWrapVersion === '') {
                $clientWrapVersion = 'v1';
            }
            if ($clientWrapIters < 100000) {
                $this->renderConnectMailboxPage('Invalid client-side encryption parameters. Please retry setup.');
                return;
            }
        }

        if ($intent === 'test') {
            [$ok, $message] = $this->testMailboxConnection([
                'email' => $email,
                'password' => $password,
                'imap_host' => $imapHost,
                'imap_port' => $imapPort,
                'imap_security' => $imapSecurity,
                'smtp_host' => $smtpHost,
                'smtp_port' => $smtpPort,
                'smtp_security' => $smtpSecurity,
                'smtp_auth' => $smtpAuth,
                'smtp_user' => $smtpUser !== '' ? $smtpUser : $email,
            ]);

            $this->audit('mailbox_test', $ok ? 'ok' : 'error', $message);
            $this->renderConnectMailboxPage($message, !$ok, [
                'email' => $email,
                'imap_host' => $imapHost,
                'imap_port' => (string) $imapPort,
                'imap_security' => $imapSecurity,
                'smtp_host' => $smtpHost,
                'smtp_port' => (string) $smtpPort,
                'smtp_security' => $smtpSecurity,
                'smtp_user' => $smtpUser !== '' ? $smtpUser : $email,
                'smtp_auth' => $smtpAuth ? '1' : '0',
            ]);
            return;
        }

        try {
            $encrypted = $this->getCrypto()->encrypt($clientWrapEnabled ? '__CLIENT_WRAP__' : $password);
        } catch (Throwable $e) {
            $this->log('mailbox_encrypt_failure', ['err' => $e->getMessage()]);
            $this->audit('mailbox_provisioning', 'error', 'encryption failed');
            $this->renderConnectMailboxPage('Encryption setup error. Contact administrator.');
            return;
        }

        $this->storage->upsertMailbox([
            'user_id' => $_SESSION['user_id'] ?? null,
            'oidc_sub' => (string) $oidcSub,
            'email' => $email,
            'imap_host' => $imapHost,
            'imap_port' => $imapPort,
            'imap_security' => $imapSecurity,
            'smtp_host' => $smtpHost,
            'smtp_port' => $smtpPort,
            'smtp_security' => $smtpSecurity,
            'smtp_auth' => $smtpAuth,
            'smtp_user' => $smtpUser,
            'password_enc' => $encrypted['password_enc'],
            'enc_alg' => $encrypted['enc_alg'],
            'enc_nonce' => $encrypted['enc_nonce'],
            'key_id' => $encrypted['key_id'] ?? 'v1',
            'client_wrap_enabled' => $clientWrapEnabled ? 1 : 0,
            'client_wrap_blob' => $clientWrapEnabled ? base64_decode($clientWrapBlobB64, true) : null,
            'client_wrap_nonce' => $clientWrapEnabled ? base64_decode($clientWrapNonceB64, true) : null,
            'client_wrap_salt' => $clientWrapEnabled ? base64_decode($clientWrapSaltB64, true) : null,
            'client_wrap_kdf' => $clientWrapEnabled ? $clientWrapKdf : null,
            'client_wrap_iters' => $clientWrapEnabled ? $clientWrapIters : null,
            'client_wrap_version' => $clientWrapEnabled ? $clientWrapVersion : null,
        ]);

        $_SESSION[self::SESSION_OIDC_EMAIL] = $email;
        unset($_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD], $_SESSION[self::SESSION_CLIENT_WRAP_UNLOCKED_AT]);
        $this->log('mailbox_provisioned', ['sub' => (string) $oidcSub, 'email' => $email]);
        $this->audit('mailbox_provisioning', 'ok', 'mailbox profile saved');
        if ($this->isBootstrapPending() && $this->isBootstrapAdminCandidate()) {
            $this->redirectTo($this->urlForAction(self::ACTION_BOOTSTRAP));
        }
        if ($clientWrapEnabled) {
            $this->redirectTo($this->urlForAction(self::ACTION_UNLOCK));
        }
        $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
    }

    public function actionBootstrap(): void
    {
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $oidcEmail = (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '');
        if ($oidcSub === '' || $oidcEmail === '') {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        if (!$this->isBootstrapPending()) {
            $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
        }

        if (!$this->isBootstrapAdminCandidate()) {
            $this->audit('bootstrap_gate', 'warn', 'non-admin attempted bootstrap onboarding');
            $this->renderBootstrapBlockedPage();
        }

        $this->claimBootstrapOwner($oidcSub, $oidcEmail);
        if (!$this->isBootstrapOwner($oidcSub)) {
            $this->renderBootstrapOwnerBlockedPage();
        }

        $policies = $this->getPolicies();
        $file = __DIR__ . '/skins/elastic/templates/bootstrap_onboarding.html';
        $template = file_get_contents($file);
        if ($template === false) {
            throw new rcube_exception('Cannot load bootstrap onboarding template.');
        }

        $html = strtr($template, [
            '{{save_action}}' => htmlspecialchars($this->urlForAction(self::ACTION_BOOTSTRAP_SAVE), ENT_QUOTES, 'UTF-8'),
            '{{csrf_token}}' => htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8'),
            '{{oidc_email}}' => htmlspecialchars($oidcEmail, ENT_QUOTES, 'UTF-8'),
            '{{client_side_wrap_enabled_checked}}' => !empty($policies['client_side_wrap_enabled'])
                && in_array(strtolower((string) $policies['client_side_wrap_enabled']), ['1', 'true', 'yes', 'on'], true)
                ? 'checked'
                : '',
            '{{allow_custom_mailbox_email_checked}}' => !empty($policies['allow_custom_mailbox_email'])
                && in_array(strtolower((string) $policies['allow_custom_mailbox_email']), ['1', 'true', 'yes', 'on'], true)
                ? 'checked'
                : '',
            '{{hide_standard_login_form_checked}}' => $this->isStandardLoginHidden() ? 'checked' : '',
            '{{login_mode_auto_selected}}' => $this->sanitizeLoginMode((string) ($policies['login_mode'] ?? $this->cfg('login_mode', 'auto'))) === 'auto' ? 'selected' : '',
            '{{login_mode_button_selected}}' => $this->sanitizeLoginMode((string) ($policies['login_mode'] ?? $this->cfg('login_mode', 'auto'))) === 'button' ? 'selected' : '',
            '{{login_button_text}}' => htmlspecialchars($this->loginButtonText(), ENT_QUOTES, 'UTF-8'),
        ]);

        header('Content-Type: text/html; charset=UTF-8');
        echo $html;
        exit;
    }

    public function actionBootstrapSave(): void
    {
        if (!$this->isBootstrapAdminCandidate()) {
            $this->audit('bootstrap_onboarding_save', 'error', 'non-admin attempted bootstrap save');
            $this->renderBootstrapBlockedPage();
        }
        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->audit('bootstrap_onboarding_save', 'error', 'invalid csrf token');
            $this->fail('Invalid CSRF token.');
        }

        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $oidcEmail = (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '');
        if ($oidcSub === '' || $oidcEmail === '') {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }
        if (!$this->isBootstrapPending()) {
            $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
        }
        if (!$this->isBootstrapOwner($oidcSub)) {
            $this->renderBootstrapOwnerBlockedPage();
        }

        $securityProfile = strtolower(trim((string) rcube_utils::get_input_value('security_profile', rcube_utils::INPUT_POST)));
        if (!in_array($securityProfile, ['strict', 'balanced'], true)) {
            $securityProfile = 'balanced';
        }

        $clientSideWrapEnabled = $this->postCheckboxEnabled('client_side_wrap_enabled') ? '1' : '0';
        $allowCustomMailboxEmail = $this->postCheckboxEnabled('allow_custom_mailbox_email') ? '1' : '0';
        $loginMode = $this->sanitizeLoginMode((string) rcube_utils::get_input_value('login_mode', rcube_utils::INPUT_POST));
        $hideStandardLoginForm = $this->postCheckboxEnabled('hide_standard_login_form') ? '1' : '0';
        $loginButtonText = trim((string) rcube_utils::get_input_value('login_button_text', rcube_utils::INPUT_POST));
        $mailboxNext = strtolower(trim((string) rcube_utils::get_input_value('bootstrap_mailbox_next', rcube_utils::INPUT_POST)));
        if (!in_array($mailboxNext, ['setup_now', 'setup_later'], true)) {
            $mailboxNext = 'setup_now';
        }
        if ($loginMode === 'button') {
            if ($loginButtonText === '') {
                $loginButtonText = 'Login with SSO';
            }
        } else {
            // Auto mode has no button. Keep button-related policy inert.
            $hideStandardLoginForm = '1';
            $loginButtonText = '';
        }

        if ($securityProfile === 'strict') {
            $this->storage->setPolicy('session_idle_timeout_sec', '1200');
            $this->storage->setPolicy('session_absolute_timeout_sec', '28800');
            $this->storage->setPolicy('login_rate_limit_per_5m', '10');
            $this->storage->setPolicy('callback_rate_limit_per_5m', '20');
            $this->storage->setPolicy('setup_rate_limit_per_5m', '6');
            $this->storage->setPolicy('auth_lock_seconds', '900');
        } else {
            $this->storage->setPolicy('session_idle_timeout_sec', '1800');
            $this->storage->setPolicy('session_absolute_timeout_sec', '43200');
            $this->storage->setPolicy('login_rate_limit_per_5m', '20');
            $this->storage->setPolicy('callback_rate_limit_per_5m', '30');
            $this->storage->setPolicy('setup_rate_limit_per_5m', '8');
            $this->storage->setPolicy('auth_lock_seconds', '600');
        }

        $this->storage->setPolicy('client_side_wrap_enabled', $clientSideWrapEnabled);
        $this->storage->setPolicy('allow_custom_mailbox_email', $allowCustomMailboxEmail);
        $this->storage->setPolicy('hide_standard_login_form', $hideStandardLoginForm);
        $this->storage->setPolicy('login_mode', $loginMode);
        $this->storage->setPolicy('login_button_text', $loginButtonText);
        $this->storage->setPolicy('bootstrap_owner_sub', $oidcSub);
        $this->storage->setPolicy('bootstrap_owner_email', $oidcEmail);
        $this->storage->setPolicy('bootstrap_completed', '1');
        $this->storage->setPolicy('bootstrap_completed_at', gmdate('Y-m-d H:i:s'));
        $this->policyCache = null;

        // Reset mappings/local state and continue straight to mailbox setup for
        // the bootstrap admin, so first-run onboarding is contiguous.
        $this->storage->purgeMappingsForModeSwitch(true);
        unset(
            $_SESSION[self::SESSION_POST_LOGIN_ACTION],
            $_SESSION[self::SESSION_AUTLOGIN],
            $_SESSION[self::SESSION_SETUP_RATE],
            $_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD],
            $_SESSION[self::SESSION_CLIENT_WRAP_UNLOCKED_AT],
            $_SESSION['user_id'],
            $_SESSION['username']
        );
        if ($mailboxNext === 'setup_later') {
            $_SESSION[self::SESSION_POST_LOGIN_ACTION] = self::ACTION_ADMIN;
            $this->audit('bootstrap_onboarding', 'ok', 'bootstrap onboarding completed; mailbox setup deferred by admin');
            $this->redirectTo($this->rc->url([
                'task' => 'settings',
                'action' => self::ACTION_ADMIN,
            ]));
        }

        $this->audit('bootstrap_onboarding', 'ok', 'bootstrap onboarding completed; redirecting to mailbox setup');
        $this->redirectTo($this->rc->url([
            'task' => 'login',
            'action' => self::ACTION_CONNECT,
            '_force_setup' => 1,
        ]));
    }

    private function loadMailboxFromSession(): ?array
    {
        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if ($oidcSub) {
            $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
            if ($mailbox) {
                return $mailbox;
            }
        }

        $userId = (int) ($_SESSION['user_id'] ?? 0);
        if ($userId > 0) {
            $mailbox = $this->storage->getMailboxByUserId($userId);
            if ($mailbox) {
                if (!empty($mailbox['oidc_sub'])) {
                    $_SESSION[self::SESSION_OIDC_SUB] = (string) $mailbox['oidc_sub'];
                }
                if (!empty($mailbox['email'])) {
                    $_SESSION[self::SESSION_OIDC_EMAIL] = strtolower((string) $mailbox['email']);
                }
                return $mailbox;
            }
        }

        $email = strtolower(trim((string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '')));
        if ($email === '' && !empty($this->rc->user)) {
            $email = strtolower(trim((string) $this->rc->user->get_username()));
        }
        if ($email !== '') {
            $mailbox = $this->storage->getMailboxByEmail($email);
            if ($mailbox) {
                if (!empty($mailbox['oidc_sub'])) {
                    $_SESSION[self::SESSION_OIDC_SUB] = (string) $mailbox['oidc_sub'];
                }
                return $mailbox;
            }
        }

        return null;
    }

    private function renderConnectMailboxPage(string $message, bool $isError = true, array $values = []): void
    {
        $file = __DIR__ . '/skins/elastic/templates/connect_mailbox.html';
        $template = file_get_contents($file);
        if ($template === false) {
            throw new rcube_exception('Cannot load connect mailbox template.');
        }

        $defaultEmail = (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '');
        $email = (string) ($values['email'] ?? $defaultEmail);
        $imapSecurity = (string) ($values['imap_security'] ?? $this->cfg('default_imap_security', 'ssl'));
        $smtpSecurity = (string) ($values['smtp_security'] ?? $this->cfg('default_smtp_security', 'tls'));
        $smtpAuthChecked = (string) ($values['smtp_auth'] ?? (((string) $this->cfg('default_smtp_auth', '1') !== '0') ? '1' : '0'));
        $strictEmailBinding = $this->isStrictOidcEmailBinding();
        $clientWrapEnabled = $this->isClientWrapEnabled();
        $imapProfile = $this->hostPolicyProfile('imap');
        $smtpProfile = $this->hostPolicyProfile('smtp');
        $imapHostValue = (string) ($values['imap_host'] ?? $this->cfg('default_imap_host', 'imap.example.com'));
        $smtpHostValue = (string) ($values['smtp_host'] ?? $this->cfg('default_smtp_host', 'smtp.example.com'));

        $buildHostField = static function (string $name, array $profile, string $value, string $placeholder): string {
            $esc = static fn (string $v): string => htmlspecialchars($v, ENT_QUOTES, 'UTF-8');
            if (($profile['mode'] ?? 'free') === 'single') {
                $locked = (string) ($profile['hosts'][0] ?? $value);
                return '<input type="hidden" name="' . $esc($name) . '" value="' . $esc($locked) . '">'
                    . '<input class="form-control" type="text" value="' . $esc($locked) . '" readonly>'
                    . '<div class="hint">Server is enforced by admin policy.</div>';
            }

            if (($profile['mode'] ?? 'free') === 'multi') {
                $hosts = (array) ($profile['hosts'] ?? []);
                if ($value === '' || !in_array(strtolower($value), $hosts, true)) {
                    $value = (string) ($hosts[0] ?? '');
                }
                $html = '<select class="form-select" name="' . $esc($name) . '">';
                foreach ($hosts as $h) {
                    $html .= '<option value="' . $esc($h) . '"' . (strtolower($h) === strtolower($value) ? ' selected' : '') . '>' . $esc($h) . '</option>';
                }
                $html .= '</select><div class="hint">Choose one of the allowed servers.</div>';
                return $html;
            }

            $listId = $esc($name) . '_datalist';
            $suggestions = '';
            $hint = 'You can enter your own server host.';
            $hosts = (array) ($profile['hosts'] ?? []);
            if (!empty($hosts)) {
                $suggestions = '<datalist id="' . $listId . '">';
                foreach ($hosts as $h) {
                    $suggestions .= '<option value="' . $esc($h) . '"></option>';
                }
                $suggestions .= '</datalist>';
                $hint = 'Custom host allowed. Suggested: ' . implode(', ', array_map($esc, $hosts));
            }

            return '<input class="form-control" type="text" name="' . $esc($name) . '" value="' . $esc($value) . '" placeholder="' . $esc($placeholder) . '"' . ($suggestions !== '' ? ' list="' . $listId . '"' : '') . '>'
                . $suggestions
                . '<div class="hint">' . $hint . '</div>';
        };

        $compactServerMode = $imapProfile['mode'] === 'single' && $smtpProfile['mode'] === 'single';

        $replacements = [
            '{{form_action}}' => htmlspecialchars($this->rc->url(['task' => 'login', 'action' => self::ACTION_SAVE_MAILBOX]), ENT_QUOTES, 'UTF-8'),
            '{{csrf_token}}' => htmlspecialchars(rcmail::get_instance()->get_request_token(), ENT_QUOTES, 'UTF-8'),
            '{{message}}' => $message !== '' ? '<div class="' . ($isError ? 'pizsso-error' : 'pizsso-success') . '">' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</div>' : '',
            '{{email}}' => htmlspecialchars($email, ENT_QUOTES, 'UTF-8'),
            '{{email_readonly_attr}}' => $strictEmailBinding ? 'readonly' : '',
            '{{email_policy_hint}}' => $strictEmailBinding
                ? '<div class="hint">Email is locked to your verified OIDC account by admin policy.</div>'
                : '<div class="hint">Admin policy allows overriding mailbox email.</div>',
            '{{imap_host_field}}' => $buildHostField('imap_host', $imapProfile, strtolower($imapHostValue), 'imap.example.com'),
            '{{imap_port}}' => htmlspecialchars((string) ($values['imap_port'] ?? $this->cfg('default_imap_port', '993')), ENT_QUOTES, 'UTF-8'),
            '{{imap_security_ssl_selected}}' => ($imapSecurity === 'ssl') ? 'selected' : '',
            '{{imap_security_tls_selected}}' => ($imapSecurity === 'tls') ? 'selected' : '',
            '{{imap_security_starttls_selected}}' => ($imapSecurity === 'starttls') ? 'selected' : '',
            '{{imap_security_none_selected}}' => ($imapSecurity === 'none') ? 'selected' : '',
            '{{smtp_host_field}}' => $buildHostField('smtp_host', $smtpProfile, strtolower($smtpHostValue), 'smtp.example.com'),
            '{{smtp_port}}' => htmlspecialchars((string) ($values['smtp_port'] ?? $this->cfg('default_smtp_port', '587')), ENT_QUOTES, 'UTF-8'),
            '{{smtp_security_ssl_selected}}' => ($smtpSecurity === 'ssl') ? 'selected' : '',
            '{{smtp_security_tls_selected}}' => ($smtpSecurity === 'tls') ? 'selected' : '',
            '{{smtp_security_starttls_selected}}' => ($smtpSecurity === 'starttls') ? 'selected' : '',
            '{{smtp_security_none_selected}}' => ($smtpSecurity === 'none') ? 'selected' : '',
            '{{smtp_auth_checked}}' => ($smtpAuthChecked !== '0') ? 'checked' : '',
            '{{smtp_user}}' => htmlspecialchars((string) ($values['smtp_user'] ?? $email), ENT_QUOTES, 'UTF-8'),
            '{{client_wrap_enabled}}' => $clientWrapEnabled ? '1' : '0',
            '{{client_wrap_block_display}}' => $clientWrapEnabled ? '' : 'display:none;',
            '{{test_button_disabled_attr}}' => $clientWrapEnabled ? 'disabled' : '',
            '{{test_button_disabled_hint}}' => $clientWrapEnabled ? '<div class="hint">Test is disabled in client-side encryption mode.</div>' : '',
            '{{server_section_style}}' => $compactServerMode ? 'display:none;' : '',
            '{{compact_server_hint}}' => $compactServerMode
                ? '<div class="helper-box mb-3"><strong>Server settings are preconfigured by your administrator.</strong><div class="mt-2">IMAP: '
                    . htmlspecialchars((string) ($imapProfile['hosts'][0] ?? ''), ENT_QUOTES, 'UTF-8')
                    . ' | SMTP: '
                    . htmlspecialchars((string) ($smtpProfile['hosts'][0] ?? ''), ENT_QUOTES, 'UTF-8')
                    . '</div></div>'
                : '',
            '{{onboarding_banner_text}}' => htmlspecialchars(
                $clientWrapEnabled
                    ? 'One-time secure onboarding. Your app-password is encrypted client-side before upload; only a wrapped payload is stored server-side.'
                    : 'One-time secure onboarding. Credentials are encrypted server-side before storage and reused for automatic sign-in.',
                ENT_QUOTES,
                'UTF-8'
            ),
        ];

        header('Content-Type: text/html; charset=UTF-8');
        echo strtr($template, $replacements);
        exit;
    }

    private function checkSetupRateLimit(): bool
    {
        $windowSec = 300;
        $maxAttempts = $this->cfgInt('setup_rate_limit_per_5m', 8);
        return $this->consumeRateLimit('setup_mailbox', $this->clientIp(), $windowSec, $maxAttempts);
    }

    private function oidcClient(): OidcClient
    {
        $policies = $this->getPolicies();
        return new OidcClient([
            'issuer' => (string) $this->cfg('issuer'),
            'client_id' => (string) $this->cfg('client_id'),
            'client_secret' => (string) $this->cfg('client_secret', ''),
            'redirect_uri' => (string) $this->cfg('redirect_uri', $this->defaultRedirectUri()),
            'scope' => (string) $this->cfg('scopes', 'openid email profile groups'),
            'allowed_issuers' => (string) ($policies['allowed_issuers'] ?? $this->cfg('allowed_issuers', '')),
            'metadata_pin_sha256' => (string) ($policies['metadata_pin_sha256'] ?? $this->cfg('metadata_pin_sha256', '')),
        ]);
    }

    private function isAllowedEmailDomain(string $email): bool
    {
        $at = strrpos($email, '@');
        if ($at === false) {
            return false;
        }

        $domain = strtolower(substr($email, $at + 1));
        $policies = $this->getPolicies();
        $list = trim((string) ($policies['allowed_email_domains'] ?? ''));
        if ($list === '') {
            $list = strtolower(trim((string) $this->cfg('allowed_email_domain', '')));
        }

        if ($list === '' || $list === '*') {
            return true;
        }

        foreach (preg_split('/[\s,]+/', $list, -1, PREG_SPLIT_NO_EMPTY) as $allowed) {
            $allowed = strtolower(trim($allowed));
            if ($allowed === '*') {
                return true;
            }
            if ($allowed !== '' && $domain === $allowed) {
                return true;
            }
        }

        return false;
    }

    private function isHostAllowed(string $type, string $host): bool
    {
        $host = strtolower(trim($host));
        if ($host === '') {
            return false;
        }

        $policies = $this->getPolicies();
        $key = $type === 'imap' ? 'allowed_imap_hosts' : 'allowed_smtp_hosts';
        $list = trim((string) ($policies[$key] ?? ''));
        if ($list === '' || $list === '*') {
            return true;
        }

        foreach (preg_split('/[\s,]+/', $list, -1, PREG_SPLIT_NO_EMPTY) as $allowed) {
            $allowed = strtolower(trim($allowed));
            if ($allowed === '*' || $allowed === $host) {
                return true;
            }
        }

        return false;
    }

    private function getLockedHostPolicy(string $type): ?string
    {
        $key = $type === 'imap' ? 'allowed_imap_hosts' : 'allowed_smtp_hosts';
        $policies = $this->getPolicies();
        $raw = trim((string) ($policies[$key] ?? ''));
        if ($raw === '' || $raw === '*') {
            return null;
        }

        $hosts = preg_split('/[\s,]+/', strtolower($raw), -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $hosts = array_values(array_unique(array_map(static fn ($v) => trim((string) $v), $hosts)));
        if (count($hosts) !== 1) {
            return null;
        }
        $host = (string) ($hosts[0] ?? '');
        if ($host === '' || $host === '*') {
            return null;
        }

        return $host;
    }

    private function hostPolicyProfile(string $type): array
    {
        $key = $type === 'imap' ? 'allowed_imap_hosts' : 'allowed_smtp_hosts';
        $policies = $this->getPolicies();
        $raw = strtolower(trim((string) ($policies[$key] ?? '')));
        if ($raw === '' || $raw === '*') {
            return ['mode' => 'free', 'hosts' => []];
        }

        $hasWildcard = strpos($raw, '*') !== false;
        $hosts = preg_split('/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $hosts = array_values(array_unique(array_map(static fn ($v) => trim((string) $v), $hosts)));
        $hosts = array_values(array_filter($hosts, static fn ($v) => $v !== '' && $v !== '*'));
        if ($hasWildcard) {
            return ['mode' => 'free', 'hosts' => $hosts];
        }
        if (count($hosts) <= 0) {
            return ['mode' => 'free', 'hosts' => []];
        }
        if (count($hosts) === 1) {
            return ['mode' => 'single', 'hosts' => $hosts];
        }

        return ['mode' => 'multi', 'hosts' => $hosts];
    }

    private function getPolicies(): array
    {
        if ($this->policyCache !== null) {
            return $this->policyCache;
        }

        $this->policyCache = $this->storage->getPolicies([
            'allowed_email_domains',
            'allowed_imap_hosts',
            'allowed_smtp_hosts',
            'allow_custom_mailbox_email',
            'client_side_wrap_enabled',
            'bootstrap_completed',
            'bootstrap_owner_sub',
            'bootstrap_owner_email',
            'session_idle_timeout_sec',
            'session_absolute_timeout_sec',
            'login_rate_limit_per_5m',
            'callback_rate_limit_per_5m',
            'setup_rate_limit_per_5m',
            'auth_lock_seconds',
            'allowed_issuers',
            'metadata_pin_sha256',
            'login_mode',
            'hide_standard_login_form',
            'login_button_text',
        ]);

        return $this->policyCache;
    }

    private function formatServer(string $host, int $port, string $security): string
    {
        $scheme = $this->normalizeSecurity($security);
        $prefix = $scheme === 'none' ? '' : ($scheme . '://');
        return $prefix . $host . ':' . $port;
    }

    private function imapSslMode(string $security): string
    {
        $security = $this->normalizeSecurity($security);

        if ($security === 'ssl') {
            return 'ssl';
        }

        if ($security === 'tls') {
            return 'tls';
        }

        return 'none';
    }

    private function normalizeSecurity(string $security): string
    {
        $security = strtolower(trim($security));
        if ($security === 'starttls') {
            return 'tls';
        }

        return in_array($security, ['ssl', 'tls', 'none'], true) ? $security : 'none';
    }

    private function extractGroups(array $claims): array
    {
        $paths = [
            ['groups'],
            ['group'],
            ['roles'],
            ['role'],
            ['cognito:groups'],
            ['realm_access', 'roles'],
        ];

        $rawGroups = [];
        foreach ($paths as $path) {
            $val = $this->claimPath($claims, $path);
            if ($val !== null) {
                $rawGroups[] = $val;
            }
        }

        // Common JWT structure: resource_access.<client>.roles
        $resourceAccess = $this->claimPath($claims, ['resource_access']);
        if (is_array($resourceAccess)) {
            foreach ($resourceAccess as $clientAccess) {
                if (is_array($clientAccess) && array_key_exists('roles', $clientAccess)) {
                    $rawGroups[] = $clientAccess['roles'];
                }
            }
        }

        $normalized = [];
        foreach ($rawGroups as $raw) {
            foreach ($this->flattenGroupValues($raw) as $value) {
                $clean = trim((string) $value);
                if ($clean !== '') {
                    $normalized[] = $clean;
                }
            }
        }

        return array_values(array_unique($normalized));
    }

    private function claimPath(array $claims, array $path)
    {
        $current = $claims;
        foreach ($path as $segment) {
            if (!is_array($current) || !array_key_exists($segment, $current)) {
                return null;
            }
            $current = $current[$segment];
        }

        return $current;
    }

    private function flattenGroupValues($value): array
    {
        $out = [];
        if (is_string($value)) {
            $parts = preg_split('/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY);
            return is_array($parts) ? $parts : [];
        }

        if (is_scalar($value)) {
            return [(string) $value];
        }

        if (!is_array($value)) {
            return [];
        }

        foreach ($value as $entry) {
            if (is_array($entry)) {
                foreach (['name', 'group', 'role', 'value', 'id', 'slug'] as $k) {
                    if (isset($entry[$k]) && is_scalar($entry[$k])) {
                        $out[] = (string) $entry[$k];
                    }
                }
            } else {
                $out = array_merge($out, $this->flattenGroupValues($entry));
            }
        }

        return $out;
    }

    private function currentUserGroups(): array
    {
        $groups = $_SESSION[self::SESSION_OIDC_GROUPS] ?? [];
        if (is_array($groups) && !empty($groups)) {
            return $groups;
        }

        if (!empty($this->rc->user)) {
            $prefs = $this->rc->user->get_prefs();
            $stored = $prefs[self::PREF_OIDC_GROUPS] ?? [];
            if (is_string($stored)) {
                $stored = preg_split('/[\s,]+/', $stored, -1, PREG_SPLIT_NO_EMPTY);
            }
            if (is_array($stored) && !empty($stored)) {
                $_SESSION[self::SESSION_OIDC_GROUPS] = array_values($stored);
                return array_values($stored);
            }
        }

        return [];
    }

    private function persistGroupsToPrefs(): void
    {
        if (empty($this->rc->user)) {
            return;
        }

        $groups = $_SESSION[self::SESSION_OIDC_GROUPS] ?? [];
        if (!is_array($groups) || empty($groups)) {
            return;
        }

        $clean = [];
        foreach ($groups as $group) {
            if (is_scalar($group)) {
                $name = trim((string) $group);
                if ($name !== '') {
                    $clean[] = $name;
                }
            }
        }
        $clean = array_values(array_unique($clean));
        if (empty($clean)) {
            return;
        }

        $this->rc->user->save_prefs([self::PREF_OIDC_GROUPS => $clean]);
    }

    private function isAdminUser(): bool
    {
        $hasOidcIdentity = !empty($_SESSION[self::SESSION_OIDC_SUB]) || !empty($_SESSION[self::SESSION_OIDC_EMAIL]);
        if (!$hasOidcIdentity && empty($_SESSION['user_id'])) {
            return false;
        }

        $groups = $this->currentUserGroups();
        if (empty($groups)) {
            return false;
        }

        $adminGroupConfig = strtolower(trim((string) $this->cfg('admin_group_name', 'webmail_admin')));
        if ($adminGroupConfig === '') {
            return false;
        }
        $adminGroups = preg_split('/[\s,]+/', $adminGroupConfig, -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($adminGroups) || empty($adminGroups)) {
            return false;
        }

        foreach ($groups as $group) {
            $normalized = strtolower(trim((string) $group));
            if (in_array($normalized, $adminGroups, true)) {
                return true;
            }
        }

        // Fallback allowlist to avoid admin lockout when OIDC group claims are not emitted.
        $adminEmailsCfg = strtolower(trim((string) $this->cfg('admin_emails', '')));
        if ($adminEmailsCfg !== '') {
            $adminEmails = preg_split('/[\s,]+/', $adminEmailsCfg, -1, PREG_SPLIT_NO_EMPTY);
            $currentEmail = strtolower(trim((string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '')));
            if ($currentEmail !== '' && is_array($adminEmails) && in_array($currentEmail, $adminEmails, true)) {
                return true;
            }
        }

        return false;
    }

    private function isBootstrapAdminCandidate(): bool
    {
        $groups = $this->currentUserGroups();
        $adminGroupConfig = strtolower(trim((string) $this->cfg('admin_group_name', 'webmail_admin')));
        if ($adminGroupConfig !== '' && !empty($groups)) {
            $adminGroups = preg_split('/[\s,]+/', $adminGroupConfig, -1, PREG_SPLIT_NO_EMPTY);
            if (is_array($adminGroups) && !empty($adminGroups)) {
                foreach ($groups as $group) {
                    $normalized = strtolower(trim((string) $group));
                    if (in_array($normalized, $adminGroups, true)) {
                        return true;
                    }
                }
            }
        }

        $adminEmailsCfg = strtolower(trim((string) $this->cfg('admin_emails', '')));
        if ($adminEmailsCfg !== '') {
            $adminEmails = preg_split('/[\s,]+/', $adminEmailsCfg, -1, PREG_SPLIT_NO_EMPTY);
            $currentEmail = strtolower(trim((string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '')));
            if ($currentEmail !== '' && is_array($adminEmails) && in_array($currentEmail, $adminEmails, true)) {
                return true;
            }
        }

        return false;
    }

    private function isStrictOidcEmailBinding(): bool
    {
        $policies = $this->getPolicies();
        $policyVal = strtolower(trim((string) ($policies['allow_custom_mailbox_email'] ?? '')));
        if ($policyVal !== '') {
            return !in_array($policyVal, ['1', 'true', 'yes', 'on'], true);
        }

        // Strict by default unless explicitly disabled.
        return !$this->cfgBool('allow_custom_mailbox_email', false);
    }

    public function actionAdminDashboard(): void
    {
        $this->requireAdmin(false, 'admin_dashboard');
        if ($this->isBootstrapPending()) {
            if (!$this->isBootstrapAdminCandidate()) {
                $this->renderBootstrapBlockedPage();
            }
            $this->claimBootstrapOwner((string) ($_SESSION[self::SESSION_OIDC_SUB] ?? ''), (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? ''));
            if (!$this->isBootstrapOwner((string) ($_SESSION[self::SESSION_OIDC_SUB] ?? ''))) {
                $this->renderBootstrapOwnerBlockedPage();
            }
            $this->redirectTo($this->urlForAction(self::ACTION_BOOTSTRAP));
        }

        $overview = $this->storage->getAdminOverview(500);
        $audit = $this->storage->getRecentAudit(300);
        $policies = $this->getPolicies();

        $file = __DIR__ . '/skins/elastic/templates/admin_dashboard.html';
        $template = file_get_contents($file);
        if ($template === false) {
            throw new rcube_exception('Cannot load admin dashboard template.');
        }

        $rows = '';
        foreach ($overview as $row) {
            $rowSub = (string) ($row['oidc_sub'] ?? '');
            $isDisabled = !empty($row['is_disabled']);
            $setDisabledValue = $isDisabled ? '0' : '1';
            $setDisabledLabel = $isDisabled ? 'Enable' : 'Disable';
            $status = $isDisabled ? 'disabled' : 'active';
            if (!empty($row['lock_until']) && strtotime((string) $row['lock_until']) > time()) {
                $status = 'locked';
            }
            $statusClass = $status === 'active' ? 'status-active' : ($status === 'locked' ? 'status-locked' : 'status-disabled');
            $rows .= '<tr>'
                . '<td>' . htmlspecialchars((string) ($row['email'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td><span class="status-badge ' . htmlspecialchars($statusClass, ENT_QUOTES, 'UTF-8') . '">' . htmlspecialchars($status, ENT_QUOTES, 'UTF-8') . '</span></td>'
                . '<td>' . (!empty($row['imap_host']) ? 'yes' : 'no') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['imap_host'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['smtp_host'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['key_id'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['last_login_at'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['last_used_at'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['last_seen_ip'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['failed_auth_count'] ?? '0'), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>'
                . '<form method="post" action="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_SET_USER_STATUS]), ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;margin-right:6px;">'
                . '<input type="hidden" name="_token" value="' . htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="oidc_sub" value="' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="is_disabled" value="' . htmlspecialchars($setDisabledValue, ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="disabled_reason" value="">'
                . '<button type="submit" class="btn btn-sm btn-outline-secondary">' . htmlspecialchars($setDisabledLabel, ENT_QUOTES, 'UTF-8') . '</button>'
                . '</form>'
                . '<form method="post" action="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_CLEAR_MAILBOX]), ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;margin-right:6px;" onsubmit="return confirm(\'Remove mailbox mapping for this user?\');">'
                . '<input type="hidden" name="_token" value="' . htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="oidc_sub" value="' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '">'
                . '<button type="submit" class="btn btn-sm btn-outline-warning">Clear Mailbox</button>'
                . '</form>'
                . '<form method="post" action="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_DELETE_USER]), ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;" onsubmit="return confirm(\'Delete mapped account for this user?\');">'
                . '<input type="hidden" name="_token" value="' . htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="oidc_sub" value="' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '">'
                . '<button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>'
                . '</form>'
                . '<form method="post" action="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_SET_NOTE]), ENT_QUOTES, 'UTF-8') . '" style="margin-top:6px;">'
                . '<input type="hidden" name="_token" value="' . htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="oidc_sub" value="' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '">'
                . '<div style="display:flex;gap:6px;align-items:center;">'
                . '<input type="text" class="form-control form-control-sm" name="admin_note" value="' . htmlspecialchars((string) ($row['admin_note'] ?? ''), ENT_QUOTES, 'UTF-8') . '" placeholder="admin note" style="max-width:220px;">'
                . '<button type="submit" class="btn btn-sm btn-outline-primary">Save</button>'
                . '</div>'
                . '</form>'
                . '</td>'
                . '</tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="12">No identities found.</td></tr>';
        }

        $auditRows = '';
        foreach ($audit as $row) {
            $auditRows .= '<tr>'
                . '<td>' . htmlspecialchars((string) ($row['created_at'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['event'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['status'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['email'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['message'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '</tr>';
        }
        if ($auditRows === '') {
            $auditRows = '<tr><td colspan="5">No audit records found.</td></tr>';
        }

        $html = strtr($template, [
            '{{overview_rows}}' => $rows,
            '{{audit_rows}}' => $auditRows,
            '{{policy_form_action}}' => htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_SAVE_POLICY]), ENT_QUOTES, 'UTF-8'),
            '{{admin_logout_action}}' => htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_LOGOUT]), ENT_QUOTES, 'UTF-8'),
            '{{setup_mailbox_action_url}}' => htmlspecialchars($this->rc->url([
                'task' => 'login',
                'action' => self::ACTION_CONNECT,
                '_force_setup' => 1,
            ]), ENT_QUOTES, 'UTF-8'),
            '{{csrf_token}}' => htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8'),
            '{{setup_mailbox_action_url}}' => htmlspecialchars($this->rc->url([
                'task' => 'login',
                'action' => self::ACTION_CONNECT,
                '_force_setup' => 1,
            ]), ENT_QUOTES, 'UTF-8'),
            '{{allowed_domains}}' => htmlspecialchars((string) ($policies['allowed_email_domains'] ?? ''), ENT_QUOTES, 'UTF-8'),
            '{{allowed_imap_hosts}}' => htmlspecialchars((string) ($policies['allowed_imap_hosts'] ?? ''), ENT_QUOTES, 'UTF-8'),
            '{{allowed_smtp_hosts}}' => htmlspecialchars((string) ($policies['allowed_smtp_hosts'] ?? ''), ENT_QUOTES, 'UTF-8'),
            '{{allow_custom_mailbox_email_checked}}' => !empty($policies['allow_custom_mailbox_email'])
                && in_array(strtolower((string) $policies['allow_custom_mailbox_email']), ['1', 'true', 'yes', 'on'], true)
                ? 'checked'
                : '',
            '{{client_side_wrap_enabled_checked}}' => !empty($policies['client_side_wrap_enabled'])
                && in_array(strtolower((string) $policies['client_side_wrap_enabled']), ['1', 'true', 'yes', 'on'], true)
                ? 'checked'
                : '',
            '{{session_idle_timeout_sec}}' => htmlspecialchars((string) ($policies['session_idle_timeout_sec'] ?? $this->cfg('session_idle_timeout_sec', '1800')), ENT_QUOTES, 'UTF-8'),
            '{{session_absolute_timeout_sec}}' => htmlspecialchars((string) ($policies['session_absolute_timeout_sec'] ?? $this->cfg('session_absolute_timeout_sec', '43200')), ENT_QUOTES, 'UTF-8'),
            '{{login_rate_limit_per_5m}}' => htmlspecialchars((string) ($policies['login_rate_limit_per_5m'] ?? $this->cfg('login_rate_limit_per_5m', '20')), ENT_QUOTES, 'UTF-8'),
            '{{callback_rate_limit_per_5m}}' => htmlspecialchars((string) ($policies['callback_rate_limit_per_5m'] ?? $this->cfg('callback_rate_limit_per_5m', '30')), ENT_QUOTES, 'UTF-8'),
            '{{setup_rate_limit_per_5m}}' => htmlspecialchars((string) ($policies['setup_rate_limit_per_5m'] ?? $this->cfg('setup_rate_limit_per_5m', '8')), ENT_QUOTES, 'UTF-8'),
            '{{auth_lock_seconds}}' => htmlspecialchars((string) ($policies['auth_lock_seconds'] ?? $this->cfg('auth_lock_seconds', '600')), ENT_QUOTES, 'UTF-8'),
            '{{allowed_issuers}}' => htmlspecialchars((string) ($policies['allowed_issuers'] ?? $this->cfg('allowed_issuers', '')), ENT_QUOTES, 'UTF-8'),
            '{{metadata_pin_sha256}}' => htmlspecialchars((string) ($policies['metadata_pin_sha256'] ?? $this->cfg('metadata_pin_sha256', '')), ENT_QUOTES, 'UTF-8'),
            '{{login_mode_auto_selected}}' => $this->sanitizeLoginMode((string) ($policies['login_mode'] ?? $this->cfg('login_mode', 'auto'))) === 'auto' ? 'selected' : '',
            '{{login_mode_button_selected}}' => $this->sanitizeLoginMode((string) ($policies['login_mode'] ?? $this->cfg('login_mode', 'auto'))) === 'button' ? 'selected' : '',
            '{{hide_standard_login_form_checked}}' => $this->isStandardLoginHidden() ? 'checked' : '',
            '{{login_button_text}}' => htmlspecialchars($this->loginButtonText(), ENT_QUOTES, 'UTF-8'),
        ]);

        header('Content-Type: text/html; charset=UTF-8');
        echo $html;
        exit;
    }

    public function actionAdminSavePolicy(): void
    {
        $this->requireAdmin(true, 'admin_policy');

        $policiesBefore = $this->getPolicies();
        $allowedDomains = trim((string) rcube_utils::get_input_value('allowed_email_domains', rcube_utils::INPUT_POST));
        $allowedImapHosts = trim((string) rcube_utils::get_input_value('allowed_imap_hosts', rcube_utils::INPUT_POST));
        $allowedSmtpHosts = trim((string) rcube_utils::get_input_value('allowed_smtp_hosts', rcube_utils::INPUT_POST));
        $allowCustomMailboxEmail = $this->postCheckboxEnabled('allow_custom_mailbox_email') ? '1' : '0';
        $clientSideWrapEnabled = $this->postCheckboxEnabled('client_side_wrap_enabled') ? '1' : '0';
        $clientSideWrapWasEnabled = !empty($policiesBefore['client_side_wrap_enabled'])
            && in_array(strtolower((string) $policiesBefore['client_side_wrap_enabled']), ['1', 'true', 'yes', 'on'], true);
        $modeChanged = $clientSideWrapWasEnabled !== ($clientSideWrapEnabled === '1');

        $this->storage->setPolicy('allowed_email_domains', $allowedDomains);
        $this->storage->setPolicy('allowed_imap_hosts', $allowedImapHosts);
        $this->storage->setPolicy('allowed_smtp_hosts', $allowedSmtpHosts);
        $this->storage->setPolicy('allow_custom_mailbox_email', $allowCustomMailboxEmail);
        $this->storage->setPolicy('client_side_wrap_enabled', $clientSideWrapEnabled);
        $this->storage->setPolicy('session_idle_timeout_sec', (string) max(60, (int) rcube_utils::get_input_value('session_idle_timeout_sec', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('session_absolute_timeout_sec', (string) max(300, (int) rcube_utils::get_input_value('session_absolute_timeout_sec', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('login_rate_limit_per_5m', (string) max(1, (int) rcube_utils::get_input_value('login_rate_limit_per_5m', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('callback_rate_limit_per_5m', (string) max(1, (int) rcube_utils::get_input_value('callback_rate_limit_per_5m', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('setup_rate_limit_per_5m', (string) max(1, (int) rcube_utils::get_input_value('setup_rate_limit_per_5m', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('auth_lock_seconds', (string) max(60, (int) rcube_utils::get_input_value('auth_lock_seconds', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('allowed_issuers', trim((string) rcube_utils::get_input_value('allowed_issuers', rcube_utils::INPUT_POST)));
        $this->storage->setPolicy('metadata_pin_sha256', strtolower(trim((string) rcube_utils::get_input_value('metadata_pin_sha256', rcube_utils::INPUT_POST))));
        $loginMode = $this->sanitizeLoginMode((string) rcube_utils::get_input_value('login_mode', rcube_utils::INPUT_POST));
        $this->storage->setPolicy('login_mode', $loginMode);
        if ($loginMode === 'button') {
            $this->storage->setPolicy('hide_standard_login_form', $this->postCheckboxEnabled('hide_standard_login_form') ? '1' : '0');
            $this->storage->setPolicy('login_button_text', trim((string) rcube_utils::get_input_value('login_button_text', rcube_utils::INPUT_POST)));
        } else {
            // In auto-redirect mode, button-related settings are not used.
            $this->storage->setPolicy('hide_standard_login_form', '1');
            $this->storage->setPolicy('login_button_text', '');
        }
        $this->policyCache = null;

        if ($modeChanged) {
            $this->storage->purgeMappingsForModeSwitch(true);
            $this->audit(
                'admin_policy',
                'warn',
                'client-side wrap mode changed; mappings and local Roundcube state reset',
                ['client_side_wrap_enabled' => $clientSideWrapEnabled]
            );
            $this->resetLocalSessionForReonboarding();
            $this->redirectTo($this->urlForAction(self::ACTION_CONNECT));
        }

        $this->audit('admin_policy', 'ok', 'policy updated');
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    public function actionAdminDeleteUser(): void
    {
        $this->requireAdmin(true, 'admin_delete_user');

        $oidcSub = trim((string) rcube_utils::get_input_value('oidc_sub', rcube_utils::INPUT_POST));
        if ($oidcSub === '') {
            $this->fail('Missing user identifier.');
        }

        $currentSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        if ($currentSub !== '' && hash_equals($currentSub, $oidcSub)) {
            $this->audit('admin_delete_user', 'error', 'self-delete blocked', ['oidc_sub' => $oidcSub]);
            $this->fail('Refusing to delete currently logged-in admin mapping.');
        }

        $identity = $this->storage->getIdentityBySub($oidcSub);
        if (!$identity) {
            $this->audit('admin_delete_user', 'warn', 'user not found', ['oidc_sub' => $oidcSub]);
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
        }

        $this->storage->deleteMappedUserBySub($oidcSub);
        $this->audit('admin_delete_user', 'ok', 'mapped user deleted', [
            'oidc_sub' => $oidcSub,
            'email' => (string) ($identity['email'] ?? ''),
        ]);

        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    public function actionAdminSetUserStatus(): void
    {
        $this->requireAdmin(true, 'admin_set_user_status');

        $oidcSub = trim((string) rcube_utils::get_input_value('oidc_sub', rcube_utils::INPUT_POST));
        $isDisabled = rcube_utils::get_input_value('is_disabled', rcube_utils::INPUT_POST) ? 1 : 0;
        $disabledReason = trim((string) rcube_utils::get_input_value('disabled_reason', rcube_utils::INPUT_POST));

        if ($oidcSub === '') {
            $this->fail('Missing user identifier.');
        }

        $currentSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        if ($currentSub !== '' && hash_equals($currentSub, $oidcSub) && $isDisabled === 1) {
            $this->audit('admin_set_user_status', 'error', 'self-disable blocked', ['oidc_sub' => $oidcSub]);
            $this->fail('Refusing to disable currently logged-in admin mapping.');
        }

        $identity = $this->storage->getIdentityBySub($oidcSub);
        if (!$identity) {
            $this->audit('admin_set_user_status', 'warn', 'user not found', ['oidc_sub' => $oidcSub]);
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
        }

        $this->storage->setUserDisabledBySub($oidcSub, $isDisabled === 1, $disabledReason);
        $this->audit(
            'admin_set_user_status',
            'ok',
            $isDisabled === 1 ? 'user disabled' : 'user enabled',
            [
                'oidc_sub' => $oidcSub,
                'email' => (string) ($identity['email'] ?? ''),
                'is_disabled' => $isDisabled,
                'disabled_reason' => $disabledReason,
            ]
        );

        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    private function testMailboxConnection(array $cfg): array
    {
        [$imapOk, $imapMessage] = $this->testImapConnection($cfg);
        if (!$imapOk) {
            return [false, $imapMessage];
        }

        [$smtpOk, $smtpMessage] = $this->testSmtpConnection($cfg);
        if (!$smtpOk) {
            return [false, $smtpMessage];
        }

        return [true, 'IMAP/SMTP test succeeded. You can save this profile. ' . $smtpMessage];
    }

    private function testImapConnection(array $cfg): array
    {
        try {
            $imap = new rcube_imap_generic();
            $imapOk = $imap->connect(
                (string) $cfg['imap_host'],
                (string) $cfg['email'],
                (string) $cfg['password'],
                [
                    'port' => (int) $cfg['imap_port'],
                    'ssl_mode' => $this->normalizeSecurity((string) $cfg['imap_security']),
                    'auth_type' => 'check',
                ]
            );
            $imapError = $imapOk ? '' : (string) $imap->getErrorStr();
            $imap->close();
            if (!$imapOk) {
                return [false, 'IMAP test failed: ' . ($imapError ?: 'authentication/connection error')];
            }
        } catch (Throwable $e) {
            return [false, 'IMAP test failed: ' . $e->getMessage()];
        }

        return [true, 'IMAP test succeeded.'];
    }

    private function testSmtpConnection(array $cfg): array
    {
        try {
            $smtp = new rcube_smtp();
            $smtpUser = !empty($cfg['smtp_auth']) ? (string) $cfg['smtp_user'] : '';
            $smtpPass = !empty($cfg['smtp_auth']) ? (string) $cfg['password'] : '';
            $smtpUri = $this->formatServer((string) $cfg['smtp_host'], (int) $cfg['smtp_port'], (string) $cfg['smtp_security']);
            $smtpOk = $smtp->connect($smtpUri, null, $smtpUser, $smtpPass);
            $smtpErr = $smtp->get_error();
            $smtpError = '';
            if (is_array($smtpErr)) {
                $smtpError = (string) ($smtpErr['label'] ?? json_encode($smtpErr, JSON_UNESCAPED_SLASHES));
            } elseif (is_string($smtpErr)) {
                $smtpError = $smtpErr;
            }
            $smtp->disconnect();

            if (!$smtpOk) {
                return [
                    false,
                    'SMTP test failed: ' . ($smtpError ?: 'authentication/connection error')
                    . ' | diagnostics: host=' . (string) $cfg['smtp_host']
                    . ' port=' . (int) $cfg['smtp_port']
                    . ' security=' . (string) $cfg['smtp_security']
                    . ' auth=' . (!empty($cfg['smtp_auth']) ? 'on' : 'off')
                    . ' user=' . ($smtpUser !== '' ? $smtpUser : '(none)'),
                ];
            }
        } catch (Throwable $e) {
            return [false, 'SMTP test failed: ' . $e->getMessage()];
        }

        return [
            true,
            'SMTP diagnostics: host=' . (string) $cfg['smtp_host']
            . ' port=' . (int) $cfg['smtp_port']
            . ' security=' . (string) $cfg['smtp_security']
            . ' auth=' . (!empty($cfg['smtp_auth']) ? 'on' : 'off')
            . ' user=' . ((string) ($cfg['smtp_user'] ?? '') !== '' ? (string) $cfg['smtp_user'] : '(none)'),
        ];
    }

    private function cfg(string $name, ?string $default = null): ?string
    {
        $map = [
            'issuer' => 'OIDC_ISSUER',
            'client_id' => 'OIDC_CLIENT_ID',
            'client_secret' => 'OIDC_CLIENT_SECRET',
            'redirect_uri' => 'OIDC_REDIRECT_URI',
            'post_logout_redirect_uri' => 'OIDC_POST_LOGOUT_REDIRECT_URI',
            'allowed_issuers' => 'ALLOWED_ISSUERS',
            'metadata_pin_sha256' => 'METADATA_PIN_SHA256',
            'allowed_email_domain' => 'ALLOWED_EMAIL_DOMAIN',
            'allow_custom_mailbox_email' => 'ALLOW_CUSTOM_MAILBOX_EMAIL',
            'mailbox_key' => 'RCUBE_MAILBOX_KEY',
            'force_https' => 'FORCE_HTTPS',
            'disable_password_login' => 'DISABLE_PASSWORD_LOGIN',
            'login_mode' => 'LOGIN_MODE',
            'hide_standard_login_form' => 'HIDE_STANDARD_LOGIN_FORM',
            'login_button_text' => 'LOGIN_BUTTON_TEXT',
            'client_side_wrap_enabled' => 'CLIENT_SIDE_WRAP_ENABLED',
            'session_idle_timeout_sec' => 'SESSION_IDLE_TIMEOUT_SEC',
            'session_absolute_timeout_sec' => 'SESSION_ABSOLUTE_TIMEOUT_SEC',
            'login_rate_limit_per_5m' => 'LOGIN_RATE_LIMIT_PER_5M',
            'callback_rate_limit_per_5m' => 'CALLBACK_RATE_LIMIT_PER_5M',
            'setup_rate_limit_per_5m' => 'SETUP_RATE_LIMIT_PER_5M',
            'auth_lock_seconds' => 'AUTH_LOCK_SECONDS',
            'default_imap_host' => 'DEFAULT_IMAP_HOST',
            'default_imap_port' => 'DEFAULT_IMAP_PORT',
            'default_imap_security' => 'DEFAULT_IMAP_SECURITY',
            'default_smtp_host' => 'DEFAULT_SMTP_HOST',
            'default_smtp_port' => 'DEFAULT_SMTP_PORT',
            'default_smtp_security' => 'DEFAULT_SMTP_SECURITY',
            'default_smtp_auth' => 'DEFAULT_SMTP_AUTH',
            'admin_group_name' => 'ADMIN_GROUP_NAME',
            'user_group_name' => 'USER_GROUP_NAME',
            'admin_emails' => 'ADMIN_EMAILS',
            'scopes' => 'OIDC_SCOPES',
        ];

        $envName = $map[$name] ?? null;
        if ($envName !== null) {
            $envValue = getenv($envName);
            if ($envValue !== false && $envValue !== '') {
                return $envValue;
            }

            if (isset($_ENV[$envName]) && $_ENV[$envName] !== '') {
                return (string) $_ENV[$envName];
            }

            if (isset($_SERVER[$envName]) && $_SERVER[$envName] !== '') {
                return (string) $_SERVER[$envName];
            }
        }

        return $this->rc->config->get('universal_oidc_mail_sso_' . $name, $default);
    }

    private function cfgBool(string $name, bool $default): bool
    {
        $val = $this->cfg($name, $default ? 'true' : 'false');
        return in_array(strtolower((string) $val), ['1', 'true', 'yes', 'on'], true);
    }

    private function cfgInt(string $name, int $default): int
    {
        $raw = $this->cfg($name, (string) $default);
        if ($raw === null || $raw === '' || !preg_match('/^-?\d+$/', (string) $raw)) {
            return $default;
        }

        return (int) $raw;
    }

    private function postCheckboxEnabled(string $name): bool
    {
        $raw = $_POST[$name] ?? rcube_utils::get_input_value($name, rcube_utils::INPUT_POST);
        if (is_array($raw)) {
            $raw = end($raw);
        }

        $val = strtolower(trim((string) $raw));
        if ($val === '') {
            return false;
        }

        return in_array($val, ['1', 'true', 'yes', 'on'], true);
    }

    private function inputTruthy(string $name): bool
    {
        $raw = rcube_utils::get_input_value($name, rcube_utils::INPUT_GPC);
        if ($raw === null || $raw === '') {
            $raw = rcube_utils::get_input_value('_' . $name, rcube_utils::INPUT_GPC);
        }
        if (is_array($raw)) {
            $raw = end($raw);
        }

        $val = strtolower(trim((string) $raw));
        return in_array($val, ['1', 'true', 'yes', 'on'], true);
    }

    private function clientIp(): string
    {
        $xff = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($xff !== '') {
            $parts = explode(',', $xff);
            $ip = trim((string) ($parts[0] ?? ''));
            if ($ip !== '') {
                return $ip;
            }
        }

        return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    }

    private function consumeRateLimit(string $scope, string $subject, int $windowSeconds, int $maxAttempts): bool
    {
        $subject = trim($subject);
        if ($subject === '') {
            $subject = 'unknown';
        }

        return $this->storage->consumeRateLimit($scope, $subject, $windowSeconds, $maxAttempts);
    }

    private function resetLocalSessionForReonboarding(): void
    {
        $keys = [
            self::SESSION_OIDC_SUB,
            self::SESSION_OIDC_EMAIL,
            self::SESSION_OIDC_NONCE,
            self::SESSION_OIDC_STATE,
            self::SESSION_OIDC_CODE_VERIFIER,
            self::SESSION_OIDC_GROUPS,
            self::SESSION_OIDC_ID_TOKEN,
            self::SESSION_OIDC_ACCESS_TOKEN,
            self::SESSION_OIDC_REFRESH_TOKEN,
            self::SESSION_OIDC_LOGIN_AT,
            self::SESSION_OIDC_LAST_ACTIVITY,
            self::SESSION_ALLOW_STANDARD_LOGIN,
            self::SESSION_POST_LOGIN_ACTION,
            self::SESSION_CLIENT_WRAP_PASSWORD,
            self::SESSION_CLIENT_WRAP_UNLOCKED_AT,
            self::SESSION_AUTLOGIN,
            self::SESSION_SETUP_RATE,
        ];

        foreach ($keys as $key) {
            unset($_SESSION[$key]);
        }

        unset($_SESSION['user_id'], $_SESSION['username']);
        @session_regenerate_id(true);
    }

    private function enforceSessionSecurityDefaults(): void
    {
        if (headers_sent()) {
            return;
        }

        @ini_set('session.cookie_httponly', '1');
        @ini_set('session.cookie_samesite', 'Lax');
        if ($this->cfgBool('force_https', false)) {
            @ini_set('session.cookie_secure', '1');
        }
    }

    private function enforceSessionTimeouts(): void
    {
        $loginAt = (int) ($_SESSION[self::SESSION_OIDC_LOGIN_AT] ?? 0);
        if ($loginAt <= 0) {
            return;
        }

        $now = time();
        $lastActivity = (int) ($_SESSION[self::SESSION_OIDC_LAST_ACTIVITY] ?? $loginAt);
        $idleLimit = max(60, (int) ($this->getPolicies()['session_idle_timeout_sec'] ?? $this->cfgInt('session_idle_timeout_sec', 1800)));
        $absoluteLimit = max(300, (int) ($this->getPolicies()['session_absolute_timeout_sec'] ?? $this->cfgInt('session_absolute_timeout_sec', 43200)));

        $idleExpired = ($now - $lastActivity) > $idleLimit;
        $absoluteExpired = ($now - $loginAt) > $absoluteLimit;
        if (!$idleExpired && !$absoluteExpired) {
            $_SESSION[self::SESSION_OIDC_LAST_ACTIVITY] = $now;
            return;
        }

        $this->audit('session_timeout', 'warn', $idleExpired ? 'idle timeout' : 'absolute timeout');

        $keys = [
            self::SESSION_OIDC_SUB,
            self::SESSION_OIDC_EMAIL,
            self::SESSION_OIDC_NONCE,
            self::SESSION_OIDC_STATE,
            self::SESSION_OIDC_CODE_VERIFIER,
            self::SESSION_OIDC_GROUPS,
            self::SESSION_OIDC_ID_TOKEN,
            self::SESSION_OIDC_ACCESS_TOKEN,
            self::SESSION_OIDC_REFRESH_TOKEN,
            self::SESSION_OIDC_LOGIN_AT,
            self::SESSION_OIDC_LAST_ACTIVITY,
            self::SESSION_AUTLOGIN,
            self::SESSION_SETUP_RATE,
            self::SESSION_ALLOW_STANDARD_LOGIN,
        ];
        foreach ($keys as $key) {
            unset($_SESSION[$key]);
        }
        unset($_SESSION['user_id'], $_SESSION['username']);

        if ($this->rc->task !== 'login') {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }
    }

    private function loginMode(): string
    {
        $policies = $this->getPolicies();
        $raw = strtolower(trim((string) ($policies['login_mode'] ?? $this->cfg('login_mode', 'auto'))));
        return $this->sanitizeLoginMode($raw);
    }

    private function sanitizeLoginMode(string $mode): string
    {
        $mode = strtolower(trim($mode));
        if (!in_array($mode, ['auto', 'button'], true)) {
            return 'auto';
        }

        return $mode;
    }

    private function loginButtonText(): string
    {
        $policies = $this->getPolicies();
        $text = trim((string) ($policies['login_button_text'] ?? $this->cfg('login_button_text', 'Login with SSO')));
        if ($text === '') {
            $text = 'Login with SSO';
        }

        return $text;
    }

    private function isStandardLoginHidden(): bool
    {
        $policies = $this->getPolicies();
        if (array_key_exists('hide_standard_login_form', $policies)) {
            $val = strtolower(trim((string) $policies['hide_standard_login_form']));
            if ($val !== '') {
                return in_array($val, ['1', 'true', 'yes', 'on'], true);
            }
        }

        return $this->cfgBool('hide_standard_login_form', true);
    }

    public function actionAdminClearMailbox(): void
    {
        $this->requireAdmin(true, 'admin_clear_mailbox');

        $oidcSub = trim((string) rcube_utils::get_input_value('oidc_sub', rcube_utils::INPUT_POST));
        if ($oidcSub === '') {
            $this->fail('Missing user identifier.');
        }

        $currentSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        if ($currentSub !== '' && hash_equals($currentSub, $oidcSub)) {
            $this->audit('admin_clear_mailbox', 'error', 'self-clear blocked', ['oidc_sub' => $oidcSub]);
            $this->fail('Refusing to clear mailbox mapping for currently logged-in admin.');
        }

        $this->storage->clearMailboxBySub($oidcSub);
        $this->audit('admin_clear_mailbox', 'ok', 'mailbox mapping cleared', ['oidc_sub' => $oidcSub]);
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    public function actionAdminSetNote(): void
    {
        $this->requireAdmin(true, 'admin_set_note');

        $oidcSub = trim((string) rcube_utils::get_input_value('oidc_sub', rcube_utils::INPUT_POST));
        if ($oidcSub === '') {
            $this->fail('Missing user identifier.');
        }

        $note = trim((string) rcube_utils::get_input_value('admin_note', rcube_utils::INPUT_POST));
        $this->storage->setUserNoteBySub($oidcSub, $note);
        $this->audit('admin_set_note', 'ok', 'admin note updated', ['oidc_sub' => $oidcSub]);
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    public function actionAdminLogout(): void
    {
        $this->requireAdmin(true, 'admin_logout');

        $this->audit('admin_logout', 'ok', 'logout requested from admin dashboard');
        $this->redirectTo($this->rc->url(['task' => 'logout', '_token' => $this->rc->get_request_token()]));
    }

    public function actionUserSettings(): void
    {
        if (empty($_SESSION['user_id']) || !$this->isUserSelfServiceAllowed()) {
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => 'edit-prefs', 'section' => self::PREF_SECTION_USER]));
        }

        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $mailbox = $oidcSub !== '' ? $this->storage->getMailboxBySub($oidcSub) : null;
        $statusMessage = (string) ($_SESSION['universal_oidc_mail_sso_user_status'] ?? '');
        unset($_SESSION['universal_oidc_mail_sso_user_status']);

        $file = __DIR__ . '/skins/elastic/templates/user_settings.html';
        $template = file_get_contents($file);
        if ($template === false) {
            throw new rcube_exception('Cannot load user settings template.');
        }

        $token = htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8');
        $testDisabled = $mailbox && $this->isClientWrapMailbox($mailbox);
        $testDisabledHint = $testDisabled
            ? '<div class="alert alert-warning py-2 small mt-2 mb-0">IMAP/SMTP tests are disabled in client-side encryption mode.</div>'
            : '';
        $statusHtml = $statusMessage !== ''
            ? '<div class="alert alert-info mb-4" role="alert">' . htmlspecialchars($statusMessage, ENT_QUOTES, 'UTF-8') . '</div>'
            : '';

        $mailboxEmail = (string) ($mailbox['email'] ?? '');
        $imap = isset($mailbox['imap_host'])
            ? ((string) $mailbox['imap_host'] . ':' . (string) $mailbox['imap_port'] . ' (' . (string) $mailbox['imap_security'] . ')')
            : 'n/a';
        $smtp = isset($mailbox['smtp_host'])
            ? ((string) $mailbox['smtp_host'] . ':' . (string) $mailbox['smtp_port'] . ' (' . (string) $mailbox['smtp_security'] . ')')
            : 'n/a';
        $smtpAuth = !empty($mailbox['smtp_auth']) ? 'enabled' : 'disabled';

        $html = strtr($template, [
            '{{status_message}}' => $statusHtml,
            '{{oidc_email}}' => htmlspecialchars((string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? ''), ENT_QUOTES, 'UTF-8'),
            '{{oidc_sub}}' => htmlspecialchars($oidcSub !== '' ? $oidcSub : 'n/a', ENT_QUOTES, 'UTF-8'),
            '{{mailbox_email}}' => htmlspecialchars($mailboxEmail !== '' ? $mailboxEmail : 'n/a', ENT_QUOTES, 'UTF-8'),
            '{{updated_at}}' => htmlspecialchars((string) ($mailbox['updated_at'] ?? 'n/a'), ENT_QUOTES, 'UTF-8'),
            '{{imap}}' => htmlspecialchars($imap, ENT_QUOTES, 'UTF-8'),
            '{{smtp}}' => htmlspecialchars($smtp, ENT_QUOTES, 'UTF-8'),
            '{{smtp_user}}' => htmlspecialchars((string) ($mailbox['smtp_user'] ?? 'n/a'), ENT_QUOTES, 'UTF-8'),
            '{{smtp_auth}}' => htmlspecialchars($smtpAuth, ENT_QUOTES, 'UTF-8'),
            '{{key_id}}' => htmlspecialchars((string) ($mailbox['key_id'] ?? 'n/a'), ENT_QUOTES, 'UTF-8'),
            '{{test_action}}' => htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_TEST_MAILBOX]), ENT_QUOTES, 'UTF-8'),
            '{{connect_url}}' => htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_CONNECT, '_force_setup' => 1]), ENT_QUOTES, 'UTF-8'),
            '{{clear_action}}' => htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_CLEAR_MAILBOX]), ENT_QUOTES, 'UTF-8'),
            '{{csrf_token}}' => $token,
            '{{test_disabled_attr}}' => $testDisabled ? 'disabled' : '',
            '{{test_disabled_hint}}' => $testDisabledHint,
        ]);

        header('Content-Type: text/html; charset=UTF-8');
        echo $html;
        exit;
    }

    public function actionUserTestMailbox(): void
    {
        $this->requireUserPostAction('user_test_mailbox');
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'No mailbox profile found. Please run setup.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }
        if ($this->isClientWrapMailbox($mailbox)) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'IMAP/SMTP test is disabled in client-side encryption mode.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Mailbox password is locked. Unlock first.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        [$ok, $msg] = $this->testMailboxConnection([
            'email' => (string) $mailbox['email'],
            'password' => $password,
            'imap_host' => (string) $mailbox['imap_host'],
            'imap_port' => (int) $mailbox['imap_port'],
            'imap_security' => (string) $mailbox['imap_security'],
            'smtp_host' => (string) $mailbox['smtp_host'],
            'smtp_port' => (int) $mailbox['smtp_port'],
            'smtp_security' => (string) $mailbox['smtp_security'],
            'smtp_auth' => !empty($mailbox['smtp_auth']) ? 1 : 0,
            'smtp_user' => (string) ($mailbox['smtp_user'] ?? $mailbox['email']),
        ]);
        $_SESSION['universal_oidc_mail_sso_user_status'] = $ok ? ('Mailbox test succeeded: ' . $msg) : ('Mailbox test failed: ' . $msg);
        $this->audit('user_mailbox_test', $ok ? 'ok' : 'error', $msg);
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
    }

    public function actionUserTestImap(): void
    {
        $this->requireUserPostAction('user_test_imap');
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'No mailbox profile found. Please run setup.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }
        if ($this->isClientWrapMailbox($mailbox)) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'IMAP test is disabled in client-side encryption mode.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Mailbox password is locked. Unlock first.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        [$ok, $msg] = $this->testImapConnection([
            'email' => (string) $mailbox['email'],
            'password' => $password,
            'imap_host' => (string) $mailbox['imap_host'],
            'imap_port' => (int) $mailbox['imap_port'],
            'imap_security' => (string) $mailbox['imap_security'],
        ]);
        $_SESSION['universal_oidc_mail_sso_user_status'] = $ok ? ('IMAP test succeeded: ' . $msg) : ('IMAP test failed: ' . $msg);
        $this->audit('user_mailbox_test_imap', $ok ? 'ok' : 'error', $msg);
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
    }

    public function actionUserTestSmtp(): void
    {
        $this->requireUserPostAction('user_test_smtp');
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'No mailbox profile found. Please run setup.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }
        if ($this->isClientWrapMailbox($mailbox)) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'SMTP test is disabled in client-side encryption mode.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $password = $this->resolveMailboxPassword($mailbox);
        if ($password === null) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Mailbox password is locked. Unlock first.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        [$ok, $msg] = $this->testSmtpConnection([
            'password' => $password,
            'smtp_host' => (string) $mailbox['smtp_host'],
            'smtp_port' => (int) $mailbox['smtp_port'],
            'smtp_security' => (string) $mailbox['smtp_security'],
            'smtp_auth' => !empty($mailbox['smtp_auth']) ? 1 : 0,
            'smtp_user' => (string) ($mailbox['smtp_user'] ?? $mailbox['email']),
        ]);
        $_SESSION['universal_oidc_mail_sso_user_status'] = $ok ? ('SMTP test succeeded: ' . $msg) : ('SMTP test failed: ' . $msg);
        $this->audit('user_mailbox_test_smtp', $ok ? 'ok' : 'error', $msg);
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
    }

    public function actionUserClearMailbox(): void
    {
        $this->requireUserPostAction('user_clear_mailbox');
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        if ($oidcSub !== '') {
            $this->storage->clearMailboxBySub($oidcSub);
            $this->audit('user_clear_mailbox', 'ok', 'user cleared own mailbox mapping');
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Mailbox profile removed. Please run setup again.';
        }

        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
    }

    public function actionUserDownloadRecovery(): void
    {
        $this->requireUserPostAction('user_download_recovery');
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $oidcEmail = (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? '');
        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'No mailbox profile found. Please run setup.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $content = "SSO Mailbox Recovery Summary\n"
            . "Generated: " . gmdate('Y-m-d H:i:s') . " UTC\n"
            . "OIDC email: " . $oidcEmail . "\n"
            . "OIDC sub: " . $oidcSub . "\n"
            . "Mailbox email: " . (string) ($mailbox['email'] ?? '') . "\n"
            . "IMAP: " . (string) ($mailbox['imap_host'] ?? '') . ":" . (string) ($mailbox['imap_port'] ?? '') . " (" . (string) ($mailbox['imap_security'] ?? '') . ")\n"
            . "SMTP: " . (string) ($mailbox['smtp_host'] ?? '') . ":" . (string) ($mailbox['smtp_port'] ?? '') . " (" . (string) ($mailbox['smtp_security'] ?? '') . ")\n"
            . "SMTP auth: " . (!empty($mailbox['smtp_auth']) ? 'enabled' : 'disabled') . "\n"
            . "SMTP user: " . (string) ($mailbox['smtp_user'] ?? '') . "\n"
            . "Encryption key id: " . (string) ($mailbox['key_id'] ?? '') . "\n";

        header('Content-Type: text/plain; charset=UTF-8');
        header('Content-Disposition: attachment; filename="sso-mailbox-recovery.txt"');
        echo $content;
        exit;
    }

    public function actionUserDownloadSupport(): void
    {
        $this->requireUserPostAction('user_download_support');
        $oidcSub = (string) ($_SESSION[self::SESSION_OIDC_SUB] ?? '');
        $mailbox = $this->storage->getMailboxBySub($oidcSub);
        if (!$mailbox) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'No mailbox profile found. Please run setup.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $bundle = [
            'generated_utc' => gmdate('Y-m-d H:i:s'),
            'oidc_email' => (string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? ''),
            'oidc_sub' => $oidcSub,
            'mailbox_email' => (string) ($mailbox['email'] ?? ''),
            'imap' => [
                'host' => (string) ($mailbox['imap_host'] ?? ''),
                'port' => (int) ($mailbox['imap_port'] ?? 0),
                'security' => (string) ($mailbox['imap_security'] ?? ''),
            ],
            'smtp' => [
                'host' => (string) ($mailbox['smtp_host'] ?? ''),
                'port' => (int) ($mailbox['smtp_port'] ?? 0),
                'security' => (string) ($mailbox['smtp_security'] ?? ''),
                'auth' => !empty($mailbox['smtp_auth']),
                'user' => (string) ($mailbox['smtp_user'] ?? ''),
            ],
            'key_id' => (string) ($mailbox['key_id'] ?? ''),
            'client_wrap_enabled' => !empty($mailbox['client_wrap_enabled']),
            'last_success_imap_auth' => $this->findRecentAuditTimestamp(['imap_auth'], ['ok']),
            'last_success_smtp_send' => $this->findRecentAuditTimestamp(['smtp_send'], ['ok']),
        ];

        header('Content-Type: application/json; charset=UTF-8');
        header('Content-Disposition: attachment; filename="sso-mailbox-support.json"');
        echo json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    public function actionUserRequestEmail(): void
    {
        $this->requireUserPostAction('user_request_email');
        if ($this->isStrictOidcEmailBinding()) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Admin policy does not allow custom mailbox email.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $newEmail = strtolower(trim((string) rcube_utils::get_input_value('new_mailbox_email', rcube_utils::INPUT_POST)));
        if ($newEmail === '' || !filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Invalid mailbox email.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }
        if (!$this->isAllowedEmailDomain($newEmail)) {
            $_SESSION['universal_oidc_mail_sso_user_status'] = 'Email domain is not allowed by policy.';
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_USER_SETTINGS]));
        }

        $this->audit('user_request_email', 'ok', 'user requested mailbox email change', ['requested_email' => $newEmail]);
        $this->redirectTo($this->rc->url([
            'task' => 'settings',
            'action' => self::ACTION_CONNECT,
            '_force_setup' => 1,
            '_prefill_email' => $newEmail,
        ]));
    }

    private function isClientWrapEnabled(): bool
    {
        $policies = $this->getPolicies();
        $policyVal = strtolower(trim((string) ($policies['client_side_wrap_enabled'] ?? '')));
        if ($policyVal !== '') {
            return in_array($policyVal, ['1', 'true', 'yes', 'on'], true);
        }

        return $this->cfgBool('client_side_wrap_enabled', false);
    }

    private function isBootstrapPending(): bool
    {
        $policies = $this->getPolicies();
        $val = strtolower(trim((string) ($policies['bootstrap_completed'] ?? '0')));
        return !in_array($val, ['1', 'true', 'yes', 'on'], true);
    }

    private function claimBootstrapOwner(string $oidcSub, string $email): void
    {
        if ($oidcSub === '') {
            return;
        }

        $policies = $this->getPolicies();
        $currentOwner = trim((string) ($policies['bootstrap_owner_sub'] ?? ''));
        if ($currentOwner !== '') {
            return;
        }

        $this->storage->setPolicy('bootstrap_owner_sub', $oidcSub);
        $this->storage->setPolicy('bootstrap_owner_email', $email);
        $this->policyCache = null;
    }

    private function isBootstrapOwner(string $oidcSub): bool
    {
        if (!$this->isBootstrapPending()) {
            return true;
        }

        $owner = trim((string) ($this->getPolicies()['bootstrap_owner_sub'] ?? ''));
        if ($owner === '' || $oidcSub === '') {
            return true;
        }

        return hash_equals($owner, $oidcSub);
    }

    private function findRecentAuditTimestamp(array $events, array $statuses = ['ok']): string
    {
        $rows = $this->storage->getRecentAudit(500);
        foreach ($rows as $row) {
            $event = (string) ($row['event'] ?? '');
            $status = strtolower((string) ($row['status'] ?? ''));
            if (!in_array($event, $events, true)) {
                continue;
            }
            if (!in_array($status, $statuses, true)) {
                continue;
            }

            $created = (string) ($row['created_at'] ?? '');
            return $created !== '' ? $created : 'n/a';
        }

        return 'n/a';
    }

    private function renderBootstrapBlockedPage(): void
    {
        $logoutUrl = htmlspecialchars($this->rc->url(['task' => 'logout', '_token' => $this->rc->get_request_token()]), ENT_QUOTES, 'UTF-8');
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>Setup pending</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>'
            . '<body class="bg-light"><main class="container py-5"><div class="row justify-content-center"><div class="col-lg-8">'
            . '<div class="card shadow-sm"><div class="card-body p-4 p-lg-5">'
            . '<h1 class="h4 mb-3">Setup is pending first admin onboarding</h1>'
            . '<p class="text-muted mb-4">A member of the admin group must complete initial onboarding before regular users can configure mailboxes.</p>'
            . '<a class="btn btn-outline-secondary" href="' . $logoutUrl . '">Logout</a>'
            . '</div></div></div></div></main></body></html>';
        exit;
    }

    private function renderBootstrapOwnerBlockedPage(): void
    {
        $ownerEmail = htmlspecialchars((string) ($this->getPolicies()['bootstrap_owner_email'] ?? 'another admin'), ENT_QUOTES, 'UTF-8');
        header('Content-Type: text/html; charset=UTF-8');
        echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<title>Onboarding in progress</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"></head>'
            . '<body class="bg-light"><main class="container py-5"><div class="row justify-content-center"><div class="col-lg-8">'
            . '<div class="card shadow-sm"><div class="card-body p-4 p-lg-5">'
            . '<h1 class="h4 mb-3">Initial onboarding is already in progress</h1>'
            . '<p class="text-muted mb-2">The bootstrap process is currently assigned to: <strong>' . $ownerEmail . '</strong>.</p>'
            . '<p class="text-muted mb-0">Please wait until onboarding is completed.</p>'
            . '</div></div></div></div></main></body></html>';
        exit;
    }

    private function isClientWrapMailbox(array $mailbox): bool
    {
        return !empty($mailbox['client_wrap_enabled']);
    }

    private function hasUnlockedClientWrapPassword(): bool
    {
        $pwd = (string) ($_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD] ?? '');
        return $pwd !== '';
    }

    private function resolveMailboxPassword(array $mailbox): ?string
    {
        if ($this->isClientWrapMailbox($mailbox)) {
            $pwd = (string) ($_SESSION[self::SESSION_CLIENT_WRAP_PASSWORD] ?? '');
            return $pwd !== '' ? $pwd : null;
        }

        try {
            return $this->getCrypto()->decrypt(
                (string) $mailbox['enc_alg'],
                (string) $mailbox['password_enc'],
                (string) $mailbox['enc_nonce'],
                (string) ($mailbox['key_id'] ?? '')
            );
        } catch (Throwable $e) {
            return null;
        }
    }

    private function decryptClientWrappedPassword(array $mailbox, string $passphrase): ?string
    {
        if (!$this->isClientWrapMailbox($mailbox)) {
            return null;
        }

        $blob = (string) ($mailbox['client_wrap_blob'] ?? '');
        $nonce = (string) ($mailbox['client_wrap_nonce'] ?? '');
        $salt = (string) ($mailbox['client_wrap_salt'] ?? '');
        $kdf = strtolower((string) ($mailbox['client_wrap_kdf'] ?? 'pbkdf2-sha256'));
        $iters = (int) ($mailbox['client_wrap_iters'] ?? 0);

        if ($blob === '' || $nonce === '' || $salt === '' || $iters < 100000 || $kdf !== 'pbkdf2-sha256') {
            return null;
        }
        if (strlen($blob) <= 16) {
            return null;
        }

        $ciphertext = substr($blob, 0, -16);
        $tag = substr($blob, -16);
        $key = hash_pbkdf2('sha256', $passphrase, $salt, $iters, 32, true);
        $plain = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag);
        if (!is_string($plain) || $plain === '') {
            return null;
        }

        return $plain;
    }

    private function renderUnlockPage(string $message, bool $isError = false): void
    {
        $templateFile = __DIR__ . '/skins/elastic/templates/unlock_mailbox.html';
        $template = file_get_contents($templateFile);
        if ($template === false) {
            $this->fail('Unable to load unlock template.');
        }

        $flash = '';
        if ($message !== '') {
            $flash = '<div class="alert ' . ($isError ? 'alert-danger' : 'alert-info') . ' mb-3">'
                . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</div>';
        }

        $html = strtr($template, [
            '{{unlock_action}}' => htmlspecialchars($this->urlForAction(self::ACTION_UNLOCK_SUBMIT), ENT_QUOTES, 'UTF-8'),
            '{{csrf_token}}' => htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8'),
            '{{message}}' => $flash,
            '{{oidc_email}}' => htmlspecialchars((string) ($_SESSION[self::SESSION_OIDC_EMAIL] ?? ''), ENT_QUOTES, 'UTF-8'),
        ]);

        header('Content-Type: text/html; charset=UTF-8');
        echo $html;
        exit;
    }

    private function enforceClientWrapModeSwitch(): void
    {
        $policies = $this->storage->getPolicies(['client_side_wrap_enabled']);
        if ((string) ($policies['client_side_wrap_enabled'] ?? '') !== '') {
            return;
        }

        $defaultFromEnv = $this->cfgBool('client_side_wrap_enabled', false) ? '1' : '0';
        $this->storage->setPolicy('client_side_wrap_enabled', $defaultFromEnv);
        $this->policyCache = null;
    }

    private function defaultRedirectUri(): string
    {
        return $this->externalBaseUrl() . '/plugins/universal_oidc_mail_sso/callback_bridge.php';
    }

    private function externalBaseUrl(): string
    {
        $forceHttps = $this->cfgBool('force_https', false);
        $proto = $forceHttps ? 'https' : ((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? $_SERVER['REQUEST_SCHEME'] ?? 'http'));
        $host = (string) ($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? 'localhost');

        if (strpos($host, ',') !== false) {
            $host = trim(explode(',', $host)[0]);
        }
        if (strpos($proto, ',') !== false) {
            $proto = trim(explode(',', $proto)[0]);
        }

        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php');
        $dir = rtrim(str_replace('\\', '/', dirname($script)), '/');

        return $proto . '://' . $host . ($dir === '' ? '' : $dir);
    }

    private function urlForAction(string $action): string
    {
        return $this->rc->url(['task' => 'login', 'action' => $action]);
    }

    private function randomB64Url(int $len): string
    {
        return rtrim(strtr(base64_encode(random_bytes($len)), '+/', '-_'), '=');
    }

    private function pkceChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    private function getCrypto(): Crypto
    {
        if ($this->crypto === null) {
            throw new rcube_exception('Mailbox encryption key is not available.');
        }

        return $this->crypto;
    }

    private function fail(string $message): void
    {
        http_response_code(403);
        header('Content-Type: text/plain; charset=UTF-8');
        echo $message;
        exit;
    }

    private function redirectTo(string $url): void
    {
        header('Location: ' . $url, true, 302);
        exit;
    }

    private function audit(string $event, string $status, string $message = '', array $meta = []): void
    {
        try {
            $this->storage->addAudit(
                $event,
                $status,
                isset($_SESSION[self::SESSION_OIDC_SUB]) ? (string) $_SESSION[self::SESSION_OIDC_SUB] : null,
                isset($_SESSION[self::SESSION_OIDC_EMAIL]) ? (string) $_SESSION[self::SESSION_OIDC_EMAIL] : null,
                !empty($_SESSION['user_id']) ? (int) $_SESSION['user_id'] : null,
                $message,
                $meta
            );
        } catch (Throwable $e) {
            // Avoid breaking auth flow if audit insert fails.
        }
    }

    private function log(string $event, array $context = []): void
    {
        $meta = [
            'request_id' => $this->requestId(),
            'ip' => $this->clientIp(),
            'task' => (string) ($this->rc->task ?? ''),
            'action' => (string) rcube_utils::get_input_value('_action', rcube_utils::INPUT_GPC),
        ];
        $safeContext = $this->sanitizeLogContext($context);
        if (!empty($safeContext)) {
            $meta['context'] = $safeContext;
        }

        rcube::write_log('errors', '[universal_oidc_mail_sso] ' . $event . ' ' . json_encode($meta, JSON_UNESCAPED_SLASHES));
    }

    private function requireAdmin(bool $post, string $event): void
    {
        if (!$this->isAdminUser()) {
            $this->audit($event, 'error', 'access denied', [
                'admin_group_name' => (string) $this->cfg('admin_group_name', 'webmail_admin'),
                'effective_groups' => implode(',', $this->currentUserGroups()),
            ]);
            $this->fail('Admin access denied.');
        }

        if (!$post) {
            return;
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->audit($event, 'error', 'invalid csrf token');
            $this->fail('Invalid CSRF token.');
        }
    }

    private function isUserSelfServiceAllowed(): bool
    {
        if (empty($_SESSION['user_id']) || empty($_SESSION[self::SESSION_OIDC_SUB])) {
            return false;
        }

        $requiredGroup = trim((string) $this->cfg('user_group_name', 'webmail'));
        if ($requiredGroup === '') {
            return true;
        }

        $groups = $this->currentUserGroups();
        return in_array($requiredGroup, $groups, true);
    }

    private function requireUserPostAction(string $event): void
    {
        if (!$this->isUserSelfServiceAllowed()) {
            $this->audit($event, 'error', 'user self-service access denied', [
                'required_group' => (string) $this->cfg('user_group_name', 'webmail'),
                'effective_groups' => implode(',', $this->currentUserGroups()),
            ]);
            $this->fail('Access denied.');
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->audit($event, 'error', 'invalid csrf token');
            $this->fail('Invalid CSRF token.');
        }
    }

    private function requestId(): string
    {
        if ($this->requestId !== null) {
            return $this->requestId;
        }

        $rid = (string) ($_SERVER['HTTP_X_REQUEST_ID'] ?? '');
        if ($rid === '') {
            $rid = bin2hex(random_bytes(8));
        }
        $rid = preg_replace('/[^a-zA-Z0-9._-]/', '', $rid) ?: bin2hex(random_bytes(8));
        $this->requestId = substr($rid, 0, 64);
        return $this->requestId;
    }

    private function sanitizeLogContext(array $context): array
    {
        $out = [];
        foreach ($context as $key => $value) {
            $k = strtolower((string) $key);
            if (preg_match('/pass|password|secret|token|authorization|nonce|code|cookie/i', $k)) {
                $out[$key] = '[redacted]';
                continue;
            }

            if (is_scalar($value) || $value === null) {
                $raw = (string) $value;
                if (strlen($raw) > 200) {
                    $raw = substr($raw, 0, 200) . '...';
                }
                $out[$key] = $raw;
            } else {
                $json = json_encode($value, JSON_UNESCAPED_SLASHES);
                if (!is_string($json)) {
                    $out[$key] = '[complex]';
                    continue;
                }
                if (strlen($json) > 200) {
                    $json = substr($json, 0, 200) . '...';
                }
                $out[$key] = $json;
            }
        }

        return $out;
    }

    private function adminActions(): array
    {
        return [
            self::ACTION_ADMIN,
            self::ACTION_ADMIN_SAVE_POLICY,
            self::ACTION_ADMIN_DELETE_USER,
            self::ACTION_ADMIN_SET_USER_STATUS,
            self::ACTION_ADMIN_CLEAR_MAILBOX,
            self::ACTION_ADMIN_SET_NOTE,
            self::ACTION_ADMIN_LOGOUT,
        ];
    }

}
