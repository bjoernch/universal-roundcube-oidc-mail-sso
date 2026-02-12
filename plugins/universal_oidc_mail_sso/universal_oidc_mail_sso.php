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
    public $task = 'login|mail|settings';

    private const SESSION_OIDC_SUB = 'universal_oidc_mail_sso_oidc_sub';
    private const SESSION_OIDC_EMAIL = 'universal_oidc_mail_sso_oidc_email';
    private const SESSION_OIDC_NONCE = 'universal_oidc_mail_sso_oidc_nonce';
    private const SESSION_OIDC_STATE = 'universal_oidc_mail_sso_oidc_state';
    private const SESSION_OIDC_CODE_VERIFIER = 'universal_oidc_mail_sso_oidc_code_verifier';
    private const SESSION_OIDC_GROUPS = 'universal_oidc_mail_sso_oidc_groups';
    private const SESSION_AUTLOGIN = 'universal_oidc_mail_sso_autologin';
    private const SESSION_SETUP_RATE = 'universal_oidc_mail_sso_setup_rate';
    private const PREF_OIDC_GROUPS = 'universal_oidc_mail_sso_groups';
    private const ACTION_LOGIN = 'plugin.universal_oidc_mail_sso_login';
    private const ACTION_CALLBACK = 'plugin.universal_oidc_mail_sso_callback';
    private const ACTION_AUTOLOGIN = 'plugin.universal_oidc_mail_sso_autologin';
    private const ACTION_CONNECT = 'plugin.universal_oidc_mail_sso_connect';
    private const ACTION_SAVE_MAILBOX = 'plugin.universal_oidc_mail_sso_save_mailbox';
    private const ACTION_ADMIN = 'plugin.universal_oidc_mail_sso_admin';
    private const ACTION_ADMIN_SAVE_POLICY = 'plugin.universal_oidc_mail_sso_admin_save_policy';
    private const ACTION_ADMIN_DELETE_USER = 'plugin.universal_oidc_mail_sso_admin_delete_user';
    private const ACTION_ADMIN_SET_USER_STATUS = 'plugin.universal_oidc_mail_sso_admin_set_user_status';

    private rcmail $rc;
    private Storage $storage;
    private ?Crypto $crypto = null;
    private ?string $cryptoInitError = null;
    private ?array $policyCache = null;

    public function init(): void
    {
        $this->rc = rcmail::get_instance();
        $this->load_config();

        $this->storage = new Storage($this->rc);
        try {
            $this->crypto = new Crypto($this->cfg('mailbox_key'));
        } catch (Throwable $e) {
            $this->cryptoInitError = $e->getMessage();
            $this->log('crypto_init_failed', ['err' => $e->getMessage()]);
        }

        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('authenticate', [$this, 'authenticate']);
        $this->add_hook('storage_connect', [$this, 'storageConnect']);
        $this->add_hook('smtp_connect', [$this, 'smtpConnect']);

        $this->register_action(self::ACTION_LOGIN, [$this, 'actionLogin']);
        $this->register_action(self::ACTION_CALLBACK, [$this, 'actionCallback']);
        $this->register_action(self::ACTION_AUTOLOGIN, [$this, 'actionAutologin']);
        $this->register_action(self::ACTION_CONNECT, [$this, 'actionConnect']);
        $this->register_action(self::ACTION_SAVE_MAILBOX, [$this, 'actionSaveMailbox']);
        $this->register_action(self::ACTION_ADMIN, [$this, 'actionAdminDashboard']);
        $this->register_action(self::ACTION_ADMIN_SAVE_POLICY, [$this, 'actionAdminSavePolicy']);
        $this->register_action(self::ACTION_ADMIN_DELETE_USER, [$this, 'actionAdminDeleteUser']);
        $this->register_action(self::ACTION_ADMIN_SET_USER_STATUS, [$this, 'actionAdminSetUserStatus']);
    }

    public function startup(array $args): array
    {
        if ($this->rc->task !== 'login' || !empty($_SESSION['user_id'])) {
            return $args;
        }

        $action = rcube_utils::get_input_value('_action', rcube_utils::INPUT_GPC);
        if (is_string($action) && strpos($action, 'plugin.universal_oidc_mail_sso_') === 0) {
            // Fallback direct dispatcher for environments where register_action
            // doesn't route plugin actions in login task as expected.
            if ($action === self::ACTION_LOGIN) {
                $this->actionLogin();
            } elseif ($action === self::ACTION_CALLBACK) {
                $this->actionCallback();
            } elseif ($action === self::ACTION_AUTOLOGIN) {
                $this->actionAutologin();
            } elseif ($action === self::ACTION_CONNECT) {
                $this->actionConnect();
            } elseif ($action === self::ACTION_SAVE_MAILBOX) {
                $this->actionSaveMailbox();
            }

            return $args;
        }

        if (!$this->cfgBool('disable_password_login', true)) {
            return $args;
        }

        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if ($oidcSub) {
            $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
            if ($mailbox) {
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

        try {
            $password = $this->getCrypto()->decrypt(
                (string) $mailbox['enc_alg'],
                (string) $mailbox['password_enc'],
                (string) $mailbox['enc_nonce']
            );
        } catch (Throwable $e) {
            $this->log('autologin_failed_decrypt', ['err' => $e->getMessage()]);
            throw new rcube_exception('Unable to decrypt mailbox credentials.');
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

        try {
            $password = $this->getCrypto()->decrypt(
                (string) $mailbox['enc_alg'],
                (string) $mailbox['password_enc'],
                (string) $mailbox['enc_nonce']
            );
        } catch (Throwable $e) {
            $this->log('storage_connect_decrypt_failed', ['err' => $e->getMessage()]);
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
            return $args;
        }

        try {
            $password = $this->getCrypto()->decrypt(
                (string) $mailbox['enc_alg'],
                (string) $mailbox['password_enc'],
                (string) $mailbox['enc_nonce']
            );
        } catch (Throwable $e) {
            $this->log('smtp_connect_decrypt_failed', ['err' => $e->getMessage()]);
            $this->audit('smtp_auth', 'error', 'decrypt failed');
            return $args;
        }

        $smtpUri = $this->formatServer((string) $mailbox['smtp_host'], (int) $mailbox['smtp_port'], (string) $mailbox['smtp_security']);

        $smtpAuth = !empty($mailbox['smtp_auth']);
        $args['smtp_user'] = $smtpAuth ? (string) $mailbox['smtp_user'] : '';
        $args['smtp_pass'] = $smtpAuth ? $password : '';
        $args['smtp_host'] = (string) $mailbox['smtp_host'];
        $args['smtp_port'] = (int) $mailbox['smtp_port'];
        $args['smtp_server'] = $smtpUri;

        return $args;
    }

    public function actionLogin(): void
    {
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

    public function actionCallback(): void
    {
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

        $existingIdentity = $this->storage->getIdentityBySub($sub);
        if (!empty($existingIdentity['is_disabled'])) {
            $this->audit('oidc_login', 'error', 'blocked: account disabled by admin', ['oidc_sub' => $sub, 'email' => $email]);
            $this->fail('This account is disabled by administrator.');
        }

        $this->storage->upsertIdentity($sub, $email, null);
        $this->log('oidc_login_success', ['sub' => $sub, 'email' => $email]);
        $this->audit('oidc_login', 'ok', 'OIDC login success', [
            'groups_count' => count($groups),
            'groups' => implode(',', $groups),
            'claim_keys' => implode(',', array_keys($claims)),
            'scope' => (string) $this->cfg('scopes', 'openid email profile groups'),
        ]);

        $mailbox = $this->storage->getMailboxBySub($sub);
        if (!$mailbox) {
            $this->log('mailbox_missing_provisioning', ['sub' => $sub]);
            $this->audit('mailbox_provisioning', 'warn', 'mailbox profile missing');
            $this->redirectTo($this->urlForAction(self::ACTION_CONNECT));
        }

        $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
    }

    public function actionAutologin(): void
    {
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

        $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
        if (!$mailbox) {
            $this->redirectTo($this->urlForAction(self::ACTION_CONNECT));
        }

        if (!$this->isHostAllowed('imap', (string) $mailbox['imap_host']) || !$this->isHostAllowed('smtp', (string) $mailbox['smtp_host'])) {
            $this->audit('policy_block', 'error', 'autologin blocked by host policy', [
                'imap_host' => (string) $mailbox['imap_host'],
                'smtp_host' => (string) $mailbox['smtp_host'],
            ]);
            $this->fail('Mailbox profile blocked by admin host policy.');
        }

        $_SESSION[self::SESSION_AUTLOGIN] = true;

        $ok = false;
        try {
            $ok = $this->rc->login(
                (string) $email,
                '__SSO_AUTLOGIN__',
                $this->formatServer((string) $mailbox['imap_host'], (int) $mailbox['imap_port'], (string) $mailbox['imap_security'])
            );
        } finally {
            unset($_SESSION[self::SESSION_AUTLOGIN]);
        }

        if (!$ok || empty($_SESSION['user_id'])) {
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
        $this->storage->upsertIdentity((string) $oidcSub, (string) $email, (int) $_SESSION['user_id']);
        $this->persistGroupsToPrefs();
        $this->audit('imap_auth', 'ok', 'autologin succeeded');

        $this->storage->touchMailboxUsage((string) $oidcSub);
        $this->redirectTo($this->rc->url(['task' => 'mail', 'mbox' => 'INBOX']));
    }

    public function actionConnect(): void
    {
        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if (!$oidcSub) {
            $this->redirectTo($this->urlForAction(self::ACTION_LOGIN));
        }

        $identity = $this->storage->getIdentityBySub((string) $oidcSub);
        if (!empty($identity['is_disabled'])) {
            $this->fail('This account is disabled by administrator.');
        }

        $mailbox = $this->storage->getMailboxBySub((string) $oidcSub);
        if ($mailbox) {
            $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
        }

        $this->renderConnectMailboxPage('');
    }

    public function actionSaveMailbox(): void
    {
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

        if ($email === '' || $password === '') {
            $this->renderConnectMailboxPage('Email and app-password are required.');
            return;
        }

        if ($email !== strtolower((string) $oidcEmail)) {
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
            $encrypted = $this->getCrypto()->encrypt($password);
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
        ]);

        $_SESSION[self::SESSION_OIDC_EMAIL] = $email;
        $this->log('mailbox_provisioned', ['sub' => (string) $oidcSub, 'email' => $email]);
        $this->audit('mailbox_provisioning', 'ok', 'mailbox profile saved');

        $this->redirectTo($this->urlForAction(self::ACTION_AUTOLOGIN));
    }

    private function loadMailboxFromSession(): ?array
    {
        $oidcSub = $_SESSION[self::SESSION_OIDC_SUB] ?? null;
        if (!$oidcSub) {
            return null;
        }

        return $this->storage->getMailboxBySub((string) $oidcSub);
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

        $replacements = [
            '{{form_action}}' => htmlspecialchars($this->rc->url(['task' => 'login', 'action' => self::ACTION_SAVE_MAILBOX]), ENT_QUOTES, 'UTF-8'),
            '{{csrf_token}}' => htmlspecialchars(rcmail::get_instance()->get_request_token(), ENT_QUOTES, 'UTF-8'),
            '{{message}}' => $message !== '' ? '<div class="' . ($isError ? 'pizsso-error' : 'pizsso-success') . '">' . htmlspecialchars($message, ENT_QUOTES, 'UTF-8') . '</div>' : '',
            '{{email}}' => htmlspecialchars($email, ENT_QUOTES, 'UTF-8'),
            '{{imap_host}}' => htmlspecialchars((string) ($values['imap_host'] ?? $this->cfg('default_imap_host', 'imap.example.com')), ENT_QUOTES, 'UTF-8'),
            '{{imap_port}}' => htmlspecialchars((string) ($values['imap_port'] ?? $this->cfg('default_imap_port', '993')), ENT_QUOTES, 'UTF-8'),
            '{{imap_security_ssl_selected}}' => ($imapSecurity === 'ssl') ? 'selected' : '',
            '{{imap_security_tls_selected}}' => ($imapSecurity === 'tls') ? 'selected' : '',
            '{{imap_security_starttls_selected}}' => ($imapSecurity === 'starttls') ? 'selected' : '',
            '{{imap_security_none_selected}}' => ($imapSecurity === 'none') ? 'selected' : '',
            '{{smtp_host}}' => htmlspecialchars((string) ($values['smtp_host'] ?? $this->cfg('default_smtp_host', 'smtp.example.com')), ENT_QUOTES, 'UTF-8'),
            '{{smtp_port}}' => htmlspecialchars((string) ($values['smtp_port'] ?? $this->cfg('default_smtp_port', '587')), ENT_QUOTES, 'UTF-8'),
            '{{smtp_security_ssl_selected}}' => ($smtpSecurity === 'ssl') ? 'selected' : '',
            '{{smtp_security_tls_selected}}' => ($smtpSecurity === 'tls') ? 'selected' : '',
            '{{smtp_security_starttls_selected}}' => ($smtpSecurity === 'starttls') ? 'selected' : '',
            '{{smtp_security_none_selected}}' => ($smtpSecurity === 'none') ? 'selected' : '',
            '{{smtp_auth_checked}}' => ($smtpAuthChecked !== '0') ? 'checked' : '',
            '{{smtp_user}}' => htmlspecialchars((string) ($values['smtp_user'] ?? $email), ENT_QUOTES, 'UTF-8'),
        ];

        header('Content-Type: text/html; charset=UTF-8');
        echo strtr($template, $replacements);
        exit;
    }

    private function checkSetupRateLimit(): bool
    {
        $windowSec = 300;
        $maxAttempts = 5;
        $now = time();

        $items = $_SESSION[self::SESSION_SETUP_RATE] ?? [];
        $items = array_values(array_filter($items, static fn ($ts) => is_int($ts) && $ts >= ($now - $windowSec)));

        if (count($items) >= $maxAttempts) {
            $_SESSION[self::SESSION_SETUP_RATE] = $items;
            return false;
        }

        $items[] = $now;
        $_SESSION[self::SESSION_SETUP_RATE] = $items;

        return true;
    }

    private function oidcClient(): OidcClient
    {
        return new OidcClient([
            'issuer' => (string) $this->cfg('issuer'),
            'client_id' => (string) $this->cfg('client_id'),
            'client_secret' => (string) $this->cfg('client_secret', ''),
            'redirect_uri' => (string) $this->cfg('redirect_uri', $this->defaultRedirectUri()),
            'scope' => (string) $this->cfg('scopes', 'openid email profile groups'),
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

    private function getPolicies(): array
    {
        if ($this->policyCache !== null) {
            return $this->policyCache;
        }

        $this->policyCache = $this->storage->getPolicies([
            'allowed_email_domains',
            'allowed_imap_hosts',
            'allowed_smtp_hosts',
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
        if (empty($_SESSION['user_id'])) {
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

    public function actionAdminDashboard(): void
    {
        if ($this->rc->task !== 'settings') {
            $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
        }

        if (!$this->isAdminUser()) {
            $this->audit('admin_dashboard', 'error', 'access denied', [
                'admin_group_name' => (string) $this->cfg('admin_group_name', 'webmail_admin'),
                'effective_groups' => implode(',', $this->currentUserGroups()),
            ]);
            $this->fail('Admin access denied.');
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
            $rows .= '<tr>'
                . '<td>' . htmlspecialchars((string) ($row['email'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . ($isDisabled ? 'disabled' : 'active') . '</td>'
                . '<td>' . (!empty($row['imap_host']) ? 'yes' : 'no') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['imap_host'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['smtp_host'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['last_login_at'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>' . htmlspecialchars((string) ($row['last_used_at'] ?? ''), ENT_QUOTES, 'UTF-8') . '</td>'
                . '<td>'
                . '<form method="post" action="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_SET_USER_STATUS]), ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;margin-right:6px;">'
                . '<input type="hidden" name="_token" value="' . htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="oidc_sub" value="' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="is_disabled" value="' . htmlspecialchars($setDisabledValue, ENT_QUOTES, 'UTF-8') . '">'
                . '<button type="submit">' . htmlspecialchars($setDisabledLabel, ENT_QUOTES, 'UTF-8') . '</button>'
                . '</form>'
                . '<form method="post" action="' . htmlspecialchars($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN_DELETE_USER]), ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;" onsubmit="return confirm(\'Delete mapped account for this user?\');">'
                . '<input type="hidden" name="_token" value="' . htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8') . '">'
                . '<input type="hidden" name="oidc_sub" value="' . htmlspecialchars($rowSub, ENT_QUOTES, 'UTF-8') . '">'
                . '<button type="submit">Delete</button>'
                . '</form>'
                . '</td>'
                . '</tr>';
        }
        if ($rows === '') {
            $rows = '<tr><td colspan="9">No identities found.</td></tr>';
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
            '{{csrf_token}}' => htmlspecialchars($this->rc->get_request_token(), ENT_QUOTES, 'UTF-8'),
            '{{allowed_domains}}' => htmlspecialchars((string) ($policies['allowed_email_domains'] ?? ''), ENT_QUOTES, 'UTF-8'),
            '{{allowed_imap_hosts}}' => htmlspecialchars((string) ($policies['allowed_imap_hosts'] ?? ''), ENT_QUOTES, 'UTF-8'),
            '{{allowed_smtp_hosts}}' => htmlspecialchars((string) ($policies['allowed_smtp_hosts'] ?? ''), ENT_QUOTES, 'UTF-8'),
        ]);

        header('Content-Type: text/html; charset=UTF-8');
        echo $html;
        exit;
    }

    public function actionAdminSavePolicy(): void
    {
        if (!$this->isAdminUser()) {
            $this->audit('admin_policy', 'error', 'access denied');
            $this->fail('Admin access denied.');
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->fail('Invalid CSRF token.');
        }

        $allowedDomains = trim((string) rcube_utils::get_input_value('allowed_email_domains', rcube_utils::INPUT_POST));
        $allowedImapHosts = trim((string) rcube_utils::get_input_value('allowed_imap_hosts', rcube_utils::INPUT_POST));
        $allowedSmtpHosts = trim((string) rcube_utils::get_input_value('allowed_smtp_hosts', rcube_utils::INPUT_POST));

        $this->storage->setPolicy('allowed_email_domains', $allowedDomains);
        $this->storage->setPolicy('allowed_imap_hosts', $allowedImapHosts);
        $this->storage->setPolicy('allowed_smtp_hosts', $allowedSmtpHosts);
        $this->policyCache = null;

        $this->audit('admin_policy', 'ok', 'policy updated');
        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    public function actionAdminDeleteUser(): void
    {
        if (!$this->isAdminUser()) {
            $this->audit('admin_delete_user', 'error', 'access denied');
            $this->fail('Admin access denied.');
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->fail('Invalid CSRF token.');
        }

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
        if (!$this->isAdminUser()) {
            $this->audit('admin_set_user_status', 'error', 'access denied');
            $this->fail('Admin access denied.');
        }

        $token = (string) rcube_utils::get_input_value('_token', rcube_utils::INPUT_POST);
        if ($token === '' || $token !== $this->rc->get_request_token()) {
            $this->fail('Invalid CSRF token.');
        }

        $oidcSub = trim((string) rcube_utils::get_input_value('oidc_sub', rcube_utils::INPUT_POST));
        $isDisabled = rcube_utils::get_input_value('is_disabled', rcube_utils::INPUT_POST) ? 1 : 0;

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

        $this->storage->setUserDisabledBySub($oidcSub, $isDisabled === 1);
        $this->audit(
            'admin_set_user_status',
            'ok',
            $isDisabled === 1 ? 'user disabled' : 'user enabled',
            ['oidc_sub' => $oidcSub, 'email' => (string) ($identity['email'] ?? ''), 'is_disabled' => $isDisabled]
        );

        $this->redirectTo($this->rc->url(['task' => 'settings', 'action' => self::ACTION_ADMIN]));
    }

    private function testMailboxConnection(array $cfg): array
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

            $smtp = new rcube_smtp();
            $smtpUser = !empty($cfg['smtp_auth']) ? (string) $cfg['smtp_user'] : '';
            $smtpPass = !empty($cfg['smtp_auth']) ? (string) $cfg['password'] : '';
            $smtpOk = $smtp->connect(
                $this->formatServer((string) $cfg['smtp_host'], (int) $cfg['smtp_port'], (string) $cfg['smtp_security']),
                null,
                $smtpUser,
                $smtpPass
            );
            $smtpErr = $smtp->get_error();
            $smtpError = '';
            if (is_array($smtpErr)) {
                $smtpError = (string) ($smtpErr['label'] ?? json_encode($smtpErr, JSON_UNESCAPED_SLASHES));
            } elseif (is_string($smtpErr)) {
                $smtpError = $smtpErr;
            }
            $smtp->disconnect();

            if (!$smtpOk) {
                return [false, 'SMTP test failed: ' . ($smtpError ?: 'authentication/connection error')];
            }
        } catch (Throwable $e) {
            return [false, 'Connection test failed: ' . $e->getMessage()];
        }

        return [true, 'IMAP/SMTP test succeeded. You can save this profile.'];
    }

    private function cfg(string $name, ?string $default = null): ?string
    {
        $map = [
            'issuer' => 'OIDC_ISSUER',
            'client_id' => 'OIDC_CLIENT_ID',
            'client_secret' => 'OIDC_CLIENT_SECRET',
            'redirect_uri' => 'OIDC_REDIRECT_URI',
            'post_logout_redirect_uri' => 'OIDC_POST_LOGOUT_REDIRECT_URI',
            'allowed_email_domain' => 'ALLOWED_EMAIL_DOMAIN',
            'mailbox_key' => 'RCUBE_MAILBOX_KEY',
            'force_https' => 'FORCE_HTTPS',
            'disable_password_login' => 'DISABLE_PASSWORD_LOGIN',
            'default_imap_host' => 'DEFAULT_IMAP_HOST',
            'default_imap_port' => 'DEFAULT_IMAP_PORT',
            'default_imap_security' => 'DEFAULT_IMAP_SECURITY',
            'default_smtp_host' => 'DEFAULT_SMTP_HOST',
            'default_smtp_port' => 'DEFAULT_SMTP_PORT',
            'default_smtp_security' => 'DEFAULT_SMTP_SECURITY',
            'default_smtp_auth' => 'DEFAULT_SMTP_AUTH',
            'admin_group_name' => 'ADMIN_GROUP_NAME',
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
        $pairs = [];
        foreach ($context as $k => $v) {
            if ($v === null || $v === '') {
                continue;
            }

            $pairs[] = $k . '=' . preg_replace('/\s+/', '_', (string) $v);
        }

        $suffix = $pairs ? ' ' . implode(' ', $pairs) : '';
        rcube::write_log('errors', '[universal_oidc_mail_sso] ' . $event . $suffix);
    }

}
