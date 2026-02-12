# universal_oidc_mail_sso

Roundcube plugin for:
- OIDC Provider OIDC SSO (Authorization Code + PKCE)
- One-time mailbox credential setup
- Encrypted mailbox credentials at rest
- Automatic IMAP/SMTP authentication after OIDC login

## Features

- OIDC discovery from `OIDC_ISSUER`
- PKCE (`S256`) + `state` + `nonce`
- ID token validation via JWKS (`RS256`)
- Required claim mapping:
  - stable user id: `sub`
  - email/login id: `email` (required)
- Optional domain allow-list check (`ALLOWED_EMAIL_DOMAIN`; empty or `*` allows all)
- One-time connect screen storing mailbox password/app-password encrypted in DB
- Encryption backends:
  - preferred: `libsodium` (`sodium_secretbox`)
  - fallback: OpenSSL `aes-256-gcm`
- Auto-injection of IMAP/SMTP credentials in Roundcube hooks (`authenticate`, `storage_connect`, `smtp_connect`)
- Optional SMTP auth toggle for servers that allow relay without SMTP AUTH
- Supports `ssl`, `tls`, `starttls`, and `none` security modes
- Built-in IMAP/SMTP credential test before saving profile
- Audit log table for authentication/provisioning events
- Admin dashboard for mapped accounts + audit history (restricted by OIDC group)
- Session-based setup form throttle + CSRF protection
- Reverse proxy aware redirect URI construction (`X-Forwarded-Proto`, `X-Forwarded-Host`, `FORCE_HTTPS`)

## Plugin layout

- `universal_oidc_mail_sso.php` main plugin
- `lib/OidcClient.php` OIDC discovery/token flow
- `lib/JwksValidator.php` JWT + JWKS signature/claim validation
- `lib/Crypto.php` encryption wrapper and key validation
- `lib/Storage.php` DB access for identity + mailbox records
- `skins/elastic/templates/connect_mailbox.html` one-time mailbox setup view
- `SQL/mysql.initial.sql` schema
- `misc/crypto_tool.php` CLI helper for key/encryption checks
- `misc/run_tests.php` minimal tests

## Database schema

Apply `SQL/mysql.initial.sql` to your Roundcube DB (it uses `{$prefix}` placeholders for Roundcube table prefix handling).

Tables:
- `oidc_mail_sso_oidc_user` minimal mapping (`oidc_sub`, `email`, `last_login_at`, optional `user_id`)
- `oidc_mail_sso_mailbox` encrypted mailbox config and app-password
- `oidc_mail_sso_audit_log` structured event/audit history

## Required env vars

- `OIDC_ISSUER` (e.g. `https://oidc.example.com`)
- `OIDC_CLIENT_ID`
- `RCUBE_MAILBOX_KEY` (base64 of exactly 32 random bytes)

Optional:
- `OIDC_CLIENT_SECRET` (for confidential clients)
- `OIDC_REDIRECT_URI` (if omitted, plugin computes from request/proxy headers)
- `OIDC_POST_LOGOUT_REDIRECT_URI`
- `ALLOWED_EMAIL_DOMAIN` (optional; empty or `*` allows all domains)
- `FORCE_HTTPS=true`
- `DISABLE_PASSWORD_LOGIN=true`
- `ADMIN_GROUP_NAME=webmail_admin`

Generic defaults (override as needed):
- `DEFAULT_IMAP_HOST=imap.example.com`
- `DEFAULT_IMAP_PORT=993`
- `DEFAULT_IMAP_SECURITY=ssl`
- `DEFAULT_SMTP_HOST=smtp.example.com`
- `DEFAULT_SMTP_PORT=587`
- `DEFAULT_SMTP_SECURITY=tls`
- `DEFAULT_SMTP_AUTH=1`

Generate key:

```sh
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

## Docker (roundcube/roundcubemail) setup

Example `docker-compose.yml` fragment:

```yaml
services:
  roundcube:
    image: roundcube/roundcubemail:latest
    ports:
      - "8080:80"
    volumes:
      - ./plugins/universal_oidc_mail_sso:/var/www/html/plugins/universal_oidc_mail_sso
    environment:
      ROUNDCUBEMAIL_PLUGINS: "universal_oidc_mail_sso"
      OIDC_ISSUER: "https://oidc.example.com"
      OIDC_CLIENT_ID: "roundcube"
      OIDC_CLIENT_SECRET: ""
      ALLOWED_EMAIL_DOMAIN: ""
      RCUBE_MAILBOX_KEY: "<base64-32-byte-key>"
      FORCE_HTTPS: "true"
      DISABLE_PASSWORD_LOGIN: "true"
```

Roundcube plugin config can be copied from `config.inc.php.dist` into `config.inc.php` if needed.

## Local test quickstart (this repository)

Files provided:
- `docker-compose.yml`
- `.env.example`
- `plugins/universal_oidc_mail_sso/SQL/mysql.local.sql`

Steps:

```sh
cd <repo-dir>
cp .env.example .env
# edit .env: set OIDC Provider client values and RCUBE_MAILBOX_KEY
docker compose up -d
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

Then open `http://localhost:8080`.

## Where secrets/config go

Primary method (recommended): container environment variables in `.env` (consumed by `docker-compose.yml`):
- `OIDC_CLIENT_ID`
- `OIDC_CLIENT_SECRET`
- `OIDC_ISSUER`
- `OIDC_REDIRECT_URI`
- `RCUBE_MAILBOX_KEY`
- `ADMIN_GROUP_NAME`

## Admin dashboard

URL:

`/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin`

Access control:
- only users with OIDC `groups` claim containing `webmail_admin` (or `ADMIN_GROUP_NAME` override)

Alternative method: Roundcube plugin config file:
- copy `plugins/universal_oidc_mail_sso/config.inc.php.dist`
- to `plugins/universal_oidc_mail_sso/config.inc.php`
- and set `$config['universal_oidc_mail_sso_*']` values there.

## CLI utility

Run key and crypto self-test:

```sh
php plugins/universal_oidc_mail_sso/misc/crypto_tool.php self-test
```

Encrypt demo value:

```sh
php plugins/universal_oidc_mail_sso/misc/crypto_tool.php encrypt "secret"
```

Decrypt:

```sh
php plugins/universal_oidc_mail_sso/misc/crypto_tool.php decrypt <alg> <password_enc_b64> <nonce_b64>
```

## Tests

```sh
php plugins/universal_oidc_mail_sso/misc/run_tests.php
```

Covers:
- encryption/decryption round-trip
- OIDC discovery retrieval and JWKS-backed ID token validation (mocked endpoints)

## Security notes / threat model

- App-password is never stored plaintext in DB.
- Master key is external (`RCUBE_MAILBOX_KEY`), not persisted by plugin.
- Decrypted credentials are used only in memory at auth/connect time.
- Logs intentionally avoid secrets/tokens/passwords.
- Missing claim/domain mismatch/missing mailbox/decrypt failures fail closed.
- CSRF token enforced on connect form submission.
- Basic session-based rate limit applied to setup submissions.

## Operational notes

- Ensure Roundcube runs behind HTTPS and trusted reverse proxy headers are set correctly.
- Keep `RCUBE_MAILBOX_KEY` in secret manager/runtime env, rotate carefully.
- If key changes, previously stored mailbox passwords cannot be decrypted and must be re-provisioned.
