# universal-roundcube-oidc-mail-sso

Universal Roundcube plugin for:
- OIDC SSO (Auth Code + PKCE)
- One-time IMAP/SMTP credential setup
- Encrypted credential storage
- Automatic mailbox login
- Admin dashboard (policy + user mapping controls)

## Repository layout

- `plugins/universal_oidc_mail_sso/` plugin source
- `docker-compose.yml` local Roundcube + MariaDB stack
- `.env.example` example environment variables (safe template)

## Quick start

```sh
cp .env.example .env
# edit .env with your OIDC and key values
docker compose up -d
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

Roundcube:
- `http://localhost:8080`

OIDC callback URL:
- `http://localhost:8080/plugins/universal_oidc_mail_sso/callback_bridge.php`

Admin URL:
- `http://localhost:8080/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin`

## Environment variables

This repo uses `.env` values from the project root.

Copy and edit:

```sh
cp .env.example .env
```

### Database/runtime

- `ROUNDCUBE_PORT`: published web port (default `8080`)
- `DB_ROOT_PASSWORD`: MariaDB root password (used for admin tasks/schema import)
- `DB_NAME`: Roundcube DB name
- `DB_USER`: Roundcube DB user
- `DB_PASSWORD`: Roundcube DB password

### Roundcube bootstrap defaults (container startup)

- `DEFAULT_IMAP_URI`: e.g. `ssl://imap.example.com`
- `DEFAULT_IMAP_PORT`: e.g. `993`
- `DEFAULT_SMTP_URI`: e.g. `tls://smtp.example.com`
- `DEFAULT_SMTP_PORT`: e.g. `587`

### OIDC settings

- `OIDC_ISSUER`: issuer base URL, e.g. `https://auth.example.com`
- `OIDC_CLIENT_ID`: OIDC client id
- `OIDC_CLIENT_SECRET`: OIDC client secret (required for confidential clients)
- `OIDC_REDIRECT_URI`: callback URL, usually `https://webmail.example.com/plugins/universal_oidc_mail_sso/callback_bridge.php`
- `OIDC_POST_LOGOUT_REDIRECT_URI`: post logout landing URL
- `OIDC_SCOPES`: usually `openid email profile groups`

### Plugin security/policy settings

- `ALLOWED_EMAIL_DOMAIN`: allowed email domain(s), comma separated, empty or `*` allows all
- `ALLOW_CUSTOM_MAILBOX_EMAIL`: `false` by default (strict: mailbox email must match OIDC email)
- `RCUBE_MAILBOX_KEY`: base64-encoded 32-byte key for mailbox password encryption
- `FORCE_HTTPS`: `true` when behind HTTPS reverse proxy
- `DISABLE_PASSWORD_LOGIN`: `true` to force OIDC flow
- `ADMIN_GROUP_NAME`: group name(s) that can access admin dashboard
- `ADMIN_EMAILS`: optional fallback allowlist if group claims are missing (comma separated)

### Connect form defaults (shown to end users)

- `DEFAULT_IMAP_HOST`
- `DEFAULT_IMAP_PORT`
- `DEFAULT_IMAP_SECURITY` (`ssl|tls|starttls|none`)
- `DEFAULT_SMTP_HOST`
- `DEFAULT_SMTP_PORT`
- `DEFAULT_SMTP_SECURITY` (`ssl|tls|starttls|none`)
- `DEFAULT_SMTP_AUTH` (`1` or `0`)

Generate encryption key:

```sh
openssl rand -base64 32
```

## Update from GitHub (VPS)

Repository:
- `https://github.com/bjoernch/universal-roundcube-oidc-mail-sso`

Pin to latest release tag:

```sh
cd /srv/docker/roundcube/universal-roundcube-oidc-mail-sso
git fetch --tags
git checkout v0.2.1
docker compose up -d --force-recreate
docker compose restart roundcube
```

Track latest `main`:

```sh
cd /srv/docker/roundcube/universal-roundcube-oidc-mail-sso
git checkout main
git pull
docker compose up -d --force-recreate
docker compose restart roundcube
```

## Security note

Do not commit `.env` or any generated secret files. This repo is configured to ignore `.env`.
