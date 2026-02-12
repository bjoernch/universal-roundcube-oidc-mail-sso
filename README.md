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

## Security note

Do not commit `.env` or any generated secret files. This repo is configured to ignore `.env`.
