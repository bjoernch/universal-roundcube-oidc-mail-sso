# universal-roundcube-oidc-mail-sso

Universal Roundcube plugin for OIDC SSO + external IMAP/SMTP mailbox provisioning.

This project is designed for users who already host email at a provider with IMAP/SMTP support (Zoho, Fastmail, mailbox.org, etc.) and want a custom-domain webmail frontend (for example `https://webmail.example.com`) with centralized OIDC login and policy control.

## Quick links

- Full docs index: [docs/README.md](./docs/README.md)
- Quick start: [docs/quickstart.md](./docs/quickstart.md)
- Full configuration reference (all parameters): [docs/configuration.md](./docs/configuration.md)
- Security model: [docs/security.md](./docs/security.md)
- Operations and updates: [docs/operations.md](./docs/operations.md)

## Repository layout

- `plugins/universal_oidc_mail_sso/` plugin source
- `docker-compose.yml` local Roundcube + MariaDB stack
- `.env.example` environment template
- `docs/` full documentation

## Local start (minimal)

```sh
cp .env.example .env
docker compose up -d
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

Roundcube: `http://localhost:8080`
