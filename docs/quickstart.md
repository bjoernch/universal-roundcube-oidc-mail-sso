# Quick Start

## Prerequisites

- Docker + Docker Compose
- OIDC provider client configured for Roundcube callback

## 1. Configure env

```sh
cp .env.example .env
```

Edit `.env` with your real values, especially:
- `DB_ROOT_PASSWORD`, `DB_PASSWORD`
- `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`
- `OIDC_REDIRECT_URI`
- `RCUBE_MAILBOX_KEY`

Generate a strong mailbox key:

```sh
openssl rand -base64 32
```

## 2. Start stack

```sh
docker compose up -d
```

## 3. Import plugin schema

```sh
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

## 4. Open app

- Roundcube: `http://localhost:8080`
- Admin dashboard: `http://localhost:8080/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin`
- User self-service: `http://localhost:8080/?_task=settings&_action=plugin.universal_oidc_mail_sso_user_settings`

## 5. First-login behavior

- Admin-group users complete initial onboarding/policy setup.
- Users then connect mailbox credentials (IMAP/SMTP) once.
- Future logins use OIDC + stored encrypted mailbox credentials.
