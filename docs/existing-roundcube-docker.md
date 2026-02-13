# Integrate Into Existing Roundcube Docker Compose Setup

This guide is for an already running Roundcube + MariaDB Docker setup.

Example base path used below:
- `/srv/docker/roundcube`

Adjust paths and service names to your environment.

## 1. Place plugin files

### Option A (recommended): keep plugin as git repo inside your stack

```sh
cd /srv/docker/roundcube
mkdir -p plugins
cd plugins
git clone https://github.com/bjoernch/universal-roundcube-oidc-mail-sso.git
```

Plugin path becomes:
- `/srv/docker/roundcube/plugins/universal-roundcube-oidc-mail-sso/plugins/universal_oidc_mail_sso`

### Option B: checkout release tag directly

```sh
cd /srv/docker/roundcube/plugins/universal-roundcube-oidc-mail-sso
git fetch --tags
git checkout v0.3.0
```

## 2. Mount plugin into Roundcube container

In your existing `docker-compose.yml`, under the Roundcube service, add:

```yaml
services:
  roundcube:
    volumes:
      - /srv/docker/roundcube/plugins/universal-roundcube-oidc-mail-sso/plugins/universal_oidc_mail_sso:/var/www/html/plugins/universal_oidc_mail_sso
    environment:
      ROUNDCUBEMAIL_PLUGINS: "archive,zipdownload,universal_oidc_mail_sso"
```

Notes:
- If `ROUNDCUBEMAIL_PLUGINS` already exists, append `universal_oidc_mail_sso`.
- Keep your existing plugin list intact.

## 3. Add required environment variables

In your compose env section or `.env`, set at minimum:

```env
OIDC_ISSUER=https://auth.example.com
OIDC_CLIENT_ID=roundcube
OIDC_CLIENT_SECRET=your-secret
OIDC_REDIRECT_URI=https://webmail.example.com/plugins/universal_oidc_mail_sso/callback_bridge.php
RCUBE_MAILBOX_KEY=<base64-32-byte-key>
ADMIN_GROUP_NAME=webmail_admin
```

Generate key:

```sh
openssl rand -base64 32
```

Use full configuration reference for all optional values:
- [configuration.md](./configuration.md)

## 4. Apply DB schema in your existing DB container

Find your DB service/container name first.

```sh
docker compose ps
```

Then import schema (example with service `db`):

```sh
cd /srv/docker/roundcube/plugins/universal-roundcube-oidc-mail-sso
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

If your DB creds are not in shell env, use explicit values.

## 5. Recreate Roundcube service

```sh
cd /srv/docker/roundcube
docker compose up -d --force-recreate roundcube
docker compose logs --tail=200 roundcube
```

## 6. Verify URLs

- Webmail root: `https://webmail.example.com/`
- Admin dashboard: `https://webmail.example.com/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin`
- User self-service: `https://webmail.example.com/?_task=settings&_action=plugin.universal_oidc_mail_sso_user_settings`

## 7. Update plugin later

```sh
cd /srv/docker/roundcube/plugins/universal-roundcube-oidc-mail-sso
git fetch --tags
git checkout v0.3.0
# or: git checkout main && git pull

cd /srv/docker/roundcube
docker compose up -d --force-recreate roundcube
```

## 8. Common placement mistakes

- Wrong mount source path (plugin not visible at `/var/www/html/plugins/universal_oidc_mail_sso`).
- Missing `ROUNDCUBEMAIL_PLUGINS` entry for `universal_oidc_mail_sso`.
- Callback URI mismatch between provider and `OIDC_REDIRECT_URI`.
- Schema not imported into the same DB used by Roundcube.
