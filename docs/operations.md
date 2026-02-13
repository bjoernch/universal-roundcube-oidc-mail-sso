# Operations, Testing, and Updates

## Update from GitHub

Repository: <https://github.com/bjoernch/universal-roundcube-oidc-mail-sso>

### Pin to release tag

```sh
cd /srv/docker/roundcube/universal-roundcube-oidc-mail-sso
git fetch --tags
git checkout v0.2.1
docker compose up -d --force-recreate
docker compose restart roundcube
```

### Track latest `main`

```sh
cd /srv/docker/roundcube/universal-roundcube-oidc-mail-sso
git checkout main
git pull
docker compose up -d --force-recreate
docker compose restart roundcube
```

## Common maintenance

### Import/repair plugin schema

```sh
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

### Full local reset (destructive)

```sh
docker compose down -v --remove-orphans
docker compose up -d --force-recreate
docker compose exec -T db mariadb -u"$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" < plugins/universal_oidc_mail_sso/SQL/mysql.local.sql
```

## CLI tools

### Crypto self-test

```sh
php plugins/universal_oidc_mail_sso/misc/crypto_tool.php self-test
```

### Key rotation

```sh
# dry-run
php plugins/universal_oidc_mail_sso/misc/rotate_mailbox_keys.php

# apply
php plugins/universal_oidc_mail_sso/misc/rotate_mailbox_keys.php --apply
```

### Unit/security tests

```sh
php plugins/universal_oidc_mail_sso/misc/run_tests.php
php plugins/universal_oidc_mail_sso/misc/security_lint.php
```

### Optional web-flow smoke tests

```sh
./scripts/smoke_web_flows.sh
```

## CI/release

- CI: `.github/workflows/ci.yml`
- Release artifacts: `.github/workflows/release-artifacts.yml`

Manual release artifact build:

```sh
./scripts/build_release_artifacts.sh v0.3.0
```
