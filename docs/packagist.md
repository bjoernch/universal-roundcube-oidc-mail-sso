# Packagist Submission Guide

## Package name (authoritative)

This repository is configured with:

- `name`: `bjoernch/universal_oidc_mail_sso`

Packagist will lock this name once first submitted.

## Before submitting

1. Ensure `composer.json` exists at repository root (done).
2. Ensure `main` is pushed.
3. Ensure at least one release tag exists (already true: `v0.3.0`).

## Submit

On Packagist Submit page, use repository URL:

- `https://github.com/bjoernch/universal-roundcube-oidc-mail-sso`

After submission, install in a Roundcube instance with:

```sh
php composer.phar require bjoernch/universal_oidc_mail_sso:^0.3
```

## Enable auto-update webhook (GitHub manual setup)

In GitHub repository settings:

1. Go to `Settings` -> `Webhooks` -> `Add webhook`
2. Configure:
   - Payload URL: `https://packagist.org/api/github?username=bjoernch`
   - Content type: `application/json`
   - Secret: your Packagist API token
   - Events: `Just the push event`

Then save webhook.

## Manual package refresh API

If needed, trigger manually:

```sh
curl -XPOST -H 'content-type:application/json' \
  'https://packagist.org/api/update-package?username=bjoernch&apiToken=API_TOKEN' \
  -d '{"repository":{"url":"https://github.com/bjoernch/universal-roundcube-oidc-mail-sso"}}'
```

## Notes

- If you later add an open-source license file, update `composer.json` `license` accordingly.
- Prefer release tags (`vX.Y.Z`) for stable installs.
