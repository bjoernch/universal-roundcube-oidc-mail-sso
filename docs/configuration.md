# Configuration Reference

This page documents every app parameter used by this repository stack and plugin.

## Format

- `Required`: whether you should explicitly set it
- `Default`: default from `.env.example` / plugin behavior
- `Used by`: stack service or plugin logic

## Core stack parameters

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `ROUNDCUBE_PORT` | No | `8080` | `docker-compose` | Host port published to Roundcube container port `80`. |
| `DB_ROOT_PASSWORD` | Yes | `change-root-pass` | MariaDB container | MariaDB root password (schema/admin tasks). |
| `DB_NAME` | Yes | `roundcube` | MariaDB + Roundcube | Database name used by Roundcube and plugin tables. |
| `DB_USER` | Yes | `roundcube` | MariaDB + Roundcube | Application DB username for Roundcube. |
| `DB_PASSWORD` | Yes | `change-db-pass` | MariaDB + Roundcube | Application DB password for Roundcube. |

## Roundcube bootstrap defaults

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `DEFAULT_IMAP_URI` | No | `ssl://imap.example.com` | Roundcube container env | Default IMAP URI before per-user plugin mailbox mapping is applied. |
| `DEFAULT_IMAP_PORT` | No | `993` | Roundcube + plugin | Default IMAP port. Also used as plugin form default. |
| `DEFAULT_SMTP_URI` | No | `tls://smtp.example.com` | Roundcube container env | Default SMTP URI before per-user mapping is applied. |
| `DEFAULT_SMTP_PORT` | No | `587` | Roundcube + plugin | Default SMTP port. Also used as plugin form default. |

## OIDC parameters

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `OIDC_ISSUER` | Yes | `https://oidc.example.com` | Plugin | OIDC issuer base URL used for discovery. |
| `OIDC_CLIENT_ID` | Yes | `roundcube` | Plugin | OIDC client id. |
| `OIDC_CLIENT_SECRET` | Depends | empty | Plugin | Needed for confidential clients. Leave empty for public clients if provider allows. |
| `OIDC_REDIRECT_URI` | Recommended | `http://localhost:8080/plugins/universal_oidc_mail_sso/callback_bridge.php` | Plugin | OAuth callback URL registered at provider. |
| `OIDC_POST_LOGOUT_REDIRECT_URI` | No | `http://localhost:8080/` | Plugin | Redirect target after provider logout. |
| `OIDC_SCOPES` | No | `openid email profile groups` | Plugin | Requested scopes. `email` and stable subject are required for mapping. |
| `ALLOWED_ISSUERS` | No | empty | Plugin | Optional allow-list of accepted issuer URLs (comma-separated). |
| `METADATA_PIN_SHA256` | No | empty | Plugin | Optional SHA-256 pin of OIDC discovery metadata. |

## Identity and mailbox policy

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `ALLOWED_EMAIL_DOMAIN` | No | empty | Plugin | Allowed OIDC email domain(s). Empty or `*` means allow all. |
| `ALLOW_CUSTOM_MAILBOX_EMAIL` | No | `false` | Plugin | If `false`, mailbox email must match verified OIDC email. |
| `ADMIN_GROUP_NAME` | No | `webmail_admin` | Plugin | OIDC group(s) allowed to access admin dashboard (comma-separated supported). |
| `USER_GROUP_NAME` | No | `webmail` | Plugin | OIDC group(s) allowed to use self-service settings. |
| `ADMIN_EMAILS` | No | empty | Plugin | Fallback admin allow-list if group claim is missing. |

## Credential encryption and key management

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `RCUBE_MAILBOX_KEY` | Yes (single-key mode) | `REPLACE_ME_BASE64_32_BYTES` | Plugin crypto | Base64 of exactly 32 random bytes. Primary server-side encryption key. |
| `RCUBE_MAILBOX_KEYS` | No | empty | Plugin crypto | Optional keyring for rotation: `keyid:base64,keyid2:base64`. |
| `RCUBE_MAILBOX_KEY_ID` | No | `v1` | Plugin crypto | Active key id when keyring mode is used. |
| `CLIENT_SIDE_WRAP_ENABLED` | No | `false` | Plugin policy | Enables optional zero-knowledge mode (client-side passphrase wrapping during onboarding). |

## Login/session behavior

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `FORCE_HTTPS` | No | `false` | Plugin | Forces HTTPS scheme in generated URLs behind proxies. |
| `DISABLE_PASSWORD_LOGIN` | No | `true` | Plugin | Disables classic username/password login flow and enforces OIDC-first. |
| `LOGIN_MODE` | No | `auto` | Plugin | `auto` (redirect to IdP) or `button` (show in-page SSO button). |
| `HIDE_STANDARD_LOGIN_FORM` | No | `true` | Plugin | Hide standard Roundcube login form when button mode is used. |
| `LOGIN_BUTTON_TEXT` | No | `Login with SSO` | Plugin | Custom SSO button label in login UI. |
| `SESSION_IDLE_TIMEOUT_SEC` | No | `1800` | Plugin | Idle session timeout in seconds. |
| `SESSION_ABSOLUTE_TIMEOUT_SEC` | No | `43200` | Plugin | Absolute max authenticated session lifetime in seconds. |

## Rate-limit and auth hardening

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `LOGIN_RATE_LIMIT_PER_5M` | No | `20` | Plugin | Max OIDC login-init attempts per IP in 5 minutes. |
| `CALLBACK_RATE_LIMIT_PER_5M` | No | `30` | Plugin | Max callback requests per IP in 5 minutes. |
| `SETUP_RATE_LIMIT_PER_5M` | No | `8` | Plugin | Max mailbox setup submissions per IP in 5 minutes. |
| `AUTH_LOCK_SECONDS` | No | `600` | Plugin | Temporary lock duration after repeated failed auth/autologin. |

## Connect-form defaults (user onboarding)

| Variable | Required | Default | Used by | Description |
|---|---:|---|---|---|
| `DEFAULT_IMAP_HOST` | No | `imap.example.com` | Plugin connect UI | Pre-filled IMAP host in mailbox setup. |
| `DEFAULT_IMAP_PORT` | No | `993` | Plugin connect UI | Pre-filled IMAP port in mailbox setup. |
| `DEFAULT_IMAP_SECURITY` | No | `ssl` | Plugin connect UI | Pre-filled IMAP security: `ssl`, `tls`, `starttls`, `none`. |
| `DEFAULT_SMTP_HOST` | No | `smtp.example.com` | Plugin connect UI | Pre-filled SMTP host in mailbox setup. |
| `DEFAULT_SMTP_PORT` | No | `587` | Plugin connect UI | Pre-filled SMTP port in mailbox setup. |
| `DEFAULT_SMTP_SECURITY` | No | `tls` | Plugin connect UI | Pre-filled SMTP security: `ssl`, `tls`, `starttls`, `none`. |
| `DEFAULT_SMTP_AUTH` | No | `1` | Plugin connect UI | Pre-filled SMTP auth toggle (`1` enabled, `0` disabled). |

## Recommended minimum production values

- Set strong unique values for `DB_ROOT_PASSWORD` and `DB_PASSWORD`.
- Use HTTPS and set `FORCE_HTTPS=true` behind reverse proxy.
- Keep `DISABLE_PASSWORD_LOGIN=true` unless you explicitly need fallback.
- Set `ALLOW_CUSTOM_MAILBOX_EMAIL=false` unless policy requires override.
- Store `RCUBE_MAILBOX_KEY` in secret manager, not in VCS.
- Keep `HIDE_STANDARD_LOGIN_FORM=true` when enforcing SSO.
