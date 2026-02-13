# Admin and User Flows

## Main URLs

- Roundcube root: `http://localhost:8080/`
- Admin dashboard: `/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin`
- User self-service: `/?_task=settings&_action=plugin.universal_oidc_mail_sso_user_settings`

## First-run flow

1. User reaches Roundcube login.
2. Plugin starts OIDC login flow.
3. If bootstrap is pending and user is in admin group:
   - admin onboarding/policy setup is required first.
4. Admin can choose to configure own mailbox now or later.
5. Regular users then run mailbox connect flow once.

## Regular login flow

1. OIDC authentication succeeds.
2. Plugin looks up mailbox mapping by OIDC `sub`.
3. Plugin injects IMAP/SMTP credentials into Roundcube hooks.
4. User lands in mailbox automatically.

## Zero-knowledge mode (client-side)

When enabled by admin policy:
- Setup page generates a client passphrase and wraps mailbox password client-side.
- User must unlock mailbox after OIDC login with that passphrase.
- Server still stores encrypted blob, but cannot decrypt without user-supplied passphrase.

When disabled:
- Mailbox password is still encrypted at rest using server-side key material (`RCUBE_MAILBOX_KEY`).

## Self-service actions

Users can:
- Open mailbox setup again
- Test connectivity (policy/mode dependent)
- Reset mailbox mapping
- Download support/recovery artifacts (if enabled by current flow)

## Admin actions

Admins can:
- Update policy values and login UX mode
- Restrict allowed domains/hosts
- Enable/disable mapped users
- Clear mailbox mappings
- Review audit data
