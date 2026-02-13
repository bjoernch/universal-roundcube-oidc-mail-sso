# Security Model

## Baseline guarantees

- OIDC login uses Authorization Code + PKCE.
- ID token is validated against provider JWKS.
- Mailbox password is never stored plaintext.
- Decryption occurs only at runtime for auth/connect operations.
- Audit records are stored for key auth/provisioning events.

## Encryption at rest

Default mode (zero-knowledge disabled):
- Passwords are encrypted at rest with server-side key material.
- Preferred algorithm: `libsodium` `sodium_secretbox`.
- Fallback: `AES-256-GCM` via OpenSSL.
- Key source: `RCUBE_MAILBOX_KEY` / `RCUBE_MAILBOX_KEYS`.

Zero-knowledge mode (client-side enabled):
- Browser wraps mailbox secret using passphrase-derived key before submit.
- Server stores wrapped blob and metadata.
- User unlocks post-OIDC with passphrase.

## Operational hardening

- Enforce HTTPS end-to-end.
- Keep secrets in environment or secret manager.
- Rotate keyring safely with `RCUBE_MAILBOX_KEYS` + rotate script.
- Keep strict mailbox binding (`ALLOW_CUSTOM_MAILBOX_EMAIL=false`) unless explicitly needed.
- Keep standard login disabled (`DISABLE_PASSWORD_LOGIN=true`) for OIDC-only posture.

## Recommended reverse-proxy headers

### Nginx

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self'; connect-src 'self'; frame-ancestors 'self';" always;
```

### Apache

```apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set Content-Security-Policy "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self'; connect-src 'self'; frame-ancestors 'self';"
```
