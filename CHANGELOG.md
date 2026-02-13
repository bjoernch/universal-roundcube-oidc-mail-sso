# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [0.3.1] - 2026-02-13

### Added
- Composer metadata for official package submission:
  - `composer.json` at repository root
  - package name `bjoernch/universal_oidc_mail_sso`
  - package type `roundcube-plugin`
  - `roundcube/plugin-installer` dependency
  - Roundcube installer metadata (`extra.roundcube`)
- Root compatibility entry files for installer-based plugin layout:
  - `universal_oidc_mail_sso.php`
  - `callback_bridge.php`
  - `config.inc.php.dist`
- New documentation for existing Docker-based Roundcube installations:
  - `docs/existing-roundcube-docker.md`
- New Packagist submission guide:
  - `docs/packagist.md`

### Changed
- Composer package description clarified to emphasize IMAP/SMTP provisioning.
- Documentation index updated with explicit links for Packagist and existing Docker deployment integration.

### Fixed
- Release workflow validation issue in `.github/workflows/release-artifacts.yml`:
  - avoid direct `secrets.*` usage in step `if` expression
  - use job-level env wiring for optional GPG import
  - add explicit `contents: write` permission for GitHub release uploads

## [0.3.0] - 2026-02-13

### Added
- In-page SSO CTA login mode with policy-driven hide/show of native Roundcube login fields.
- Admin dashboard logout action that routes through Roundcube logout and OIDC end-session flow.
- Centralized admin authorization guard with consistent CSRF validation for admin POST actions.
- Structured security logging with request id, IP, task/action context, and sensitive-field redaction.
- Database-backed rate-limiting support and hardened policy controls in admin UI.
- Key-rotation helper script: `plugins/universal_oidc_mail_sso/misc/rotate_mailbox_keys.php`.
- Security lint script: `plugins/universal_oidc_mail_sso/misc/security_lint.php`.
- Smoke flow test script: `scripts/smoke_web_flows.sh`.
- CI workflow for lint + tests: `.github/workflows/ci.yml`.
- Release artifact workflow: `.github/workflows/release-artifacts.yml`.

### Changed
- Admin dashboard redesigned to a modern Bootstrap 5 aligned layout.
- Default login CTA text set to `Login with SSO` (still admin-configurable).
- OIDC direct-admin-link flow improved to return to admin dashboard after auth.
- Mailbox encryption supports key identifiers and key-ring based rotation.

### Fixed
- Duplicate-index migration noise for `idx_audit_row_hash` by checking index existence first.
- Admin logout CSRF handling from dashboard action.

## [0.2.2] - 2026-02-12
- OIDC end-session logout redirect and direct-admin routing fixes.

## [0.2.1] - 2026-02-12
- Strict OIDC email binding defaults and improved admin UX.

## [0.2.0] - 2026-02-12
- Initial public hardening/UX release.

## [0.1.0] - 2026-02-12
- Initial release.
