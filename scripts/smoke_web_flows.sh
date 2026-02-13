#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
DB_SERVICE="${DB_SERVICE:-db}"

ok() { echo "[OK] $1"; }
fail() { echo "[FAIL] $1" >&2; exit 1; }

sql() {
  local q="$1"
  printf '%s\n' "$q" | docker compose exec -T "$DB_SERVICE" sh -lc 'mariadb -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' >/dev/null
}

contains() {
  local haystack="$1"
  local needle="$2"
  printf '%s' "$haystack" | grep -q "$needle"
}

# Enforce button mode + hidden native login to verify CTA-only UX.
sql "INSERT INTO oidc_mail_sso_policy (policy_key,policy_value,updated_at) VALUES ('login_mode','button',NOW()) ON DUPLICATE KEY UPDATE policy_value=VALUES(policy_value), updated_at=NOW();"
sql "INSERT INTO oidc_mail_sso_policy (policy_key,policy_value,updated_at) VALUES ('hide_standard_login_form','1',NOW()) ON DUPLICATE KEY UPDATE policy_value=VALUES(policy_value), updated_at=NOW();"

login_html="$(curl -fsS "${BASE_URL}/?_task=login")"
contains "$login_html" 'pizsso-cta' && ok "login page has SSO CTA" || fail "login page has SSO CTA"
! contains "$login_html" 'rcmloginuser' && ok "login page hides username field" || fail "login page hides username field"

admin_headers="$(curl -sSI "${BASE_URL}/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin")"
printf '%s' "$admin_headers" | grep -qi 'location: /?_task=login&_action=plugin.universal_oidc_mail_sso_login' && ok "admin direct link redirects into OIDC login flow" || fail "admin direct link redirects into OIDC login flow"

logout_headers="$(curl -sSI -X POST "${BASE_URL}/?_task=settings&_action=plugin.universal_oidc_mail_sso_admin_logout")"
printf '%s' "$logout_headers" | grep -Eqi '^HTTP/.* (302|403)' && ok "admin logout requires CSRF when called without session/token" || fail "admin logout requires CSRF when called without session/token"

echo "All smoke tests passed."
