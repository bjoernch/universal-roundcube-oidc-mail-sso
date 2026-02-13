#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version-tag>" >&2
  exit 1
fi

OUT_DIR="dist"
ARCHIVE="${OUT_DIR}/universal-roundcube-oidc-mail-sso-${VERSION}.tar.gz"
SHA_FILE="${ARCHIVE}.sha256"
SIG_FILE="${ARCHIVE}.asc"

mkdir -p "$OUT_DIR"

git archive --format=tar.gz --prefix="universal-roundcube-oidc-mail-sso-${VERSION}/" -o "$ARCHIVE" "$VERSION"
sha256sum "$ARCHIVE" > "$SHA_FILE"

if command -v gpg >/dev/null 2>&1; then
  if gpg --list-secret-keys >/dev/null 2>&1; then
    gpg --armor --detach-sign --output "$SIG_FILE" "$ARCHIVE"
    echo "Signed artifact created: $SIG_FILE"
  else
    echo "No GPG secret key available; skipped detached signature." >&2
  fi
else
  echo "gpg not installed; skipped detached signature." >&2
fi

echo "Artifact: $ARCHIVE"
echo "Checksum: $SHA_FILE"
