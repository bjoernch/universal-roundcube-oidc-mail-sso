# Release Process

## 1. Validate

```sh
php plugins/universal_oidc_mail_sso/misc/security_lint.php
php plugins/universal_oidc_mail_sso/misc/run_tests.php
```

## 2. Update changelog

- Edit `CHANGELOG.md`
- Move items from `Unreleased` to target version section

## 3. Create signed tag

```sh
git tag -s vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

If signing key is unavailable:

```sh
git tag vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

## 4. Build local release artifacts (optional)

```sh
./scripts/build_release_artifacts.sh vX.Y.Z
```

Outputs:
- `dist/universal-roundcube-oidc-mail-sso-vX.Y.Z.tar.gz`
- `dist/...sha256`
- `dist/...asc` (if GPG key exists)

## 5. GitHub release assets

- Workflow `.github/workflows/release-artifacts.yml` runs on `v*` tags
- Uploads archive + checksum (+ signature when configured)
