#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../lib/Crypto.php';

use UniversalOidcMailSso\Lib\Crypto;

function usage(): void
{
    $msg = <<<TXT
Usage:
  php plugins/universal_oidc_mail_sso/misc/rotate_mailbox_keys.php [--apply] [--limit=100] [--oidc-sub=<sub>]

Behavior:
  - Dry-run by default (no DB writes)
  - Reads DB from env:
    ROUNDCUBEMAIL_DB_HOST/DB_HOST (default: db)
    ROUNDCUBEMAIL_DB_PORT/DB_PORT (default: 3306)
    ROUNDCUBEMAIL_DB_NAME/DB_NAME
    ROUNDCUBEMAIL_DB_USER/DB_USER
    ROUNDCUBEMAIL_DB_PASSWORD/DB_PASSWORD
    ROUNDCUBEMAIL_DB_PREFIX/DB_PREFIX (optional)
  - Uses Crypto keyring env:
    RCUBE_MAILBOX_KEYS + RCUBE_MAILBOX_KEY_ID (or RCUBE_MAILBOX_KEY)
TXT;
    fwrite(STDERR, $msg . PHP_EOL);
}

$options = getopt('', ['apply', 'limit::', 'oidc-sub::', 'help']);
if (isset($options['help'])) {
    usage();
    exit(0);
}

$apply = isset($options['apply']);
$limit = isset($options['limit']) ? max(1, (int) $options['limit']) : 500;
$oidcSubFilter = isset($options['oidc-sub']) ? trim((string) $options['oidc-sub']) : '';

$dbHost = getenv('ROUNDCUBEMAIL_DB_HOST') ?: (getenv('DB_HOST') ?: 'db');
$dbPort = (int) (getenv('ROUNDCUBEMAIL_DB_PORT') ?: (getenv('DB_PORT') ?: '3306'));
$dbName = getenv('ROUNDCUBEMAIL_DB_NAME') ?: getenv('DB_NAME') ?: '';
$dbUser = getenv('ROUNDCUBEMAIL_DB_USER') ?: getenv('DB_USER') ?: '';
$dbPass = getenv('ROUNDCUBEMAIL_DB_PASSWORD') ?: getenv('DB_PASSWORD') ?: '';
$dbPrefix = getenv('ROUNDCUBEMAIL_DB_PREFIX') ?: (getenv('DB_PREFIX') ?: '');

if ($dbName === '' || $dbUser === '') {
    fwrite(STDERR, "Missing DB credentials in environment.\n");
    usage();
    exit(1);
}

try {
    $crypto = new Crypto(getenv('RCUBE_MAILBOX_KEY') ?: null);
} catch (Throwable $e) {
    fwrite(STDERR, "Crypto init failed: {$e->getMessage()}\n");
    exit(1);
}

$table = $dbPrefix . 'oidc_mail_sso_mailbox';
$dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $dbHost, $dbPort, $dbName);

try {
    $pdo = new PDO($dsn, $dbUser, $dbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Throwable $e) {
    fwrite(STDERR, "DB connection failed: {$e->getMessage()}\n");
    exit(1);
}

$sql = "SELECT id, oidc_sub, email, enc_alg, password_enc, enc_nonce, key_id FROM `{$table}`";
$params = [];
if ($oidcSubFilter !== '') {
    $sql .= ' WHERE oidc_sub = :sub';
    $params[':sub'] = $oidcSubFilter;
}
$sql .= ' ORDER BY id ASC LIMIT ' . $limit;

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$rows = $stmt->fetchAll();

$total = count($rows);
$rotated = 0;
$skipped = 0;
$errors = 0;

$update = $pdo->prepare(
    "UPDATE `{$table}` SET password_enc = :password_enc, enc_alg = :enc_alg, enc_nonce = :enc_nonce, key_id = :key_id, updated_at = NOW() WHERE id = :id"
);

foreach ($rows as $row) {
    $id = (int) ($row['id'] ?? 0);
    $sub = (string) ($row['oidc_sub'] ?? '');
    $oldKeyId = (string) ($row['key_id'] ?? '');

    try {
        $plain = $crypto->decrypt(
            (string) ($row['enc_alg'] ?? ''),
            (string) ($row['password_enc'] ?? ''),
            (string) ($row['enc_nonce'] ?? ''),
            $oldKeyId
        );

        $new = $crypto->encrypt($plain);
        $newKeyId = (string) ($new['key_id'] ?? 'v1');

        if ($newKeyId === $oldKeyId) {
            $skipped++;
            echo "[SKIP] id={$id} sub={$sub} key_id unchanged ({$oldKeyId})\n";
            continue;
        }

        if ($apply) {
            $update->execute([
                ':password_enc' => (string) $new['password_enc'],
                ':enc_alg' => (string) $new['enc_alg'],
                ':enc_nonce' => (string) $new['enc_nonce'],
                ':key_id' => $newKeyId,
                ':id' => $id,
            ]);
        }

        $rotated++;
        echo '[' . ($apply ? 'ROTATE' : 'PLAN') . "] id={$id} sub={$sub} {$oldKeyId} -> {$newKeyId}\n";
    } catch (Throwable $e) {
        $errors++;
        echo "[ERROR] id={$id} sub={$sub} {$e->getMessage()}\n";
    }
}

echo "\nSummary: total={$total} rotated={$rotated} skipped={$skipped} errors={$errors} mode=" . ($apply ? 'apply' : 'dry-run') . "\n";
exit($errors > 0 ? 2 : 0);
