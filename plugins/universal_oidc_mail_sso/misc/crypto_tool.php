#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../lib/Crypto.php';

use UniversalOidcMailSso\Lib\Crypto;

$cmd = $argv[1] ?? 'self-test';

function out(string $line): void
{
    fwrite(STDOUT, $line . PHP_EOL);
}

try {
    $crypto = new Crypto(getenv('RCUBE_MAILBOX_KEY') ?: null);
} catch (Throwable $e) {
    out('ERROR: ' . $e->getMessage());
    exit(1);
}

$info = $crypto->keyInfo();
out('Key loaded: ' . ($info['loaded'] ? 'yes' : 'no'));
out('Key length: ' . $info['length']);
out('Backend: ' . ($info['sodium'] ? 'libsodium' : 'openssl-aes-256-gcm'));

if ($cmd === 'self-test') {
    $probe = 'probe-' . bin2hex(random_bytes(8));
    $enc = $crypto->encrypt($probe);
    $dec = $crypto->decrypt($enc['enc_alg'], $enc['password_enc'], $enc['enc_nonce']);
    out($dec === $probe ? 'SELF-TEST: OK' : 'SELF-TEST: FAIL');
    exit($dec === $probe ? 0 : 2);
}

if ($cmd === 'encrypt') {
    $plaintext = $argv[2] ?? '';
    if ($plaintext === '') {
        out('Usage: crypto_tool.php encrypt <plaintext>');
        exit(1);
    }

    $enc = $crypto->encrypt($plaintext);
    out(json_encode($enc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    exit(0);
}

if ($cmd === 'decrypt') {
    $encAlg = $argv[2] ?? '';
    $passwordEnc = $argv[3] ?? '';
    $encNonce = $argv[4] ?? '';
    if ($encAlg === '' || $passwordEnc === '' || $encNonce === '') {
        out('Usage: crypto_tool.php decrypt <enc_alg> <password_enc_b64> <enc_nonce_b64>');
        exit(1);
    }

    out($crypto->decrypt($encAlg, $passwordEnc, $encNonce));
    exit(0);
}

out('Usage: crypto_tool.php [self-test|encrypt|decrypt]');
exit(1);
