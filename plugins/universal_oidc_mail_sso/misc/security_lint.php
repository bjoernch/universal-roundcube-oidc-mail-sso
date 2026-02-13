#!/usr/bin/env php
<?php

declare(strict_types=1);

$root = dirname(__DIR__);
$files = [
    $root . '/universal_oidc_mail_sso.php',
    $root . '/lib/OidcClient.php',
    $root . '/lib/Storage.php',
    $root . '/lib/Crypto.php',
];

$violations = [];

$forbiddenPatterns = [
    '/write_log\([^\n]*\$_(GET|POST|REQUEST|COOKIE)\b/i' => 'Do not log raw superglobal values directly.',
    '/write_log\([^\n]*(password|app_password|access_token|refresh_token|id_token|client_secret)\b/i' => 'Do not log sensitive secrets/tokens.',
    '/var_dump\s*\(/i' => 'Debug var_dump should not be committed.',
    '/print_r\s*\(/i' => 'Debug print_r should not be committed.',
];

foreach ($files as $file) {
    $src = @file_get_contents($file);
    if (!is_string($src)) {
        $violations[] = [$file, 0, 'Unable to read file'];
        continue;
    }

    $lines = preg_split('/\R/', $src);
    if (!is_array($lines)) {
        continue;
    }

    foreach ($lines as $ln => $line) {
        $lineNo = $ln + 1;
        foreach ($forbiddenPatterns as $pattern => $message) {
            if (preg_match($pattern, $line)) {
                $violations[] = [$file, $lineNo, $message];
            }
        }
    }
}

if ($violations !== []) {
    fwrite(STDERR, "Security lint failed:\n");
    foreach ($violations as [$file, $lineNo, $message]) {
        fwrite(STDERR, sprintf("- %s:%d %s\n", $file, $lineNo, $message));
    }
    exit(1);
}

echo "Security lint passed.\n";
