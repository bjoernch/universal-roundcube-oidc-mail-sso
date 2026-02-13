#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once __DIR__ . '/../lib/Crypto.php';
require_once __DIR__ . '/../lib/JwksValidator.php';
require_once __DIR__ . '/../lib/OidcClient.php';

use UniversalOidcMailSso\Lib\Crypto;
use UniversalOidcMailSso\Lib\OidcClient;

function ok(string $name): void
{
    echo "[OK] {$name}\n";
}

function fail(string $name, string $msg): void
{
    fwrite(STDERR, "[FAIL] {$name}: {$msg}\n");
    exit(1);
}

function b64url(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function testCryptoRoundtrip(): void
{
    $name = 'crypto round-trip';

    if (getenv('RCUBE_MAILBOX_KEY') === false) {
        putenv('RCUBE_MAILBOX_KEY=' . base64_encode(random_bytes(32)));
    }

    try {
        $crypto = new Crypto(getenv('RCUBE_MAILBOX_KEY') ?: null);
        $pt = 'hello-' . bin2hex(random_bytes(4));
        $enc = $crypto->encrypt($pt);
        $dec = $crypto->decrypt($enc['enc_alg'], $enc['password_enc'], $enc['enc_nonce']);

        if ($dec !== $pt) {
            fail($name, 'round-trip mismatch');
        }
    } catch (Throwable $e) {
        fail($name, $e->getMessage());
    }

    ok($name);
}

function testOidcDiscoveryAndJwksValidation(): void
{
    $name = 'oidc discovery + jwks validation (mocked)';

    $privateKeyRes = openssl_pkey_new([
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ]);
    if ($privateKeyRes === false) {
        fail($name, 'could not create RSA key');
    }

    openssl_pkey_export($privateKeyRes, $privatePem);
    $details = openssl_pkey_get_details($privateKeyRes);
    if (!$details || empty($details['rsa'])) {
        fail($name, 'missing RSA key details');
    }

    $kid = 'kid-1';
    $jwks = [
        'keys' => [[
            'kty' => 'RSA',
            'kid' => $kid,
            'alg' => 'RS256',
            'use' => 'sig',
            'n' => b64url($details['rsa']['n']),
            'e' => b64url($details['rsa']['e']),
        ]],
    ];

    $now = time();
    $header = ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $kid];
    $payload = [
        'iss' => 'https://oidc.example.com',
        'aud' => 'roundcube-client',
        'sub' => 'subject-123',
        'email' => 'user@felgner.ch',
        'nonce' => 'nonce-123',
        'iat' => $now,
        'exp' => $now + 600,
    ];

    $headerB64 = b64url(json_encode($header, JSON_UNESCAPED_SLASHES));
    $payloadB64 = b64url(json_encode($payload, JSON_UNESCAPED_SLASHES));
    $signed = $headerB64 . '.' . $payloadB64;

    $sig = '';
    if (!openssl_sign($signed, $sig, $privatePem, OPENSSL_ALGO_SHA256)) {
        fail($name, 'openssl_sign failed');
    }

    $jwt = $signed . '.' . b64url($sig);

    $httpHandler = static function (string $method, string $url) use ($jwks): string {
        if ($method === 'GET' && $url === 'https://oidc.example.com/.well-known/openid-configuration') {
            return json_encode([
                'issuer' => 'https://oidc.example.com',
                'authorization_endpoint' => 'https://oidc.example.com/authorize',
                'token_endpoint' => 'https://oidc.example.com/token',
                'jwks_uri' => 'https://oidc.example.com/jwks',
            ], JSON_UNESCAPED_SLASHES);
        }

        if ($method === 'GET' && $url === 'https://oidc.example.com/jwks') {
            return json_encode($jwks, JSON_UNESCAPED_SLASHES);
        }

        throw new RuntimeException('Unexpected request: ' . $method . ' ' . $url);
    };

    try {
        $client = new OidcClient([
            'issuer' => 'https://oidc.example.com',
            'client_id' => 'roundcube-client',
            'client_secret' => '',
            'redirect_uri' => 'https://mail.example.com/?_task=login&_action=plugin.universal_oidc_mail_sso_callback',
        ], $httpHandler);

        $discovery = $client->discover();
        $claims = $client->validateIdToken($discovery, $jwt, 'nonce-123');

        if (($claims['email'] ?? null) !== 'user@felgner.ch') {
            fail($name, 'claims did not validate as expected');
        }
    } catch (Throwable $e) {
        fail($name, $e->getMessage());
    }

    ok($name);
}

function testEndSessionUrlBuilder(): void
{
    $name = 'oidc end-session URL builder';

    try {
        $client = new OidcClient([
            'issuer' => 'https://oidc.example.com',
            'client_id' => 'roundcube-client',
            'client_secret' => '',
            'redirect_uri' => 'https://mail.example.com/cb',
        ]);

        $discovery = [
            'end_session_endpoint' => 'https://oidc.example.com/logout',
        ];

        $url = $client->buildEndSessionUrl($discovery, 'id-token-hint', 'https://mail.example.com/');
        if (strpos($url, 'id_token_hint=id-token-hint') === false || strpos($url, 'post_logout_redirect_uri=') === false) {
            fail($name, 'end-session URL missing expected query params');
        }
    } catch (Throwable $e) {
        fail($name, $e->getMessage());
    }

    ok($name);
}

function testDiscoveryAllowlistAndPinning(): void
{
    $name = 'oidc discovery allowlist + metadata pin';

    $doc = [
        'issuer' => 'https://oidc.example.com',
        'authorization_endpoint' => 'https://oidc.example.com/authorize',
        'token_endpoint' => 'https://oidc.example.com/token',
        'jwks_uri' => 'https://oidc.example.com/jwks',
    ];
    $pin = hash('sha256', json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

    $httpHandler = static function (string $method, string $url) use ($doc): string {
        if ($method === 'GET' && $url === 'https://oidc.example.com/.well-known/openid-configuration') {
            return json_encode($doc, JSON_UNESCAPED_SLASHES);
        }
        throw new RuntimeException('Unexpected request: ' . $method . ' ' . $url);
    };

    try {
        $client = new OidcClient([
            'issuer' => 'https://oidc.example.com',
            'client_id' => 'roundcube-client',
            'client_secret' => '',
            'redirect_uri' => 'https://mail.example.com/cb',
            'allowed_issuers' => 'https://oidc.example.com',
            'metadata_pin_sha256' => $pin,
        ], $httpHandler);
        $discovery = $client->discover();
        if (($discovery['issuer'] ?? '') !== 'https://oidc.example.com') {
            fail($name, 'issuer mismatch');
        }
    } catch (Throwable $e) {
        fail($name, $e->getMessage());
    }

    ok($name);
}

testCryptoRoundtrip();
testOidcDiscoveryAndJwksValidation();
testEndSessionUrlBuilder();
testDiscoveryAllowlistAndPinning();

echo "All tests passed.\n";
