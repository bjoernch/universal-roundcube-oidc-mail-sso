<?php

declare(strict_types=1);

namespace UniversalOidcMailSso\Lib;

use RuntimeException;

class JwksValidator
{
    public function validateIdToken(string $jwt, array $jwks, array $expect): array
    {
        [$headerB64, $payloadB64, $sigB64] = $this->splitJwt($jwt);
        $header = $this->jsonDecode($this->b64urlDecode($headerB64), 'JWT header');
        $payload = $this->jsonDecode($this->b64urlDecode($payloadB64), 'JWT payload');
        $signature = $this->b64urlDecode($sigB64);

        if (($header['alg'] ?? '') !== 'RS256') {
            throw new RuntimeException('Only RS256 ID tokens are supported.');
        }

        $kid = $header['kid'] ?? null;
        $jwk = $this->findJwk($jwks, $kid);
        $pem = $this->jwkToPem($jwk);

        $signedPart = $headerB64 . '.' . $payloadB64;
        $verified = openssl_verify($signedPart, $signature, $pem, OPENSSL_ALGO_SHA256);
        if ($verified !== 1) {
            throw new RuntimeException('ID token signature validation failed.');
        }

        $this->validateClaims($payload, $expect);

        return $payload;
    }

    private function validateClaims(array $claims, array $expect): void
    {
        $now = time();

        foreach (['iss', 'aud', 'nonce', 'exp', 'iat', 'sub'] as $required) {
            if (!array_key_exists($required, $claims)) {
                throw new RuntimeException('Missing required claim: ' . $required);
            }
        }

        if (($claims['iss'] ?? null) !== ($expect['issuer'] ?? null)) {
            throw new RuntimeException('Issuer mismatch.');
        }

        $aud = $claims['aud'];
        $audOk = is_array($aud) ? in_array($expect['client_id'], $aud, true) : ($aud === $expect['client_id']);
        if (!$audOk) {
            throw new RuntimeException('Audience mismatch.');
        }

        if (($claims['nonce'] ?? null) !== ($expect['nonce'] ?? null)) {
            throw new RuntimeException('Nonce mismatch.');
        }

        if (($claims['exp'] ?? 0) < $now - 30) {
            throw new RuntimeException('ID token is expired.');
        }

        if (($claims['iat'] ?? 0) > $now + 60) {
            throw new RuntimeException('ID token iat is in the future.');
        }

        if (isset($claims['nbf']) && $claims['nbf'] > $now + 30) {
            throw new RuntimeException('ID token not yet valid.');
        }
    }

    private function splitJwt(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed JWT.');
        }

        return $parts;
    }

    private function findJwk(array $jwks, ?string $kid): array
    {
        $keys = $jwks['keys'] ?? [];
        foreach ($keys as $key) {
            if (($key['kty'] ?? '') !== 'RSA') {
                continue;
            }

            if ($kid === null || ($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }

        throw new RuntimeException('No matching RSA JWK found.');
    }

    private function jwkToPem(array $jwk): string
    {
        $n = $this->b64urlDecode($jwk['n'] ?? '');
        $e = $this->b64urlDecode($jwk['e'] ?? '');

        if ($n === '' || $e === '') {
            throw new RuntimeException('Invalid JWK modulus/exponent.');
        }

        $modulus = $this->asn1Integer($n);
        $exponent = $this->asn1Integer($e);
        $rsaPublicKey = $this->asn1Sequence($modulus . $exponent);

        $algorithmIdentifier = $this->asn1Sequence(
            $this->asn1ObjectIdentifier('1.2.840.113549.1.1.1') . $this->asn1Null()
        );

        $subjectPublicKeyInfo = $this->asn1Sequence(
            $algorithmIdentifier . $this->asn1BitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private function asn1Integer(string $data): string
    {
        if (ord($data[0]) > 0x7f) {
            $data = "\x00" . $data;
        }

        return "\x02" . $this->asn1Length(strlen($data)) . $data;
    }

    private function asn1Sequence(string $data): string
    {
        return "\x30" . $this->asn1Length(strlen($data)) . $data;
    }

    private function asn1BitString(string $data): string
    {
        return "\x03" . $this->asn1Length(strlen($data) + 1) . "\x00" . $data;
    }

    private function asn1Null(): string
    {
        return "\x05\x00";
    }

    private function asn1ObjectIdentifier(string $oid): string
    {
        $parts = array_map('intval', explode('.', $oid));
        $first = (40 * $parts[0]) + $parts[1];
        $encoded = chr($first);

        for ($i = 2; $i < count($parts); $i++) {
            $encoded .= $this->encodeBase128($parts[$i]);
        }

        return "\x06" . $this->asn1Length(strlen($encoded)) . $encoded;
    }

    private function encodeBase128(int $value): string
    {
        $bytes = [($value & 0x7f)];
        $value >>= 7;

        while ($value > 0) {
            array_unshift($bytes, ($value & 0x7f) | 0x80);
            $value >>= 7;
        }

        return implode('', array_map('chr', $bytes));
    }

    private function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $temp = '';
        while ($length > 0) {
            $temp = chr($length & 0xff) . $temp;
            $length >>= 8;
        }

        return chr(0x80 | strlen($temp)) . $temp;
    }

    private function jsonDecode(string $json, string $label): array
    {
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new RuntimeException('Unable to parse ' . $label . '.');
        }

        return $data;
    }

    private function b64urlDecode(string $data): string
    {
        $data = strtr($data, '-_', '+/');
        $padding = strlen($data) % 4;
        if ($padding > 0) {
            $data .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode($data, true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64url data.');
        }

        return $decoded;
    }
}
