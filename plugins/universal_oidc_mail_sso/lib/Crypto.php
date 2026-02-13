<?php

declare(strict_types=1);

namespace UniversalOidcMailSso\Lib;

use RuntimeException;

class Crypto
{
    private const KEY_LEN = 32;

    private array $keysById = [];
    private string $primaryKeyId = 'v1';

    public function __construct(?string $base64Key = null)
    {
        $ring = getenv('RCUBE_MAILBOX_KEYS') ?: '';
        $single = $base64Key ?: getenv('RCUBE_MAILBOX_KEY') ?: '';
        $this->primaryKeyId = trim((string) (getenv('RCUBE_MAILBOX_KEY_ID') ?: 'v1'));
        if ($this->primaryKeyId === '') {
            $this->primaryKeyId = 'v1';
        }

        if ($ring !== '') {
            $this->loadKeyRing($ring);
        }

        if ($single !== '') {
            $this->keysById[$this->primaryKeyId] = $this->decodeKey($single, 'RCUBE_MAILBOX_KEY');
        }

        if (empty($this->keysById)) {
            throw new RuntimeException('Mailbox key not configured. Set RCUBE_MAILBOX_KEY (or RCUBE_MAILBOX_KEYS).');
        }

        if (!isset($this->keysById[$this->primaryKeyId])) {
            $this->primaryKeyId = (string) array_key_first($this->keysById);
        }
    }

    public function keyInfo(): array
    {
        return [
            'loaded' => !empty($this->keysById),
            'length' => strlen((string) ($this->keysById[$this->primaryKeyId] ?? '')),
            'primary_key_id' => $this->primaryKeyId,
            'key_count' => count($this->keysById),
            'sodium' => function_exists('sodium_crypto_secretbox'),
        ];
    }

    public function encrypt(string $plaintext): array
    {
        $key = $this->keysById[$this->primaryKeyId];
        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

            return [
                'enc_alg' => 'sodium_secretbox',
                'password_enc' => base64_encode($ciphertext),
                'enc_nonce' => base64_encode($nonce),
                'key_id' => $this->primaryKeyId,
            ];
        }

        if (!function_exists('openssl_encrypt')) {
            throw new RuntimeException('Neither libsodium nor OpenSSL is available.');
        }

        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

        if ($ciphertext === false) {
            throw new RuntimeException('OpenSSL encryption failed.');
        }

        return [
            'enc_alg' => 'aes-256-gcm',
            'password_enc' => base64_encode($ciphertext . $tag),
            'enc_nonce' => base64_encode($iv),
            'key_id' => $this->primaryKeyId,
        ];
    }

    public function decrypt(string $encAlg, string $passwordEncB64, string $nonceB64, ?string $keyId = null): string
    {
        $ciphertextRaw = base64_decode($passwordEncB64, true);
        $nonce = base64_decode($nonceB64, true);

        if ($ciphertextRaw === false || $nonce === false) {
            throw new RuntimeException('Malformed encrypted payload.');
        }

        $keysToTry = $this->keysForDecrypt($keyId);
        $lastError = null;
        foreach ($keysToTry as $key) {
            try {
                return $this->decryptWithKey($encAlg, $ciphertextRaw, $nonce, $key);
            } catch (RuntimeException $e) {
                $lastError = $e->getMessage();
            }
        }

        throw new RuntimeException($lastError ?: 'Unable to decrypt mailbox password.');
    }

    private function decryptWithKey(string $encAlg, string $ciphertextRaw, string $nonce, string $key): string
    {
        if ($encAlg === 'sodium_secretbox') {
            if (!function_exists('sodium_crypto_secretbox_open')) {
                throw new RuntimeException('libsodium is not available to decrypt sodium payload.');
            }

            $plaintext = sodium_crypto_secretbox_open($ciphertextRaw, $nonce, $key);
            if ($plaintext === false) {
                throw new RuntimeException('Unable to decrypt mailbox password.');
            }

            return $plaintext;
        }

        if ($encAlg === 'aes-256-gcm') {
            if (strlen($ciphertextRaw) < 16) {
                throw new RuntimeException('Malformed AES-GCM payload.');
            }

            $tag = substr($ciphertextRaw, -16);
            $ciphertext = substr($ciphertextRaw, 0, -16);

            $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $nonce, $tag, '');
            if ($plaintext === false) {
                throw new RuntimeException('Unable to decrypt mailbox password.');
            }

            return $plaintext;
        }

        throw new RuntimeException('Unsupported encryption algorithm: ' . $encAlg);
    }

    private function keysForDecrypt(?string $keyId): array
    {
        if ($keyId !== null && $keyId !== '' && isset($this->keysById[$keyId])) {
            return [$this->keysById[$keyId]];
        }

        // Fallback for older rows without key_id or if key id was renamed.
        return array_values($this->keysById);
    }

    private function loadKeyRing(string $ring): void
    {
        $pairs = preg_split('/\s*,\s*/', trim($ring), -1, PREG_SPLIT_NO_EMPTY);
        if (!is_array($pairs)) {
            return;
        }

        foreach ($pairs as $pair) {
            $parts = explode(':', $pair, 2);
            if (count($parts) !== 2) {
                continue;
            }
            $id = trim($parts[0]);
            $key = trim($parts[1]);
            if ($id === '' || $key === '') {
                continue;
            }
            $this->keysById[$id] = $this->decodeKey($key, 'RCUBE_MAILBOX_KEYS');
        }
    }

    private function decodeKey(string $base64Key, string $source): string
    {
        $decoded = base64_decode($base64Key, true);
        if ($decoded === false || strlen($decoded) !== self::KEY_LEN) {
            throw new RuntimeException($source . ' must contain base64-encoded 32-byte keys.');
        }

        return $decoded;
    }
}
