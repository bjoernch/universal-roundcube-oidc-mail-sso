<?php

declare(strict_types=1);

namespace UniversalOidcMailSso\Lib;

use RuntimeException;

class Crypto
{
    private const KEY_LEN = 32;

    private string $key;

    public function __construct(?string $base64Key = null)
    {
        $base64Key = $base64Key ?: getenv('RCUBE_MAILBOX_KEY') ?: '';
        $decoded = base64_decode($base64Key, true);

        if ($decoded === false || strlen($decoded) !== self::KEY_LEN) {
            throw new RuntimeException('RCUBE_MAILBOX_KEY must be base64-encoded 32 bytes.');
        }

        $this->key = $decoded;
    }

    public function keyInfo(): array
    {
        return [
            'loaded' => !empty($this->key),
            'length' => strlen($this->key),
            'sodium' => function_exists('sodium_crypto_secretbox'),
        ];
    }

    public function encrypt(string $plaintext): array
    {
        if (function_exists('sodium_crypto_secretbox')) {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $this->key);

            return [
                'enc_alg' => 'sodium_secretbox',
                'password_enc' => base64_encode($ciphertext),
                'enc_nonce' => base64_encode($nonce),
            ];
        }

        if (!function_exists('openssl_encrypt')) {
            throw new RuntimeException('Neither libsodium nor OpenSSL is available.');
        }

        $iv = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

        if ($ciphertext === false) {
            throw new RuntimeException('OpenSSL encryption failed.');
        }

        return [
            'enc_alg' => 'aes-256-gcm',
            'password_enc' => base64_encode($ciphertext . $tag),
            'enc_nonce' => base64_encode($iv),
        ];
    }

    public function decrypt(string $encAlg, string $passwordEncB64, string $nonceB64): string
    {
        $ciphertextRaw = base64_decode($passwordEncB64, true);
        $nonce = base64_decode($nonceB64, true);

        if ($ciphertextRaw === false || $nonce === false) {
            throw new RuntimeException('Malformed encrypted payload.');
        }

        if ($encAlg === 'sodium_secretbox') {
            if (!function_exists('sodium_crypto_secretbox_open')) {
                throw new RuntimeException('libsodium is not available to decrypt sodium payload.');
            }

            $plaintext = sodium_crypto_secretbox_open($ciphertextRaw, $nonce, $this->key);
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

            $plaintext = openssl_decrypt($ciphertext, 'aes-256-gcm', $this->key, OPENSSL_RAW_DATA, $nonce, $tag, '');
            if ($plaintext === false) {
                throw new RuntimeException('Unable to decrypt mailbox password.');
            }

            return $plaintext;
        }

        throw new RuntimeException('Unsupported encryption algorithm: ' . $encAlg);
    }
}
