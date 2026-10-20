<?php

declare(strict_types=1);

namespace HubServicePhp;

use RuntimeException;

/**
 * ed25519 keychain: load-or-generate the ``auth`` key file and sign tokens.
 *
 * Hub-pro auth parity with the TS reference (hub-service/keychain.ts):
 *
 * - The key file (``auth`` in the working directory, matching the TS keychain)
 *   is the base64 encoding of the 48-byte PKCS8 DER private key followed by
 *   the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars).
 * - A signed token has the shape ``key.<pub>.<sig>.<expiry>`` where:
 *     pub     = base64 of the 44-byte SPKI public key (bytes 48..92 of the file)
 *     sig     = base64 ed25519 signature over the expiry string
 *     expiry  = DECIMAL epoch-seconds string of now + 10 (TS parity; hub-pro
 *               rejects it once expired or if over 5 minutes ahead)
 * - The hub verifies the signature against the embedded public key and treats
 *   the key as the connection identity (owner/host/group permissions).
 *
 * Keys are generated with the OpenSSL extension (openssl_pkey_new
 * OPENSSL_KEYTYPE_ED25519) and signatures are produced with the bundled
 * libsodium extension (sodium_crypto_sign_detached), which is the standard
 * ed25519 signer in PHP — openssl_sign() does not support ed25519 keys on
 * modern PHP/OpenSSL builds. Both extensions ship with PHP by default.
 *
 * Usage::
 *
 *     $token = Keychain::sign();        // fresh token for a connect
 *     $pub = Keychain::publicKey();     // the service's public key (identity)
 */
final class Keychain
{
    /** TS keychain layout: PKCS8 DER private key (48 bytes for ed25519) followed by SPKI DER public key (44 bytes). */
    private const PRIVATE_DER_LENGTH = 48;

    private const PUBLIC_DER_LENGTH = 44;

    /** PKCS8 ed25519 DER: 16-byte header then the 32-byte raw seed. */
    private const SEED_OFFSET = 16;

    private const SEED_LENGTH = 32;

    /** SPKI ed25519 DER: 12-byte header then the 32-byte raw public key. */
    private const PUBLIC_RAW_OFFSET = 12;

    private static ?string $keyPath = null;

    private static ?string $seed = null;

    private static ?string $publicB64 = null;

    /**
     * Override the key file location (default: ``auth`` in the cwd).
     */
    public static function setKeyPath(string $path): void
    {
        self::$keyPath = $path;
        self::$seed = null;
        self::$publicB64 = null;
    }

    /**
     * The service's public key (base64 of the 44-byte SPKI DER).
     */
    public static function publicKey(): string
    {
        return self::loadOrGenerate()['publicB64'];
    }

    /**
     * A fresh auth token: ``key.<pub>.<sig>.<expiry>``.
     */
    public static function sign(int $expires = 10): string
    {
        $key = self::loadOrGenerate();
        $data = (string) (time() + $expires);
        $signature = sodium_crypto_sign_detached($data, self::secretKey($key['seed']));

        return sprintf('key.%s.%s.%s', $key['publicB64'], base64_encode($signature), $data);
    }

    /**
     * @return array{seed: string, publicB64: string}
     */
    private static function loadOrGenerate(): array
    {
        if (self::$seed !== null && self::$publicB64 !== null) {
            return ['seed' => self::$seed, 'publicB64' => self::$publicB64];
        }

        $path = self::$keyPath ?? 'auth';
        if (is_file($path)) {
            $decoded = base64_decode(trim((string) file_get_contents($path)), true);
            if ($decoded === false || strlen($decoded) !== self::PRIVATE_DER_LENGTH + self::PUBLIC_DER_LENGTH) {
                throw new RuntimeException("Invalid auth key file: $path (expected 92 decoded bytes)");
            }
            self::$seed = substr($decoded, self::SEED_OFFSET, self::SEED_LENGTH);
            self::$publicB64 = base64_encode(substr($decoded, self::PRIVATE_DER_LENGTH, self::PUBLIC_DER_LENGTH));
        } else {
            $generated = self::generate();
            $encoded = base64_encode($generated['privateDer'] . $generated['publicDer']);
            if (file_put_contents($path, $encoded . "\n") === false) {
                throw new RuntimeException("Cannot write auth key file: $path");
            }
            self::$seed = $generated['seed'];
            self::$publicB64 = base64_encode($generated['publicDer']);
        }

        return ['seed' => self::$seed, 'publicB64' => self::$publicB64];
    }

    /**
     * Generate an ed25519 keypair and return its TS-layout DER components.
     *
     * @return array{privateDer: string, publicDer: string, seed: string}
     */
    private static function generate(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
        if ($key === false) {
            throw new RuntimeException('openssl_pkey_new failed to generate an ed25519 key');
        }
        if (!openssl_pkey_export($key, $privatePem)) {
            throw new RuntimeException('openssl_pkey_export failed');
        }
        $details = openssl_pkey_get_details($key);
        if ($details === false || !isset($details['key'])) {
            throw new RuntimeException('openssl_pkey_get_details failed');
        }

        $privateDer = self::pemToDer($privatePem, 'PRIVATE KEY');
        $publicDer = self::pemToDer($details['key'], 'PUBLIC KEY');
        if (strlen($privateDer) !== self::PRIVATE_DER_LENGTH || strlen($publicDer) !== self::PUBLIC_DER_LENGTH) {
            throw new RuntimeException('Unexpected ed25519 DER lengths from OpenSSL');
        }

        return [
            'privateDer' => $privateDer,
            'publicDer' => $publicDer,
            'seed' => substr($privateDer, self::SEED_OFFSET, self::SEED_LENGTH),
        ];
    }

    /**
     * The 64-byte libsodium secret key (seed + public) for a 32-byte seed.
     */
    private static function secretKey(string $seed): string
    {
        return substr(sodium_crypto_sign_seed_keypair($seed), 0, 64);
    }

    private static function pemToDer(string $pem, string $label): string
    {
        $body = preg_replace('/-----BEGIN ' . $label . '-----/', '', $pem);
        $body = (string) preg_replace('/-----END ' . $label . '-----/', '', (string) $body);
        $body = preg_replace('/\s+/', '', (string) $body);
        $der = base64_decode((string) $body, true);
        if ($der === false) {
            throw new RuntimeException("Cannot decode $label PEM");
        }

        return $der;
    }
}
