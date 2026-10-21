<?php

declare(strict_types=1);

namespace HubServicePhp;

use RuntimeException;

/**
 * ed25519 keychain: load-or-generate the ``auth`` key file and sign tokens.
 *
 * hub-server auth parity with the TS reference (hub-service/keychain.ts):
 *
 * - The key file (``auth`` in the working directory, matching the TS keychain)
 *   is the base64 encoding of the 48-byte PKCS8 DER private key followed by
 *   the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars).
 * - A signed token has the shape ``key.<pub>.<sig>.<expiry>`` where:
 *     pub     = base64 of the 44-byte SPKI public key (bytes 48..92 of the file)
 *     sig     = base64 ed25519 signature over the signed data
 *     expiry  = DECIMAL epoch-seconds string of now + 60 (protocol default;
 *               hub-server rejects it once expired or over 5 minutes ahead)
 * - The signed data depends on the ``v`` header (Docs/Devices/protocol.md):
 *     v: 0    the expiry string alone
 *     v: 1    ``hub1:<hub key>:<expiry>``, so the token only works on the hub
 *             whose key it names
 * - The hub verifies the signature against the embedded public key and treats
 *   the key as the connection identity (owner/host/group permissions).
 * - Hub keys learned from ``hub/info`` are pinned in ``hubs.json`` beside the
 *   key file: ``{"<address>": "<hub SPKI>"}`` (see HubPins).
 *
 * Keys are generated with the OpenSSL extension (openssl_pkey_new
 * OPENSSL_KEYTYPE_ED25519) and signatures are produced with the bundled
 * libsodium extension (sodium_crypto_sign_detached), which is the standard
 * ed25519 signer in PHP — openssl_sign() does not support ed25519 keys on
 * modern PHP/OpenSSL builds. Both extensions ship with PHP by default.
 *
 * Usage::
 *
 *     $token = Keychain::sign();                  // v0 token for a connect
 *     $token = Keychain::sign(hubKey: $hubKey);   // v1 token bound to one hub
 *     $pub = Keychain::publicKey();               // the service's public key (identity)
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

    /** RFC 8410 DER headers: PKCS8 before the 32-byte seed, SPKI before the 32-byte public key. */
    private const PKCS8_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

    private const SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

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
     * The service key file in use.
     */
    public static function keyPath(): string
    {
        return self::$keyPath ?? 'auth';
    }

    /**
     * A fresh auth token: ``key.<pub>.<sig>.<expiry>``. With ``$hubKey`` (the
     * pinned hub key) it signs ``hub1:<hub key>:<expiry>`` for ``v: 1``;
     * without it the token is v0 (the expiry alone).
     */
    public static function sign(int $expires = 60, ?string $hubKey = null): string
    {
        $key = self::loadOrGenerate();

        return self::tokenWith($key['seed'], $key['publicB64'], time() + $expires, $hubKey);
    }

    /**
     * The base64 signature of ``$data`` with the service key (agent challenges
     * for Hub Network shares).
     */
    public static function signChallenge(string $data): string
    {
        $key = self::loadOrGenerate();

        return base64_encode(sodium_crypto_sign_detached($data, self::secretKey($key['seed'])));
    }

    /**
     * An auth token for an exact expiry from key file bytes (92 bytes).
     */
    public static function token(string $keyFile, int $expiry, ?string $hubKey = null): string
    {
        return self::tokenWith(self::seed($keyFile), self::spki($keyFile), $expiry, $hubKey);
    }

    /**
     * The base64 Ed25519 signature of ``$data`` with key file bytes.
     */
    public static function signData(string $keyFile, string $data): string
    {
        return base64_encode(sodium_crypto_sign_detached($data, self::secretKey(self::seed($keyFile))));
    }

    /**
     * The public half of key file bytes: base64 of the 44-byte SPKI DER.
     */
    public static function spki(string $keyFile): string
    {
        return base64_encode(substr($keyFile, self::PRIVATE_DER_LENGTH, self::PUBLIC_DER_LENGTH));
    }

    /**
     * Key file bytes from its base64 text.
     */
    public static function decodeKeyFile(string $text, string $path = 'key file'): string
    {
        $decoded = base64_decode(trim($text), true);
        if ($decoded === false || strlen($decoded) !== self::PRIVATE_DER_LENGTH + self::PUBLIC_DER_LENGTH) {
            throw new RuntimeException("Invalid auth key file: $path (expected 92 decoded bytes)");
        }

        return $decoded;
    }

    /**
     * Key file bytes for a 32-byte seed (TS layout).
     */
    public static function keyFileBytes(string $seed): string
    {
        $public = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));

        return self::PKCS8_PREFIX . $seed . self::SPKI_PREFIX . $public;
    }

    /**
     * Loads key file bytes, creating the file if missing. ``$private`` creates
     * it atomically with mode 0600 inside a 0700 directory (device keys).
     */
    public static function loadKeyFile(string $path, bool $private = false): string
    {
        if (is_file($path)) {
            return self::decodeKeyFile((string) file_get_contents($path), $path);
        }

        $bytes = self::keyFileBytes(random_bytes(self::SEED_LENGTH));
        if (!$private) {
            if (file_put_contents($path, base64_encode($bytes)) === false) {
                throw new RuntimeException("Cannot write key file: $path");
            }

            return $bytes;
        }

        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException("Cannot create key directory: $dir");
        }
        $temp = $dir . '/.device.' . bin2hex(random_bytes(6));
        $old = umask(0077);
        $file = @fopen($temp, 'x');
        umask($old);
        if ($file === false) {
            throw new RuntimeException("Cannot write key file: $path");
        }
        try {
            fwrite($file, base64_encode($bytes));
            fclose($file);
            // link, not rename: a key another process created first wins.
            if (!@link($temp, $path)) {
                if (is_file($path)) {
                    return self::decodeKeyFile((string) file_get_contents($path), $path);
                }
                throw new RuntimeException("Cannot write key file: $path");
            }
        } finally {
            @unlink($temp);
        }

        return $bytes;
    }

    /**
     * The hubs.json key for a hub address: a bare port is
     * ``ws://localhost:<port>``; a URL keeps its form with the scheme and host
     * lowercased and no trailing slash (channel TS normalization).
     */
    public static function pinAddress(int|string $address): string
    {
        if (is_int($address) || ctype_digit($address)) {
            return 'ws://localhost:' . $address;
        }
        $url = $address;
        if (preg_match('#^([A-Za-z][A-Za-z0-9+.-]*)://([^/?\#]*)(.*)$#s', $url, $m) === 1) {
            $authority = $m[2];
            $at = strrpos($authority, '@');
            $authority = $at === false
                ? strtolower($authority)
                : substr($authority, 0, $at + 1) . strtolower(substr($authority, $at + 1));
            $url = strtolower($m[1]) . '://' . $authority . $m[3];
        }

        return rtrim($url, '/');
    }

    private static function tokenWith(string $seed, string $publicB64, int $expiry, ?string $hubKey): string
    {
        $data = $hubKey !== null && $hubKey !== '' ? "hub1:$hubKey:$expiry" : (string) $expiry;
        $signature = sodium_crypto_sign_detached($data, self::secretKey($seed));

        return sprintf('key.%s.%s.%s', $publicB64, base64_encode($signature), $expiry);
    }

    private static function seed(string $keyFile): string
    {
        return substr($keyFile, self::SEED_OFFSET, self::SEED_LENGTH);
    }

    /**
     * @return array{seed: string, publicB64: string}
     */
    private static function loadOrGenerate(): array
    {
        if (self::$seed !== null && self::$publicB64 !== null) {
            return ['seed' => self::$seed, 'publicB64' => self::$publicB64];
        }

        $path = self::keyPath();
        if (is_file($path)) {
            $decoded = self::decodeKeyFile((string) file_get_contents($path), $path);
            self::$seed = self::seed($decoded);
            self::$publicB64 = self::spki($decoded);
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
