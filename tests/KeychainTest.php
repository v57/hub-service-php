<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\Keychain;
use PHPUnit\Framework\TestCase;

final class KeychainTest extends TestCase
{
    /** TS test key: auth = base64(48-byte PKCS8 private + 44-byte SPKI public). */
    private const TS_AUTH = 'MC4CAQAwBQYDK2VwBCIEINguo0cc0FACJ0oRV3V/+ZqIyj04ON5wdMJGH4a/do8CMCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ=';

    private const TS_PUB = 'MCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ=';

    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hub-service-php-keychain-' . bin2hex(random_bytes(4));
        mkdir($this->dir, 0700, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    public function testTokenShapeAndExpiry(): void
    {
        Keychain::setKeyPath($this->dir . '/auth');
        $token = Keychain::sign();
        $parts = explode('.', $token);

        self::assertCount(4, $parts);
        self::assertSame('key', $parts[0]);
        self::assertSame(Keychain::publicKey(), $parts[1]);
        self::assertNotSame('', $parts[2], 'signature must not be empty');
        self::assertMatchesRegularExpression('/^\d+$/', $parts[3], 'expiry must be a DECIMAL string (TS parity)');

        $expiry = (int) $parts[3];
        self::assertGreaterThanOrEqual(time() + 59, $expiry);
        self::assertLessThanOrEqual(time() + 61, $expiry);
    }

    public function testSignatureVerifiesAgainstPublicKey(): void
    {
        Keychain::setKeyPath($this->dir . '/auth');
        $token = Keychain::sign();
        [, $pubB64, $sigB64, $expiry] = explode('.', $token);

        $publicDer = base64_decode($pubB64, true);
        self::assertSame(44, strlen($publicDer), 'SPKI DER public key must be 44 bytes');
        // SPKI ed25519 layout: 12-byte header, then the 32-byte raw public key.
        $rawPub = substr($publicDer, 12, 32);

        $signature = base64_decode($sigB64, true);
        self::assertSame(64, strlen($signature), 'ed25519 signature must be 64 bytes');

        self::assertTrue(
            sodium_crypto_sign_verify_detached($signature, $expiry, $rawPub),
            'signature must verify against the embedded public key over the expiry string',
        );
    }

    public function testAuthFileRoundTrip(): void
    {
        $path = $this->dir . '/auth';
        Keychain::setKeyPath($path);
        $pub = Keychain::publicKey();

        // File written in TS layout: base64 of 92 bytes (48 private + 44 public).
        self::assertFileExists($path);
        $fileB64 = trim((string) file_get_contents($path));
        self::assertSame(124, strlen($fileB64), 'auth file must be 124 base64 chars');
        self::assertSame(92, strlen(base64_decode($fileB64, true)), 'auth file must decode to 92 bytes');

        // Reload forces a fresh parse of the file.
        Keychain::setKeyPath($path);
        self::assertSame($pub, Keychain::publicKey(), 'public key must survive a reload');
        $reloaded = explode('.', Keychain::sign());
        self::assertSame('key', $reloaded[0]);
        self::assertSame($pub, $reloaded[1], 'token public key must survive a reload');
        self::assertNotSame('', $reloaded[2]);
        self::assertMatchesRegularExpression('/^\d+$/', $reloaded[3]);
    }

    public function testLoadsTSGeneratedAuthFile(): void
    {
        $path = $this->dir . '/auth';
        file_put_contents($path, self::TS_AUTH . "\n");

        Keychain::setKeyPath($path);
        self::assertSame(self::TS_PUB, Keychain::publicKey());

        // The token signed with the loaded TS key must verify against its pub.
        $token = Keychain::sign();
        [, $pubB64, $sigB64, $expiry] = explode('.', $token);
        self::assertSame(self::TS_PUB, $pubB64);
        $rawPub = substr(base64_decode($pubB64, true), 12, 32);
        self::assertTrue(sodium_crypto_sign_verify_detached(base64_decode($sigB64, true), $expiry, $rawPub));
    }

    public function testCorruptAuthFileThrows(): void
    {
        $path = $this->dir . '/auth';
        file_put_contents($path, 'bm90LWEta2V5'); // "not-a-key"

        Keychain::setKeyPath($path);
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Invalid auth key file');
        Keychain::publicKey();
    }

    public function testFreshSignaturesPerSecond(): void
    {
        Keychain::setKeyPath($this->dir . '/auth');
        // sign(1) and sign(10) produce different expiry seconds → different tokens.
        self::assertNotSame(Keychain::sign(1), Keychain::sign(10));
        // A custom expiry must be honored: expiry == now + 0 (within a second).
        $parts = explode('.', Keychain::sign(0));
        self::assertGreaterThanOrEqual(time() - 1, (int) $parts[3]);
        self::assertLessThanOrEqual(time() + 1, (int) $parts[3]);
    }
}
