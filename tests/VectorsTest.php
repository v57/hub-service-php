<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\Device;
use HubServicePhp\Keychain;
use PHPUnit\Framework\TestCase;

/** Docs/Devices/vectors.json: every string must match exactly. */
final class VectorsTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/../../../Docs/Devices/vectors.json'), true);
    }

    private static function key(string $name): string
    {
        return Keychain::decodeKeyFile(self::vectors()['keys'][$name]['keyFile']);
    }

    public function testKeyFilesAndPublicKeys(): void
    {
        foreach (['hub', 'service', 'device'] as $name) {
            $key = self::vectors()['keys'][$name];
            self::assertSame($key['publicKey'], Keychain::spki(self::key($name)));
            self::assertSame($key['keyFile'], base64_encode(Keychain::keyFileBytes((string) hex2bin($key['seed']))));
        }
    }

    public function testDeviceIdAndSafetyCode(): void
    {
        $device = self::vectors()['keys']['device'];
        self::assertSame($device['deviceId'], Device::deviceId($device['publicKey']));
        self::assertSame($device['safetyCode'], Device::safetyCode($device['publicKey']));
    }

    public function testAuthTokens(): void
    {
        $vectors = self::vectors();
        $auth = $vectors['auth'];
        self::assertSame($auth['v0']['header'], Keychain::token(self::key('service'), $auth['expiry']));
        self::assertSame($auth['v1']['header'], Keychain::token(self::key('service'), $auth['expiry'], $vectors['keys']['hub']['publicKey']));
    }

    public function testCertificates(): void
    {
        $vectors = self::vectors();
        $service = $vectors['keys']['service']['publicKey'];
        $header = Device::issue(self::key('device'), $service, 's3-local/Backup Disk', 1792500000, 1793104800, 'Mac Studio', 'macos');
        self::assertSame($vectors['certificate']['header'], $header);
        self::assertSame($vectors['certificate']['payload'], explode('.', $header)[0]);
        self::assertSame(
            $vectors['childCertificate']['header'],
            Device::issue(self::key('device'), $service, 'builder', 1792500000, 1793104800, 'builder', 'linux', 'Mac Studio'),
        );
    }

    public function testDeviceIssuesTheVectorCertificate(): void
    {
        $vectors = self::vectors();
        $device = new Device(key: self::key('device'), name: 'Mac Studio', platform: 'macos');
        self::assertSame($vectors['keys']['device']['deviceId'], $device->id());
        self::assertSame(
            $vectors['certificate']['header'],
            $device->certificate($vectors['keys']['service']['publicKey'], 's3-local/Backup Disk', 1792500000),
        );
    }
}
