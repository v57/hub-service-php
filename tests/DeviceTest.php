<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\Device;
use HubServicePhp\Keychain;
use HubServicePhp\Service;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/** Device key file and service certificates (protocol.md §3). */
final class DeviceTest extends TestCase
{
    private string $dir;

    private string|false $saved;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hubdevice-php-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        $this->saved = getenv('HUB_DEVICE_KEY');
        putenv('HUB_DEVICE_KEY=' . $this->dir . '/hub/device.key');
        Keychain::setKeyPath($this->dir . '/auth');
    }

    protected function tearDown(): void
    {
        putenv($this->saved === false ? 'HUB_DEVICE_KEY' : 'HUB_DEVICE_KEY=' . $this->saved);
        Keychain::setKeyPath('auth');
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    /**
     * @return array<string, mixed>
     */
    private static function decode(string $header): array
    {
        return json_decode((string) base64_decode(strtr(explode('.', $header)[0], '-_', '+/')), true);
    }

    public function testKeyPathOverride(): void
    {
        self::assertSame($this->dir . '/hub/device.key', Device::defaultKeyPath());
    }

    public function testKeyFileCreatedPrivateAndReused(): void
    {
        $key = (new Device())->publicKey();
        $path = $this->dir . '/hub/device.key';
        clearstatcache();
        self::assertSame(0600, fileperms($path) & 0777);
        self::assertSame(0700, fileperms(dirname($path)) & 0777);
        self::assertSame(92, strlen((string) base64_decode((string) file_get_contents($path))));
        self::assertSame($key, (new Device())->publicKey());
        self::assertSame(['device.key'], array_values(array_diff(scandir(dirname($path)), ['.', '..'])));
    }

    public function testCertificateSignedByDeviceOverPayload(): void
    {
        $device = new Device(name: 'Mac Studio', platform: 'macos');
        $header = $device->certificate('SERVICE', 's3-local/Backup Disk', 1792500000);
        [$payload, $signature] = explode('.', $header);
        self::assertTrue(sodium_crypto_sign_verify_detached(
            base64_decode($signature),
            $payload,
            substr(base64_decode($device->publicKey()), 12),
        ));
        $body = self::decode($header);
        self::assertSame(['v', 'device', 'service', 'instance', 'deviceName', 'platform', 'iat', 'exp'], array_keys($body));
        self::assertSame(Device::CERTIFICATE_LIFETIME, $body['exp'] - $body['iat']);
    }

    public function testCertificateRenewedWithLessThanADayLeft(): void
    {
        $device = new Device();
        $first = $device->certificate('SERVICE', 'echo', 1000);
        self::assertSame($first, $device->certificate('SERVICE', 'echo', 1000 + 5 * 86400));
        $renewed = $device->certificate('SERVICE', 'echo', 1000 + 6 * 86400 + 1);
        self::assertNotSame($first, $renewed);
        self::assertSame(1000 + 6 * 86400 + 1 + Device::CERTIFICATE_LIFETIME, Device::certificateExpiry($renewed));
    }

    public function testServiceSendsDeviceHeaderForItsKey(): void
    {
        $service = new Service(['address' => 1, 'instance' => 'echo/main']);
        $headers = $service->authHeaders();
        $body = self::decode($headers['device']);
        self::assertSame(Keychain::publicKey(), $body['service']);
        self::assertSame(explode('.', $headers['auth'])[1], $body['service']);
        self::assertSame('echo/main', $body['instance']);
        self::assertSame($service->device?->publicKey(), $body['device']);
    }

    public function testInstanceDefaults(): void
    {
        self::assertSame('Echo', (new Service(['name' => 'Echo']))->instance());
        $service = new Service();
        self::assertSame('service', $service->instance());
        $service->post('s3/read', static fn (mixed $body): mixed => $body)->post('echo', static fn (mixed $body): mixed => $body);
        self::assertSame('s3', $service->instance());
    }

    public function testInstanceLengthChecked(): void
    {
        $this->expectException(RuntimeException::class);
        (new Device())->certificate('SERVICE', str_repeat('x', 129));
    }

    public function testDeviceModeOffSendsNoHeader(): void
    {
        self::assertArrayNotHasKey('device', (new Service(['address' => 1, 'device' => false]))->authHeaders());
        self::assertDirectoryDoesNotExist($this->dir . '/hub');
    }

    public function testUnreadableDeviceKeyFallsBackToPlainKey(): void
    {
        file_put_contents($this->dir . '/blocked', 'not a directory');
        putenv('HUB_DEVICE_KEY=' . $this->dir . '/blocked/device.key');
        $headers = (new Service(['address' => 1]))->authHeaders();
        self::assertArrayNotHasKey('device', $headers);
        self::assertStringStartsWith('key.', $headers['auth']);
    }
}
