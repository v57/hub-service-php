<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\HubPins;
use HubServicePhp\Keychain;
use HubServicePhp\Service;
use HubServicePhp\Tests\Support\CoroutineTestCase;
use HubServicePhp\Tests\Support\FakeHub;

/** v1 hub-bound auth: hub/info pinning against a fake hub (protocol.md §2). */
final class AuthTest extends CoroutineTestCase
{
    private const HUB_KEY = FakeHub::HUB_KEY;

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hubauth-php-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        Keychain::setKeyPath($this->dir . '/auth');
    }

    protected function tearDown(): void
    {
        Keychain::setKeyPath('auth');
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private static function verify(string $token, string $signed): void
    {
        [, $pub, $sig] = explode('.', $token);
        self::assertTrue(sodium_crypto_sign_verify_detached(
            base64_decode($sig),
            $signed,
            substr(base64_decode($pub), 12),
        ));
    }

    public function testV0AndV1Tokens(): void
    {
        $token = Keychain::sign();
        self::verify($token, explode('.', $token)[3]);
        $token = Keychain::sign(hubKey: self::HUB_KEY);
        self::verify($token, 'hub1:' . self::HUB_KEY . ':' . explode('.', $token)[3]);
    }

    public function testPinsRoundTrip(): void
    {
        $pins = new HubPins($this->dir . '/hubs.json');
        self::assertNull($pins->get('ws://localhost:1997'));
        $pins->set('ws://localhost:1997', self::HUB_KEY);
        self::assertSame(['ws://localhost:1997' => self::HUB_KEY], json_decode((string) file_get_contents($this->dir . '/hubs.json'), true));
        $pins->forget('ws://localhost:1997');
        self::assertNull($pins->get('ws://localhost:1997'));
    }

    public function testPinAddressNormalization(): void
    {
        self::assertSame('ws://localhost:1997', Keychain::pinAddress(1997));
        self::assertSame('ws://localhost:1997', Keychain::pinAddress('1997'));
        self::assertSame('ws://hub.example.com:2000', Keychain::pinAddress('WS://Hub.Example.COM:2000/'));
        self::assertSame('wss://hub.example.com/Path', Keychain::pinAddress('wss://hub.example.com/Path/'));
    }

    public function testSuppliedHubKeyConnectsV1(): void
    {
        $headers = (new Service(['address' => 1, 'hubKey' => self::HUB_KEY]))->authHeaders();
        self::assertSame('1', $headers['v']);
        self::verify($headers['auth'], 'hub1:' . self::HUB_KEY . ':' . explode('.', $headers['auth'])[3]);
    }

    public function testOneParameterSignStaysV0(): void
    {
        $service = new Service([
            'address' => 1,
            'hubKey' => self::HUB_KEY,
            'sign' => static fn (int $expires): string => Keychain::sign($expires),
        ]);
        self::assertSame('0', $service->authHeaders()['v']);
    }

    public function testLearnsAndPinsHubKeyThenReconnectsV1(): void
    {
        $hub = new FakeHub();
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->server->port]))->start();
                try {
                    $hub->waitFor(static fn (FakeHub $h): int => count($h->connects()), 2);
                    $connects = $hub->connects();
                    self::assertSame(['0', '1'], [$connects[0]['v'], $connects[1]['v']]);
                    self::verify($connects[1]['auth'], 'hub1:' . self::HUB_KEY . ':' . explode('.', $connects[1]['auth'])[3]);
                    self::assertSame(self::HUB_KEY, (new HubPins($this->dir . '/hubs.json'))->get($service->target()));
                    $service->forgetHubKey();
                    self::assertNull($service->hubKey());
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    public function testHubLiteKeepsV0(): void
    {
        $hub = new FakeHub(lite: true);
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->server->port]))->start();
                try {
                    $hub->waitFor(static fn (FakeHub $h): int => count($h->connects()), 1);
                    \OpenSwoole\Coroutine::usleep(300_000);
                    self::assertSame(['0'], array_column($hub->connects(), 'v'));
                    self::assertFileDoesNotExist($this->dir . '/hubs.json');
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }
}
