<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\HubPins;
use HubServicePhp\HubProof;
use HubServicePhp\Keychain;
use HubServicePhp\Service;
use HubServicePhp\Tests\Support\CoroutineTestCase;
use HubServicePhp\Tests\Support\FakeHub;
use OpenSwoole\Coroutine;

/** Auth v2: the hub's proof, its pin and one token per connect (protocol.md §2). */
final class AuthTest extends CoroutineTestCase
{
    private const HUB_KEY = FakeHub::HUB_KEY;

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hubauth-php-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        Keychain::setKeyPath($this->dir . '/auth');
        putenv('HUB_ALLOW_PLAINTEXT');
    }

    protected function tearDown(): void
    {
        Keychain::setKeyPath('auth');
        putenv('HUB_ALLOW_PLAINTEXT');
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return json_decode((string) file_get_contents(__DIR__ . '/../../../Docs/Devices/vectors.json'), true);
    }

    private static function verify(string $token): void
    {
        [, $pub, $sig, $expiry, $nonce] = explode('.', $token);
        self::assertTrue(sodium_crypto_sign_verify_detached(
            base64_decode($sig),
            'hub1:' . self::HUB_KEY . ":$nonce:$expiry",
            substr(base64_decode($pub), 12),
        ));
    }

    public function testTokenMatchesVector(): void
    {
        $vectors = self::vectors();
        $auth = $vectors['auth'];
        $service = Keychain::decodeKeyFile($vectors['keys']['service']['keyFile']);
        self::assertSame($auth['v1']['header'], Keychain::token($service, $auth['expiry'], self::HUB_KEY, $auth['nonce']));
    }

    public function testProofMatchesVector(): void
    {
        $vectors = self::vectors();
        $info = $vectors['hubInfo'];
        self::assertSame($info['signedData'], HubProof::signedData(self::HUB_KEY, $info['nonce']));
        $answer = ['key' => self::HUB_KEY, 'proof' => $info['proof'], 'challenge' => 'c'];
        self::assertTrue(HubProof::verify($answer, $info['nonce']));
        self::assertFalse(HubProof::verify($answer, 'another-nonce-another-nonce'));
        self::assertFalse(HubProof::verify(['key' => $vectors['keys']['service']['publicKey']] + $answer, $info['nonce']));
        self::assertFalse(HubProof::verify(['key' => self::HUB_KEY, 'challenge' => 'c'], $info['nonce']));
        self::assertFalse(HubProof::verify(['key' => self::HUB_KEY, 'proof' => $info['proof']], $info['nonce']));
        self::assertFalse(HubProof::verify('no answer', $info['nonce']));
    }

    public function testTransportMatchesVector(): void
    {
        foreach (self::vectors()['transport'] as $vector) {
            self::assertSame($vector['transport'], HubProof::hubTransportOf($vector['url']), $vector['url']);
        }
        self::assertSame('loopback', HubProof::hubTransportOf(1997));
        self::assertSame('loopback', HubProof::hubTransportOf('1997'));
    }

    public function testClientNonceIs32BytesOfBase64Url(): void
    {
        $nonce = HubProof::makeClientNonce();
        self::assertSame(43, strlen($nonce));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $nonce);
        self::assertNotSame($nonce, HubProof::makeClientNonce());
    }

    public function testTokenLastsThirtySecondsOverTheChallenge(): void
    {
        $token = Keychain::sign(self::HUB_KEY, 'challenge');
        self::verify($token);
        $parts = explode('.', $token);
        self::assertSame('challenge', $parts[4]);
        self::assertGreaterThanOrEqual(25, (int) $parts[3] - time());
        self::assertLessThanOrEqual(31, (int) $parts[3] - time());
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

    public function testSendsATokenOnlyAfterProofAndPinsTheKey(): void
    {
        $hub = new FakeHub();
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->port]))->start();
                try {
                    // A call made right away waits for the authenticated connection.
                    self::assertSame('hi', $service->send('test/echo', 'hi'));
                    $connects = $hub->connects();
                    self::assertArrayNotHasKey('auth', $connects[0]);
                    self::assertArrayNotHasKey('device', $connects[0]);
                    $connect = $connects[count($connects) - 1];
                    self::assertSame('1', $connect['v']);
                    self::assertArrayHasKey('device', $connect);
                    self::verify($connect['auth']);
                    self::assertSame(self::HUB_KEY, (new HubPins($this->dir . '/hubs.json'))->get($service->target()));
                    self::assertNull($service->lastError());
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

    public function testEachConnectHasItsOwnChallenge(): void
    {
        $hub = new FakeHub();
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->port]))->start();
                $updates = static fn (FakeHub $h): int => count(array_filter($h->entries(), static fn (array $e): bool => ($e['path'] ?? '') === 'hub/service/update'));
                try {
                    $hub->waitFor($updates, 1);
                    // The reconnect asks again.
                    $client = (new \ReflectionProperty($service, 'sender'))->getValue($service)->ws;
                    (new \ReflectionProperty($client, 'ws'))->getValue($client)->close();
                    $hub->waitFor($updates, 2);
                    $nonces = $hub->nonces();
                    self::assertCount(2, $nonces);
                    self::assertNotSame($nonces[0], $nonces[1]);
                    $tokens = array_column($hub->credentials(), 'auth');
                    self::assertCount(2, $tokens);
                    self::assertNotSame(explode('.', $tokens[0])[4], explode('.', $tokens[1])[4]);
                    array_walk($tokens, static fn (string $token) => self::verify($token));
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    /** @return array<string, array{string}> */
    public static function answersWithoutProof(): array
    {
        return ['no proof' => ['no-proof'], "another key's proof" => ['another-signs']];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('answersWithoutProof')]
    public function testHubWithoutAProofGetsNothingAndIsNotPinned(string $answer): void
    {
        $hub = new FakeHub($answer);
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->port]))->start();
                try {
                    Coroutine::usleep(1_500_000);
                    self::assertGreaterThanOrEqual(2, count($hub->connects()), 'it keeps asking');
                    self::assertSame([], $hub->credentials());
                    self::assertNull($service->hubKey());
                    self::assertFileDoesNotExist($this->dir . '/hubs.json');
                    self::assertStringContainsString("didn't prove", (string) $service->lastError());
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    public function testHubWithAnotherKeyThanThePinGetsNothing(): void
    {
        // Proves its own key, but this address is pinned to the real hub's.
        $hub = new FakeHub('another-key');
        try {
            $this->co(function () use ($hub): void {
                $service = new Service(['address' => $hub->port]);
                $service->pins()->set($service->target(), self::HUB_KEY);
                $service->start();
                try {
                    Coroutine::usleep(1_200_000);
                    self::assertSame([], $hub->credentials());
                    self::assertSame(self::HUB_KEY, $service->pins()->get($service->target()));
                    self::assertStringContainsString('not the pinned', (string) $service->lastError());
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    public function testSuppliedHubKeyIsAPin(): void
    {
        $hub = new FakeHub('another-key');
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->port, 'hubKey' => self::HUB_KEY]))->start();
                try {
                    Coroutine::usleep(500_000);
                    self::assertSame([], $hub->credentials());
                    self::assertSame(self::HUB_KEY, $service->hubKey());
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    public function testStopEndsTheWaitForAProof(): void
    {
        $hub = new FakeHub('no-proof');
        try {
            $started = microtime(true);
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->port, 'device' => false]))->start();
                Coroutine::usleep(300_000);
                $service->stop();
            });
            // The coroutine scheduler only returns once the wait has ended.
            self::assertLessThan(3.0, microtime(true) - $started);
        } finally {
            $hub->stop();
        }
    }

    public function testCustomSignGetsTheProvenKeyAndChallengeAfterTheProof(): void
    {
        $calls = [];
        $sign = static function (string $hubKey, string $challenge) use (&$calls): string {
            $calls[] = [$hubKey, $challenge];
            return Keychain::sign($hubKey, $challenge);
        };
        $hub = new FakeHub('no-proof');
        try {
            $this->co(function () use ($hub, $sign, &$calls): void {
                $service = (new Service(['address' => $hub->port, 'device' => false, 'sign' => $sign]))->start();
                Coroutine::usleep(400_000);
                self::assertSame([], $calls);
                $service->stop();
            });
        } finally {
            $hub->stop();
        }
        $hub = new FakeHub();
        try {
            $this->co(function () use ($hub, $sign, &$calls): void {
                $service = (new Service(['address' => $hub->port, 'device' => false, 'sign' => $sign]))->start();
                try {
                    $hub->waitFor(static fn (FakeHub $h): int => count($h->credentials()), 1);
                    self::assertCount(1, $calls);
                    self::assertSame(self::HUB_KEY, $calls[0][0]);
                    self::assertSame(explode('.', $hub->credentials()[0]['auth'])[4], $calls[0][1]);
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    public function testPublicPlaintextIsNotDialed(): void
    {
        $service = (new Service(['address' => 'ws://hub.example.com:1997']))->start();
        self::assertNull((new \ReflectionProperty($service, 'sender'))->getValue($service));
        self::assertStringContainsString('unencrypted', (string) $service->lastError());
        $this->expectExceptionMessage('unencrypted');
        $service->send('x');
    }

    public function testSchemesThisClientCantEncryptAreNotDialed(): void
    {
        foreach (['https://hub.example.com', 'quic://hub.example.com:1997'] as $address) {
            $service = (new Service(['address' => $address, 'allowPlaintext' => true]))->start();
            self::assertNull((new \ReflectionProperty($service, 'sender'))->getValue($service));
            self::assertStringContainsString('unencrypted', (string) $service->lastError());
        }
    }

    public function testAllowPlaintextOptsOut(): void
    {
        $this->co(function (): void {
            $service = (new Service(['address' => 'ws://hub.invalid-name:1', 'allowPlaintext' => true]))->start();
            self::assertNotNull((new \ReflectionProperty($service, 'sender'))->getValue($service));
            $service->stop();
            putenv('HUB_ALLOW_PLAINTEXT=1');
            $service = (new Service(['address' => 'ws://hub:1']))->start();
            self::assertNotNull((new \ReflectionProperty($service, 'sender'))->getValue($service));
            $service->stop();
        });
    }
}
