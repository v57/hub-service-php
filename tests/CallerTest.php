<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\Caller;
use HubServicePhp\CallerDevice;
use HubServicePhp\Keychain;
use HubServicePhp\Request;
use HubServicePhp\Service;
use HubServicePhp\Tests\Support\CoroutineTestCase;
use HubServicePhp\Tests\Support\FakeHub;

/** Caller identity from context.hub.caller (protocol.md §4). */
final class CallerTest extends CoroutineTestCase
{
    /** @return array<string, mixed> */
    private static function context(): array
    {
        $vectors = json_decode((string) file_get_contents(__DIR__ . '/../../../Docs/Devices/vectors.json'), true);

        return $vectors['caller']['context'];
    }

    public function testParseCaller(): void
    {
        $caller = Caller::parse(self::context()['hub']['caller']);
        self::assertEquals(new Caller(
            key: 'MCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=',
            device: new CallerDevice('8cef065b7af83669150b7d32704d3d3e', 'Mac Studio'),
            groups: ['owners'],
            owner: true,
        ), $caller);
    }

    public function testParseAnonymousAndMergedCallers(): void
    {
        self::assertEquals(new Caller(), Caller::parse(['groups' => []]));
        $merged = Caller::parse(['key' => 'A', 'via' => 'H', 'claimed' => ['key' => 'B', 'owner' => true]]);
        self::assertSame('H', $merged?->via);
        self::assertEquals(new Caller(key: 'B', owner: true), $merged?->claimed);
        self::assertNull(Caller::parse(null));
    }

    public function testHandlersGetTheCaller(): void
    {
        $dir = sys_get_temp_dir() . '/hubcaller-php-' . bin2hex(random_bytes(4));
        mkdir($dir);
        Keychain::setKeyPath($dir . '/auth');
        $saved = getenv('HUB_DEVICE_KEY');
        putenv('HUB_DEVICE_KEY=' . $dir . '/device.key');
        $context = self::context();
        $results = $dir . '/results.json';
        // The hub process calls the service back on test/run.
        $hub = new FakeHub(scenario: 'caller', results: $results);
        try {
            $this->co(function () use ($hub, $results): void {
                $service = (new Service(['address' => $hub->port, 'hubKey' => FakeHub::HUB_KEY]))
                    ->post('whoami', static function (mixed $body, Request $request): array {
                        $caller = $request->caller ?? new Caller();
                        $keys = array_keys($request->context);
                        sort($keys);
                        return [$body, $caller->key, $caller->owner, $keys];
                    })
                    ->post('echo', static fn (mixed $body): mixed => $body)
                    ->post('trim', 'trim')
                    ->stream('whoami/values', static function (mixed $body, Request $request): \Generator {
                        yield $request->caller?->device?->name;
                    })
                    ->start();
                try {
                    self::assertTrue($service->send('test/run'));
                } finally {
                    $service->stop();
                }
            });
            $out = json_decode((string) file_get_contents($results), true);
            self::assertSame(['hi', $context['hub']['caller']['key'], true, []], $out['post']);
            self::assertSame('hi', $out['plain']);
            self::assertSame('hi', $out['internal']);
            self::assertSame(['Mac Studio'], $out['stream']);
            self::assertSame(['hi', null, false, ['service']], $out['anonymous']);
            // A caller is trusted only from the pinned hub.
            self::assertSame(['hi', null, false, []], $out['spoofed']);
        } finally {
            $hub->stop();
            putenv($saved === false ? 'HUB_DEVICE_KEY' : 'HUB_DEVICE_KEY=' . $saved);
            Keychain::setKeyPath('auth');
            exec('rm -rf ' . escapeshellarg($dir));
        }
    }
}
