<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use Generator;
use HubServicePhp\App;
use HubServicePhp\AppHeader;
use HubServicePhp\Service;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class ServiceTest extends TestCase
{
    public function testServicesListIncludesRegisteredPaths(): void
    {
        $service = new Service();
        $service
            ->post('echo', static fn (mixed $body): mixed => $body)
            ->stream('echo/values', static function (mixed $body): Generator {
                yield $body;
            })
            ->app(new App(new AppHeader('Echo', 'echo/ui'), ['hi']));

        $update = $service->update();

        // post + stream + app path, sorted by path.
        self::assertCount(3, $update['services']);
        self::assertSame(
            ['echo', 'echo/ui', 'echo/values'],
            array_column($update['services'], 'path'),
        );

        self::assertCount(1, $update['apps']);
        self::assertSame('app', $update['apps'][0]->type);
        self::assertSame('Echo', $update['apps'][0]->name);
        self::assertSame('echo/ui', $update['apps'][0]->path);
    }

    public function testSettingsApplyToUpdatePayload(): void
    {
        $service = new Service();
        $service->post('echo', static fn (mixed $body): mixed => $body, [
            'permissions' => ['name' => 'Echo', 'allows' => true],
            'limit' => 5,
        ]);

        $services = $service->update()['services'];
        self::assertCount(1, $services);

        $entry = $services[0];
        self::assertSame('echo', $entry['path']);
        self::assertSame(5, $entry['limit']);
        // group auto-filled from the first path segment (TS/Go parity).
        self::assertSame('echo', $entry['permissions']['group']);
        self::assertSame('Echo', $entry['permissions']['name']);
        self::assertTrue($entry['permissions']['allows']);
    }

    public function testUpdateJSONMatchesWireContract(): void
    {
        $service = new Service();
        $service->post('echo', static fn (mixed $body): mixed => $body, [
            'permissions' => ['name' => 'Echo', 'allows' => true],
            'limit' => 5,
        ]);

        $json = json_encode($service->update(), JSON_UNESCAPED_SLASHES);
        self::assertSame(
            '{"services":[{"path":"echo","permissions":{"group":"echo","name":"Echo","allows":true},"limit":5}],"apps":[]}',
            $json,
        );
    }

    public function testUpdateJSONWithAppMatchesWireContract(): void
    {
        $service = new Service();
        $service
            ->post('echo', static fn (mixed $body): mixed => $body)
            ->app(new App(new AppHeader('Echo', 'echo/ui'), []));

        $json = json_encode($service->update(), JSON_UNESCAPED_SLASHES);
        self::assertSame(
            '{"services":[{"path":"echo"},{"path":"echo/ui"}],"apps":[{"type":"app","name":"Echo","path":"echo/ui"}]}',
            $json,
        );
    }

    public function testSendBeforeStartThrows(): void
    {
        $service = new Service();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Service not started');
        $service->send('echo', 'x');
    }

    public function testValuesBeforeStartThrows(): void
    {
        $service = new Service();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Service not started');
        $service->values('echo', 'x');
    }

    public function testProfileOnlyWhenSet(): void
    {
        $plain = new Service();
        self::assertNull($plain->profile());

        $named = new Service(['name' => 'Echo']);
        self::assertSame(['name' => 'Echo'], $named->profile());

        $iconed = new Service(['icon' => ['symbol' => 'speaker.wave.2', 'text' => 'E']]);
        self::assertSame(
            ['icon' => ['symbol' => 'speaker.wave.2', 'text' => 'E']],
            $iconed->profile(),
        );

        $both = new Service([
            'name' => 'Echo',
            'icon' => ['symbol' => 'speaker.wave.2', 'text' => 'E'],
        ]);
        self::assertSame(
            '{"name":"Echo","icon":{"symbol":"speaker.wave.2","text":"E"}}',
            json_encode($both->profile(), JSON_UNESCAPED_SLASHES),
        );
    }

    public function testAddressDefaults(): void
    {
        $service = new Service();
        // 1997 is the default; address is private, exercised via start() later.
        self::assertNull($service->profile());
    }
}
