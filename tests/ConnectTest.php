<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\Keychain;
use HubServicePhp\Service;
use HubServicePhp\Tests\Support\CoroutineTestCase;
use HubServicePhp\Tests\Support\FakeHub;

final class ConnectTest extends CoroutineTestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hubconnect-php-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        Keychain::setKeyPath($this->dir . '/auth');
    }

    protected function tearDown(): void
    {
        Keychain::setKeyPath('auth');
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    public function testConnectSendsProfileAndServiceUpdates(): void
    {
        $hub = new FakeHub(lite: true);
        try {
            $this->co(function () use ($hub): void {
                $service = (new Service(['address' => $hub->server->port, 'name' => 'Echo']))
                    ->post('echo', static fn (mixed $body): mixed => $body)
                    ->start();
                try {
                    $updates = static fn (FakeHub $h): int => count(array_filter($h->entries(), static fn (array $e): bool => isset($e['path'])));
                    $hub->waitFor($updates, 2);
                    $paths = array_values(array_filter(array_column($hub->entries(), 'path')));
                    self::assertSame(['hub/profile/update', 'hub/service/update'], $paths);
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }
}
