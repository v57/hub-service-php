<?php

declare(strict_types=1);

namespace HubServicePhp\Tests;

use HubServicePhp\Keychain;
use HubServicePhp\LocalAgentError;
use HubServicePhp\NetworkPublisher;
use HubServicePhp\Service;
use HubServicePhp\Tests\Support\CoroutineTestCase;
use HubServicePhp\Tests\Support\FakeHub;
use InvalidArgumentException;

/** Hub Network share publication against a fake agent and hub (TS network.ts parity). */
final class NetworkTest extends CoroutineTestCase
{
    private string $dir;

    private string $socket;

    /** @var resource|null */
    private $agent = null;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/hubnet-php-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        // Unix socket paths are short.
        $this->socket = '/tmp/hn-' . bin2hex(random_bytes(4)) . '.sock';
        Keychain::setKeyPath($this->dir . '/auth');
    }

    protected function tearDown(): void
    {
        if (is_resource($this->agent)) {
            proc_terminate($this->agent, SIGTERM);
            proc_close($this->agent);
        }
        @unlink($this->socket);
        Keychain::setKeyPath('auth');
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    private function startAgent(string $mode = 'fresh'): void
    {
        $this->agent = proc_open([PHP_BINARY, __DIR__ . '/Support/fake-agent.php', $this->socket, $mode], [0 => ['pipe', 'r'], 1 => STDOUT, 2 => STDERR], $pipes);
        for ($i = 0; $i < 200 && !file_exists($this->socket); $i++) {
            usleep(20_000);
        }
    }

    /** @return array<string, mixed> */
    private static function share(string $name = 's3', int $port = 9001): array
    {
        return ['name' => $name, 'protocol' => 'tcp', 'target' => ['host' => '127.0.0.1', 'port' => $port]];
    }

    public function testShareValidation(): void
    {
        NetworkPublisher::validateShare(self::share());
        $bad = [
            ['name' => ''] + self::share(),
            ['protocol' => 'sctp'] + self::share(),
            ['target' => ['host' => 'h', 'port' => 70000]] + self::share(),
            self::share() + ['policy' => ['mode' => 'keys', 'keys' => []]],
        ];
        foreach ($bad as $share) {
            try {
                NetworkPublisher::validateShare($share);
                self::fail('accepted ' . json_encode($share));
            } catch (InvalidArgumentException) {
                self::assertTrue(true);
            }
        }
    }

    public function testDeclaredSharesPublishOnConnectAndUpdate(): void
    {
        $this->startAgent();
        $hub = new FakeHub();
        try {
            $this->co(function () use ($hub): void {
                $service = new Service(['address' => $hub->port, 'hubKey' => FakeHub::HUB_KEY, 'device' => false]);
                $service->network->agentSocket = $this->socket;
                $service->share('s3', 'tcp', '127.0.0.1', 9001, ['mode' => 'hub'])->start();
                try {
                    $hub->waitFor(static fn (): int => $service->sharePublication('s3') === null ? 0 : 1, 1);
                    $wire = $hub->replaced()[0]['shares'][0];
                    self::assertSame(['s3', 1, ['mode' => 'hub']], [$wire['name'], $wire['version'], $wire['policy']]);
                    self::assertSame(Keychain::publicKey(), $wire['attestation']['serviceKey']);
                    self::assertSame('hnr1_s3', $service->sharePublication('s3')['resourceId'] ?? null);

                    $service->publishShare('ssh', 'tcp', '127.0.0.1', 22);
                    $last = static fn (): array => $hub->replaced()[count($hub->replaced()) - 1]['shares'];
                    self::assertSame(['s3', 'ssh'], array_column($last(), 'name'));
                    self::assertSame(['mode' => 'private'], $last()[1]['policy']);

                    $service->updateShare('ssh', port: 2222);
                    self::assertSame(['host' => '127.0.0.1', 'port' => 2222], $last()[1]['target']);
                    self::assertSame(2222, $service->sharePublication('ssh')['port'] ?? null);

                    $service->removeShare('s3');
                    self::assertSame(['ssh'], array_column($last(), 'name'));
                    self::assertSame(['hnr1_ssh'], array_column($service->sharePublications(), 'resourceId'));
                } finally {
                    $service->stop();
                }
            });
        } finally {
            $hub->stop();
        }
    }

    public function testExpiredAttestationIsRefusedAndRolledBack(): void
    {
        $this->startAgent('expired');
        $publisher = new NetworkPublisher($this->socket);
        try {
            $publisher->publishShare(self::share(), Keychain::publicKey(), [Keychain::class, 'signChallenge'], new \stdClass());
            self::fail('published with an expired attestation');
        } catch (LocalAgentError $error) {
            self::assertSame('attestation-expired', $error->errorCode);
        }
        self::assertFalse($publisher->hasShares());
    }

    public function testAgentUnavailableAndRejected(): void
    {
        $publisher = new NetworkPublisher($this->socket);
        try {
            $publisher->requestAttestation(self::share(), Keychain::publicKey(), [Keychain::class, 'signChallenge']);
            self::fail('reached a missing agent');
        } catch (LocalAgentError $error) {
            self::assertSame('agent-unavailable', $error->errorCode);
        }
        $this->startAgent();
        // Inside a coroutine, the coroutine client is used.
        $this->co(function () use ($publisher): void {
            try {
                $publisher->requestAttestation(self::share(), Keychain::publicKey(), static fn (): string => 'AAAA');
                self::fail('the agent accepted a bad signature');
            } catch (LocalAgentError $error) {
                self::assertSame(['agent-rejected', 403], [$error->errorCode, $error->status]);
            }
        });
    }
}
