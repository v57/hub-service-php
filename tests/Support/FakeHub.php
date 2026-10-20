<?php

declare(strict_types=1);

namespace HubServicePhp\Tests\Support;

use ChannelPhp\Channel;
use ChannelPhp\Transports\RunningServer;
use OpenSwoole\Coroutine;
use RuntimeException;

/**
 * A hub in a forked OpenSwoole server process. It logs every connect's
 * headers and every update to a file the test reads, and answers hub/info
 * unless booted as hub-lite.
 */
final class FakeHub
{
    public const HUB_KEY = 'MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=';

    public readonly RunningServer $server;

    public readonly string $log;

    /**
     * @param array<string, callable(array): mixed> $extra more handlers (run in the hub process)
     */
    public function __construct(bool $lite = false, array $extra = [])
    {
        $this->log = (string) tempnam(sys_get_temp_dir(), 'fakehub-php-');
        $log = $this->log;
        $channel = new Channel();
        if (!$lite) {
            $channel->post('hub/info', static fn (): array => [
                'key' => self::HUB_KEY, 'protocol' => 1, 'pro' => true, 'mode' => 'default-allow',
            ]);
        }
        foreach (['hub/profile/update', 'hub/service/update'] as $path) {
            $channel->post($path, static function (array $request) use ($log, $path): mixed {
                self::append($log, ['path' => $path, 'body' => $request['body'] ?? null]);
                return null;
            });
        }
        foreach ($extra as $path => $handler) {
            $channel->post($path, $handler);
        }
        $this->server = $channel->listen('127.0.0.1:' . self::freePort(), [
            'state' => static function (array $headers) use ($log): \stdClass {
                self::append($log, ['headers' => $headers]);
                return new \stdClass();
            },
        ]);
    }

    public function stop(): void
    {
        $this->server->stop();
        @unlink($this->log);
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function entries(): array
    {
        $lines = file($this->log, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];

        return array_map(static fn (string $line): array => json_decode($line, true), $lines);
    }

    /**
     * @return list<array<string, string|null>>
     */
    public function connects(): array
    {
        return array_values(array_map(
            static fn (array $e): array => $e['headers'],
            array_filter($this->entries(), static fn (array $e): bool => isset($e['headers'])),
        ));
    }

    /**
     * Waits (inside a coroutine) until the log has $count matching entries.
     */
    public function waitFor(callable $count, int $want, float $seconds = 5.0): void
    {
        $deadline = microtime(true) + $seconds;
        while ($count($this) < $want) {
            if (microtime(true) > $deadline) {
                throw new RuntimeException("timed out waiting for $want entries: " . json_encode($this->entries()));
            }
            Coroutine::usleep(20_000);
        }
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function append(string $log, array $entry): void
    {
        file_put_contents($log, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);
    }

    private static function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
