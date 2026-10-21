<?php

declare(strict_types=1);

namespace HubServicePhp\Tests\Support;

use OpenSwoole\Coroutine;
use RuntimeException;

/**
 * A hub in its own OpenSwoole server process (fake-hub.php). It logs every
 * connect's headers and every update to a file the test reads, and answers
 * hub/info unless booted as hub-lite.
 */
final class FakeHub
{
    public const HUB_KEY = 'MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=';

    public readonly int $port;

    public readonly string $log;

    /** @var resource */
    private $process;

    /**
     * A fresh PHP process, not a fork: a fork inherits the test process's
     * coroutine hooks, and then the hub's header logging yields inside the
     * open handler and drops the client's first message.
     *
     * @param string $scenario 'none', or 'caller' (test/run calls the service back, results to $results)
     */
    public function __construct(bool $lite = false, string $scenario = 'none', string $results = '')
    {
        $this->log = (string) tempnam(sys_get_temp_dir(), 'fakehub-php-');
        $this->port = self::freePort();
        $command = [PHP_BINARY, __DIR__ . '/fake-hub.php', (string) $this->port, $this->log, $lite ? 'lite' : 'pro', $scenario, $results];
        $process = proc_open($command, [0 => ['pipe', 'r'], 1 => STDOUT, 2 => STDERR], $pipes);
        if (!is_resource($process)) {
            throw new RuntimeException('cannot start the fake hub');
        }
        $this->process = $process;
        $deadline = microtime(true) + 10.0;
        while (($socket = @stream_socket_client('tcp://127.0.0.1:' . $this->port, $code, $message, 0.2)) === false) {
            if (microtime(true) > $deadline) {
                $this->stop();
                throw new RuntimeException('the fake hub did not start');
            }
            usleep(50_000);
        }
        fclose($socket);
    }

    public function stop(): void
    {
        if (is_resource($this->process)) {
            proc_terminate($this->process, SIGTERM);
            $deadline = microtime(true) + 3.0;
            while (proc_get_status($this->process)['running'] && microtime(true) < $deadline) {
                usleep(20_000);
            }
            if (proc_get_status($this->process)['running']) {
                proc_terminate($this->process, SIGKILL);
            }
            proc_close($this->process);
        }
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
     * The network/shares/replace bodies received.
     *
     * @return list<array<string, mixed>>
     */
    public function replaced(): array
    {
        return array_values(array_map(
            static fn (array $e): array => $e['replaced'],
            array_filter($this->entries(), static fn (array $e): bool => isset($e['replaced'])),
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

    private static function freePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0');
        $name = (string) stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
