<?php

declare(strict_types=1);

namespace HubServicePhp;

use InvalidArgumentException;
use OpenSwoole\Coroutine;
use OpenSwoole\Coroutine\Client as CoClient;
use RuntimeException;

/**
 * Hub Network share publication (TS network.ts parity).
 *
 * A share makes a local TCP/UDP port reachable through Hub Network. For each
 * declared share the service asks the local hub-net agent (HTTP over its Unix
 * socket) for an attestation: ``/challenge`` returns a nonce, the service signs
 * it with its key, and ``/attest`` returns the agent-signed attestation. The
 * complete declared set then goes to the hub in one ``network/shares/replace``
 * call, which answers with one publication per share in request order. The set
 * is republished after every reconnect.
 *
 * A share is ``['name' => .., 'protocol' => 'tcp'|'udp', 'target' => ['host' => .., 'port' => ..], 'policy' => [..]]``.
 */
final class NetworkPublisher
{
    public const WIRE_VERSION = 1;

    public const AGENT_SOCKET = '/var/run/hub-net/agent.sock';

    private const MAX_SHARE_NAME_LENGTH = 255;

    /** @var array<string, array<string, mixed>> */
    private array $shares = [];

    /** @var array<string, array<string, mixed>> */
    private array $publications = [];

    /**
     * @param (callable(array, string, callable(string): string): array)|null $attestationProvider
     */
    public function __construct(
        public string $agentSocket = self::AGENT_SOCKET,
        public float $agentTimeout = 5.0,
        public $attestationProvider = null,
    ) {
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function declaredShares(): array
    {
        $names = array_map('strval', array_keys($this->shares));
        sort($names, SORT_STRING);

        return array_map(fn (string $name): array => $this->shares[$name], $names);
    }

    public function hasShares(): bool
    {
        return $this->shares !== [];
    }

    /**
     * Declares a share; the next connect publishes the whole set.
     *
     * @param array<string, mixed> $share
     */
    public function declareShare(array $share): void
    {
        self::validateShare($share);
        $this->shares[$share['name']] = $share;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function publications(): array
    {
        return array_values($this->publications);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function publication(string $name): ?array
    {
        return $this->publications[$name] ?? null;
    }

    /**
     * Proves the service key to the local agent; returns its attestation.
     *
     * @param array<string, mixed> $share
     * @param callable(string): string $sign
     * @return array<string, mixed>
     */
    public function requestAttestation(array $share, string $serviceKey, callable $sign): array
    {
        self::validateShare($share);
        $body = [
            'serviceKey' => $serviceKey,
            'shareName' => $share['name'],
            'protocol' => $share['protocol'],
            'target' => $share['target'],
        ];
        $challenge = $this->agent('/challenge', $body, 'challenge');
        $nonce = is_array($challenge) ? ($challenge['nonce'] ?? null) : null;
        if (!is_string($nonce) || $nonce === '') {
            throw new LocalAgentError('invalid-agent-response', 'Hub Network agent returned an invalid challenge');
        }
        $attestation = $this->agent('/attest', $body + ['signature' => (string) $sign($nonce)], 'attestation');
        self::validateAttestation($attestation, $share, $serviceKey);

        return $attestation;
    }

    /**
     * @param array<string, mixed> $share
     * @param callable(string): string $sign
     * @return list<array<string, mixed>>
     */
    public function publishShare(array $share, string $serviceKey, callable $sign, object $sender): array
    {
        self::validateShare($share);
        $previous = $this->shares[$share['name']] ?? null;
        $this->shares[$share['name']] = $share;
        try {
            return $this->synchronize($serviceKey, $sign, $sender);
        } catch (\Throwable $error) {
            if ($previous !== null) {
                $this->shares[$share['name']] = $previous;
            } else {
                unset($this->shares[$share['name']]);
            }
            throw $error;
        }
    }

    /**
     * @param callable(string): string $sign
     * @return list<array<string, mixed>>
     */
    public function republishAll(string $serviceKey, callable $sign, object $sender): array
    {
        return $this->synchronize($serviceKey, $sign, $sender);
    }

    /**
     * @param callable(string): string $sign
     * @return list<array<string, mixed>>
     */
    public function removeShare(string $name, string $serviceKey, callable $sign, object $sender): array
    {
        self::string($name, 'share name', self::MAX_SHARE_NAME_LENGTH);
        $removed = $this->shares[$name] ?? null;
        if ($removed === null) {
            throw new RuntimeException("Share '$name' not found");
        }
        unset($this->shares[$name]);
        try {
            return $this->synchronize($serviceKey, $sign, $sender);
        } catch (\Throwable $error) {
            $this->shares[$name] = $removed;
            throw $error;
        }
    }

    /**
     * @param array<string, mixed> $share
     */
    public static function validateShare(mixed $share): void
    {
        if (!is_array($share)) {
            throw new InvalidArgumentException('Invalid Hub Network share');
        }
        self::string($share['name'] ?? null, 'share name', self::MAX_SHARE_NAME_LENGTH);
        if (!in_array($share['protocol'] ?? null, ['tcp', 'udp'], true)) {
            throw new InvalidArgumentException('Invalid Hub Network protocol');
        }
        $target = $share['target'] ?? null;
        if (!is_array($target)) {
            throw new InvalidArgumentException('Invalid Hub Network target');
        }
        self::string($target['host'] ?? null, 'target host');
        self::port($target['port'] ?? null);
        if (isset($share['policy'])) {
            self::validatePolicy($share['policy']);
        }
    }

    public static function validatePolicy(mixed $policy): void
    {
        if (!is_array($policy) || !is_string($policy['mode'] ?? null)) {
            throw new InvalidArgumentException('Invalid Hub Network policy');
        }
        switch ($policy['mode']) {
            case 'hub':
            case 'private':
            case 'disabled':
                return;
            case 'group':
                self::string($policy['group'] ?? null, 'policy group');
                return;
            case 'keys':
                $keys = $policy['keys'] ?? null;
                if (!is_array($keys) || $keys === []) {
                    throw new InvalidArgumentException('Invalid Hub Network policy keys');
                }
                foreach ($keys as $key) {
                    try {
                        self::string($key, 'policy key');
                    } catch (InvalidArgumentException) {
                        throw new InvalidArgumentException('Invalid Hub Network policy keys');
                    }
                }
                return;
            default:
                throw new InvalidArgumentException('Invalid Hub Network policy mode');
        }
    }

    /**
     * @param callable(string): string $sign
     * @return list<array<string, mixed>>
     */
    private function synchronize(string $serviceKey, callable $sign, object $sender): array
    {
        $shares = $this->declaredShares();
        $wire = [];
        foreach ($shares as $share) {
            $attestation = $this->attestationProvider !== null
                ? ($this->attestationProvider)($share, $serviceKey, $sign)
                : $this->requestAttestation($share, $serviceKey, $sign);
            self::validateAttestation($attestation, $share, $serviceKey);
            $wire[] = $share + ['version' => self::WIRE_VERSION, 'attestation' => $attestation];
        }

        $response = $sender->send('network/shares/replace', ['shares' => $wire]);
        if (!is_array($response) || !is_array($response['shares'] ?? null)) {
            throw new RuntimeException('Hub returned an invalid shares/replace response');
        }
        $publications = array_values($response['shares']);
        if (count($publications) !== count($shares)) {
            throw new RuntimeException(sprintf('Hub returned %d publications for %d shares', count($publications), count($shares)));
        }
        // v1 publications carry no share name: the hub keeps request order.
        $correlated = [];
        $resources = [];
        foreach ($shares as $index => $share) {
            $validated = self::validatePublication($publications[$index], $share, $index);
            if (isset($resources[$validated['resourceId']])) {
                throw new RuntimeException("Hub returned duplicate resourceId at share index $index");
            }
            $resources[$validated['resourceId']] = true;
            $correlated[$share['name']] = $validated;
        }
        $this->publications = $correlated;

        return array_values($correlated);
    }

    /**
     * @param array<string, mixed> $share
     * @return array<string, mixed>
     */
    private static function validatePublication(mixed $value, array $share, int $index): array
    {
        if (!is_array($value)) {
            throw new RuntimeException("Invalid Hub publication at share index $index");
        }
        if (($value['version'] ?? null) !== self::WIRE_VERSION) {
            throw new RuntimeException("Invalid Hub publication version at share index $index");
        }
        $resource = $value['resourceId'] ?? null;
        if (!is_string($resource) || !str_starts_with($resource, 'hnr1_') || $resource === 'hnr1_') {
            throw new RuntimeException("Invalid Hub publication resourceId at share index $index");
        }
        self::string($value['authority'] ?? null, "publication authority at share index $index");
        self::string($value['providerId'] ?? null, "publication providerId at share index $index");
        self::string($value['overlayAddress'] ?? null, "publication overlayAddress at share index $index");
        if (($value['protocol'] ?? null) !== $share['protocol']) {
            throw new RuntimeException("Hub publication protocol mismatch at share index $index");
        }
        self::port($value['port'] ?? null, "publication port at share index $index");

        return $value;
    }

    /**
     * @param array<string, mixed> $share
     */
    private static function validateAttestation(mixed $attestation, array $share, string $serviceKey): void
    {
        $target = is_array($attestation) ? ($attestation['target'] ?? null) : null;
        if (
            !is_array($attestation)
            || ($attestation['version'] ?? null) !== self::WIRE_VERSION
            || ($attestation['serviceKey'] ?? null) !== $serviceKey
            || ($attestation['shareName'] ?? null) !== $share['name']
            || ($attestation['protocol'] ?? null) !== $share['protocol']
            || !is_array($target)
            || ($target['host'] ?? null) !== $share['target']['host']
            || ($target['port'] ?? null) !== $share['target']['port']
        ) {
            throw new LocalAgentError('attestation-mismatch', 'Local-agent attestation does not match the share');
        }
        $issued = self::time($attestation['issuedAt'] ?? null);
        $expires = self::time($attestation['expiresAt'] ?? null);
        $now = microtime(true);
        if ($issued === null || $expires === null || $expires <= $issued || $issued > $now + 30 || $expires <= $now) {
            throw new LocalAgentError('attestation-expired', 'Local-agent attestation is expired');
        }
    }

    private static function time(mixed $value): ?float
    {
        if (!is_string($value)) {
            return null;
        }
        $time = date_create_immutable($value);

        return $time === false ? null : (float) $time->format('U.u');
    }

    private static function string(mixed $value, string $field, ?int $maxLength = null): string
    {
        if (
            !is_string($value)
            || trim($value) === ''
            || preg_match('/[\x00-\x1f\x7f]/', $value) === 1
            || ($maxLength !== null && mb_strlen($value) > $maxLength)
        ) {
            throw new InvalidArgumentException("Invalid Hub Network $field");
        }

        return $value;
    }

    private static function port(mixed $value, string $field = 'target port'): void
    {
        if (!is_int($value) || $value < 1 || $value > 65535) {
            throw new InvalidArgumentException("Invalid Hub Network $field");
        }
    }

    /**
     * POSTs JSON to the agent over its Unix socket and decodes the reply.
     *
     * @param array<string, mixed> $body
     */
    private function agent(string $path, array $body, string $operation): mixed
    {
        [$status, $payload] = $this->post($path, $body);
        if ($status < 200 || $status > 299) {
            $detail = trim($payload);
            throw new LocalAgentError(
                'agent-rejected',
                "Hub Network agent rejected $operation ($status)" . ($detail !== '' ? ": $detail" : ''),
                $status,
            );
        }
        $decoded = json_decode($payload, true);
        if ($decoded === null && json_last_error() !== JSON_ERROR_NONE) {
            throw new LocalAgentError('invalid-agent-response', 'Hub Network agent returned invalid JSON', $status);
        }

        return $decoded;
    }

    /**
     * @param array<string, mixed> $body
     * @return array{int, string}
     */
    private function post(string $path, array $body): array
    {
        $data = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $request = "POST $path HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
            . 'Content-Length: ' . strlen($data) . "\r\nConnection: close\r\n\r\n" . $data;
        $deadline = microtime(true) + $this->agentTimeout;
        $raw = '';

        if (Coroutine::getCid() >= 0) {
            $client = new CoClient(SWOOLE_SOCK_UNIX_STREAM);
            if (!$client->connect($this->agentSocket, 0, $this->agentTimeout)) {
                throw new LocalAgentError('agent-unavailable', "Hub Network agent is unavailable at {$this->agentSocket}");
            }
            try {
                $client->send($request);
                while (true) {
                    $left = $deadline - microtime(true);
                    if ($left <= 0) {
                        throw $this->timeout();
                    }
                    $chunk = $client->recv($left);
                    if ($chunk === '' || $chunk === false) {
                        if ($chunk === false && (int) $client->errCode === SOCKET_ETIMEDOUT) {
                            throw $this->timeout();
                        }
                        break;
                    }
                    $raw .= $chunk;
                }
            } finally {
                $client->close();
            }
        } else {
            $stream = @stream_socket_client('unix://' . $this->agentSocket, $code, $message, $this->agentTimeout);
            if ($stream === false) {
                throw new LocalAgentError('agent-unavailable', "Hub Network agent is unavailable at {$this->agentSocket}");
            }
            try {
                stream_set_timeout($stream, (int) ceil($this->agentTimeout));
                fwrite($stream, $request);
                while (!feof($stream)) {
                    $chunk = fread($stream, 65536);
                    if (($chunk === false || $chunk === '') && stream_get_meta_data($stream)['timed_out']) {
                        throw $this->timeout();
                    }
                    $raw .= (string) $chunk;
                }
            } finally {
                fclose($stream);
            }
        }

        return self::parseResponse($raw);
    }

    private function timeout(): LocalAgentError
    {
        return new LocalAgentError('agent-timeout', sprintf('Hub Network agent timed out after %d ms', (int) ($this->agentTimeout * 1000)));
    }

    /**
     * @return array{int, string}
     */
    private static function parseResponse(string $raw): array
    {
        [$head, $body] = array_pad(explode("\r\n\r\n", $raw, 2), 2, '');
        $lines = explode("\r\n", $head);
        if (preg_match('#^HTTP/1\.[01] (\d{3})#', $lines[0] ?? '', $match) !== 1) {
            throw new LocalAgentError('invalid-agent-response', 'Hub Network agent returned an invalid HTTP response');
        }
        $headers = [];
        foreach (array_slice($lines, 1) as $line) {
            [$name, $value] = array_pad(explode(':', $line, 2), 2, '');
            $headers[strtolower(trim($name))] = trim($value);
        }
        if (strtolower($headers['transfer-encoding'] ?? '') === 'chunked') {
            $decoded = '';
            while ($body !== '') {
                [$sizeLine, $rest] = array_pad(explode("\r\n", $body, 2), 2, '');
                $size = hexdec(explode(';', $sizeLine)[0]);
                if ($size === 0) {
                    break;
                }
                $decoded .= substr($rest, 0, (int) $size);
                $body = (string) substr($rest, (int) $size + 2);
            }
            $body = $decoded;
        } elseif (isset($headers['content-length'])) {
            $body = substr($body, 0, (int) $headers['content-length']);
        }

        return [(int) $match[1], $body];
    }
}
