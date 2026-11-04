<?php

declare(strict_types=1);

namespace HubServicePhp;

use ChannelPhp\Channel;
use ChannelPhp\ClientSender;
use ChannelPhp\Sender;
use ChannelPhp\Values;
use Generator;
use OpenSwoole\Coroutine;
use RuntimeException;

/**
 * Service registers API endpoints on a hub and serves calls forwarded by it.
 *
 * Port of hub-service (TS reference): on every (re)connect the service sends
 * hub/profile/update (if a profile is set) and hub/service/update with the
 * current services + apps lists. The hub drops services on disconnect, so the
 * updates are re-issued on each reconnect.
 *
 * Auth follows Docs/Devices/protocol.md section 2: every (re)connect asks the
 * hub to prove its key and sends a fresh token for that answer alone (see
 * HubProof). The first proven key is pinned in ``hubs.json`` beside the key
 * file; a hub that doesn't prove its key, or answers with another than the
 * pinned one, gets nothing.
 */
final class Service
{
    /** Retry delays (seconds) for a hub that doesn't prove its key, or can't be reached. */
    private const HANDSHAKE_RETRY = 1.0;

    private const HANDSHAKE_MAX_RETRY = 30.0;

    private Channel $channel;

    private int|string $address;

    /** @var array{name?: string, icon?: mixed}|null */
    private ?array $profile = null;

    /** @var list<AppHeader> */
    private array $apps = [];

    /** @var array<string, true> */
    private array $paths = [];

    /** @var array<string, array{permissions?: array<string, mixed>, limit?: mixed}> */
    private array $settings = [];

    private ?ClientSender $sender = null;

    /** @var callable(string, string): string */
    private $sign;

    private ?string $hubKey;

    private bool $allowPlaintext;

    /** Why the service isn't connected, if it knows. */
    private ?string $lastError = null;

    /** Moves on with every stop, which ends a wait for the hub's proof. */
    private int $generation = 0;

    private ?string $pinned = null;

    private bool $pinLoaded = false;

    private ?string $instance;

    public readonly ?Device $device;

    /** Hub Network shares; the agent socket is ``$network->agentSocket``. */
    public readonly NetworkPublisher $network;

    /** @var callable(string): string */
    private $signChallenge;

    private ?string $serviceKey = null;

    /**
     * Options: ``address``, ``name``, ``icon``; ``sign`` (token factory, called
     * as ``sign(hubKey, challenge)`` with the key the hub proved and the
     * challenge of this connect, only after the proof); ``hubKey`` (the hub's
     * key when known up front, otherwise the first key a hub proves is pinned);
     * ``allowPlaintext`` (dial plain ws:// beyond loopback, the overlay and the
     * LAN, which would carry the key unencrypted: for private networks the SDK
     * can't recognize, such as a container's ws://hub:1997; also
     * ``HUB_ALLOW_PLAINTEXT=1``); ``instance`` (this service's
     * name on its device, unique per device; default: ``HUB_INSTANCE``, else
     * ``name``, else the cwd name, else ``service``); ``device``
     * (true, the default, certifies the service with this device's key when
     * it can be read or created; false sends no ``device`` header; a Device
     * uses that one); ``signChallenge`` (signs Hub Network agent challenges
     * with the service key; default: the keychain ``auth`` file).
     *
     * @param array{address?: int|string, name?: string, icon?: mixed, sign?: callable, hubKey?: string, allowPlaintext?: bool, instance?: string, device?: bool|Device} $options
     */
    public function __construct(array $options = [])
    {
        $this->channel = new Channel();

        $address = $options['address'] ?? null;
        if ($address !== null) {
            $this->address = $address;
        } else {
            $env = getenv('HUB');
            $this->address = ($env !== false && $env !== '')
                ? (ctype_digit($env) ? (int)$env : $env)
                : 1997;
        }

        $this->sign = $options['sign'] ?? [Keychain::class, 'sign'];
        $this->hubKey = $options['hubKey'] ?? null;
        $this->allowPlaintext = ($options['allowPlaintext'] ?? false) || getenv('HUB_ALLOW_PLAINTEXT') === '1';
        $this->instance = $options['instance'] ?? null;
        $device = $options['device'] ?? true;
        $this->device = $device instanceof Device ? $device : ($device ? new Device() : null);
        $this->signChallenge = $options['signChallenge'] ?? [Keychain::class, 'signChallenge'];
        $this->network = new NetworkPublisher();

        $name = $options['name'] ?? null;
        $icon = $options['icon'] ?? null;
        if ($name !== null && $name !== '') {
            $this->profile ??= [];
            $this->profile['name'] = $name;
        }
        if ($icon !== null) {
            $this->profile ??= [];
            $this->profile['icon'] = $icon;
        }
    }

    /**
     * Registers a request/response API endpoint. A handler with a second
     * parameter also gets the Request (``$request->caller``: who is calling).
     *
     * @param callable(mixed): mixed $handler
     * @param array{permissions?: array{group?: string, name?: string, allows?: bool}, limit?: mixed} $settings
     */
    public function post(string $path, callable $handler, array $settings = []): self
    {
        $this->addPath($path, $settings);
        $this->channel->post($path, $this->adapt($handler));

        return $this;
    }

    /**
     * Registers a streaming API endpoint. The handler receives the request body
     * (and the Request, as in post) and returns a \Generator whose yielded
     * values are streamed to the caller.
     *
     * @param callable(mixed): \Generator $handler
     * @param array{permissions?: array{group?: string, name?: string, allows?: bool}, limit?: mixed} $settings
     */
    public function stream(string $path, callable $handler, array $settings = []): self
    {
        $this->addPath($path, $settings);
        $this->channel->stream($path, $this->adapt($handler));

        return $this;
    }

    /**
     * Registers an app: its header goes to the hub apps list and its path serves
     * the AppInterface as a stream (TS parity: the path is also callable).
     */
    public function app(App $app): self
    {
        $this->apps[] = $app->header;
        $this->addPath($app->header->path, []);
        $header = $app->header->toArray();
        $this->channel->stream($app->header->path, static function () use ($app, $header): Generator {
            yield [
                'header' => $header,
                'body' => $app->body,
                'top' => $app->top,
                'bottom' => $app->bottom,
                'data' => $app->data,
            ];
        });

        return $this;
    }

    /**
     * Calls an API through the hub. Throws if the service is not started.
     */
    public function send(string $path, mixed $body = null, mixed $context = null): mixed
    {
        return $this->senderOrError()->send($path, $body, $context);
    }

    /**
     * Opens a stream call through the hub. Throws if the service is not started.
     */
    public function values(string $path, mixed $body = null, mixed $context = null): Values
    {
        return $this->senderOrError()->values($path, $body, $context);
    }

    /**
     * Connects to the hub. Every (re)connect first asks the hub to prove its key
     * (see authHeaders), then sends hub/profile/update (if a profile is set) plus
     * hub/service/update with the current services+apps. A plain ws:// address
     * beyond loopback, the overlay and the LAN isn't dialed.
     */
    public function start(): self
    {
        if ($this->sender !== null) {
            return $this;
        }

        $this->lastError = null;
        // channel-php only encrypts wss://: it would dial https:// and quic:// as plain TCP.
        if (in_array(strtolower((string) parse_url((string) $this->address, PHP_URL_SCHEME)), ['https', 'quic'], true)) {
            $this->lastError = $this->target() . " would carry this service's key unencrypted: this client only "
                . 'encrypts wss://';
            error_log('hub-service: ' . $this->lastError);

            return $this;
        }
        if (!$this->allowPlaintext && HubProof::hubTransportOf($this->address) === HubProof::REFUSED) {
            $this->lastError = $this->target() . " would carry this service's key unencrypted. Use wss://, "
                . 'or set allowPlaintext (HUB_ALLOW_PLAINTEXT=1) on a private network';
            error_log('hub-service: ' . $this->lastError);

            return $this;
        }

        $service = $this;
        $this->sender = $this->channel->connect($this->address, [
            'headers' => static function () use ($service): array {
                // The client resolves the provider before every (re)connect.
                return $service->authHeaders();
            },
            'onConnect' => static function (Sender $sender) use ($service): void {
                // Own coroutine: channel-php calls onConnect before it starts
                // reading, so awaiting a response here would never return. It
                // yields first so the client's replay of pending requests,
                // right after onConnect, doesn't send these a second time.
                go(static function () use ($service, $sender): void {
                    Coroutine::usleep(1000);
                    $service->sendUpdates($sender);
                });
            },
        ]);

        return $this;
    }

    /**
     * Runs before every connection attempt (protocol.md section 2), inside a
     * coroutine. It comes back with a token over a fresh challenge from a hub
     * that proved its key; until one has, it holds the attempt back, so nothing
     * goes out and requests keep waiting. A stop makes it throw, which ends the
     * client's attempt.
     *
     * @return array<string, string>
     */
    public function authHeaders(): array
    {
        $generation = $this->generation;
        $delay = self::HANDSHAKE_RETRY;
        $reported = null;
        while (true) {
            try {
                $headers = $this->handshake(fn (): bool => $generation !== $this->generation);
                $this->lastError = null;

                return $headers;
            } catch (\Throwable $error) {
                $this->lastError = $error->getMessage();
                if ($this->lastError !== $reported) {
                    $reported = $this->lastError;
                    error_log('hub-service: ' . $reported);
                }
            }
            $deadline = microtime(true) + $delay;
            do {
                if ($generation !== $this->generation) {
                    throw new RuntimeException('Service stopped');
                }
                Coroutine::usleep(50_000);
            } while (microtime(true) < $deadline);
            $delay = min($delay * 2, self::HANDSHAKE_MAX_RETRY);
        }
    }

    /**
     * Why the service isn't connected, if it knows: a refused address, or a hub
     * that didn't prove its key or answers with another than the pinned one.
     */
    public function lastError(): ?string
    {
        return $this->lastError;
    }

    /**
     * Asks the hub for its proof and signs for that answer alone.
     *
     * @param callable(): bool $cancelled
     * @return array<string, string>
     */
    private function handshake(callable $cancelled): array
    {
        try {
            $proof = HubProof::ask($this->address, cancelled: $cancelled);
        } catch (\Throwable $error) {
            throw new RuntimeException($this->target() . ': ' . $error->getMessage() . ', sending it nothing', 0, $error);
        }
        $this->pinLoaded = false; // pick up a pin another process wrote
        $pinned = $this->hubKey();
        if ($pinned === null) {
            $this->pins()->set($this->target(), $proof['key']);
            $this->pinned = $proof['key'];
            $this->pinLoaded = true;
        } elseif ($pinned !== $proof['key']) {
            throw new RuntimeException(
                $this->target() . " answers with key {$proof['key']}, not the pinned $pinned, sending it nothing. "
                . 'forgetHubKey() if its key really changed',
            );
        }
        $token = (string) ($this->sign)($proof['key'], $proof['challenge']);

        $headers = ['auth' => $token, 'v' => Keychain::AUTH_VERSION];
        $this->serviceKey = explode('.', $token)[1] ?? null;
        if ($this->device !== null) {
            try {
                // The certificate names the key in the token, whoever signed it.
                $headers['device'] = $this->device->certificate(explode('.', $token)[1] ?? '', $this->instance());
            } catch (\Throwable) {
                // No readable or creatable device key: a plain key connection.
            }
        }

        return $headers;
    }

    /**
     * The instance name sent in the certificate: the option, else
     * ``HUB_INSTANCE`` (the launcher sets it), else the name, else the cwd
     * name, else ``service``; at most 128 UTF-8 bytes.
     */
    public function instance(): string
    {
        $env = getenv('HUB_INSTANCE');
        foreach ([$this->instance, $env === false ? null : $env, $this->profile['name'] ?? null, basename((string) getcwd())] as $value) {
            if ($value !== null && $value !== '') {
                $name = mb_strcut($value, 0, 128, 'UTF-8');

                return $name === '' ? 'service' : $name;
            }
        }

        return 'service';
    }

    /**
     * The hubs.json pin key for this hub.
     */
    public function target(): string
    {
        return Keychain::pinAddress($this->address);
    }

    /**
     * Pinned hub keys: ``hubs.json`` beside the service key file.
     */
    public function pins(): HubPins
    {
        return new HubPins(dirname(Keychain::keyPath()) . '/hubs.json');
    }

    /**
     * The hub key this service expects: supplied, else pinned, else null until
     * a hub proved one. The pin is read from hubs.json at each connect and kept
     * in memory.
     */
    public function hubKey(): ?string
    {
        if ($this->hubKey !== null) {
            return $this->hubKey;
        }
        if (!$this->pinLoaded) {
            $this->pinned = $this->pins()->get($this->target());
            $this->pinLoaded = true;
        }

        return $this->pinned;
    }

    /**
     * Clears the pinned hub key; the next connect pins what the hub proves.
     */
    public function forgetHubKey(): void
    {
        $this->hubKey = null;
        $this->pinned = null;
        $this->pins()->forget($this->target());
    }

    /**
     * Disconnects from the hub and stops reconnecting, ending a wait for its
     * proof.
     */
    public function stop(): void
    {
        $this->generation++;
        $this->sender?->stop();
        $this->sender = null;
    }

    /**
     * Builds the current hub/service/update payload: one services entry per
     * registered post/stream handler (sorted by path) plus the apps list.
     *
     * @return array{services: list<array<string, mixed>>, apps: list<AppHeader>}
     */
    public function update(): array
    {
        $paths = array_keys($this->paths);
        sort($paths, SORT_STRING);

        $services = [];
        foreach ($paths as $path) {
            $entry = ['path' => $path];
            $settings = $this->settings[$path] ?? null;
            if ($settings !== null) {
                if (isset($settings['permissions'])) {
                    $entry['permissions'] = $settings['permissions'];
                }
                if (array_key_exists('limit', $settings) && $settings['limit'] !== null) {
                    $entry['limit'] = $settings['limit'];
                }
            }
            $services[] = $entry;
        }

        return [
            'services' => $services,
            'apps' => array_map(static fn (AppHeader $header): array => $header->toArray(), $this->apps),
        ];
    }

    /**
     * The hub/profile/update payload (name/icon), or null when neither is set.
     *
     * @return array{name?: string, icon?: mixed}|null
     */
    public function profile(): ?array
    {
        return $this->profile;
    }

    private function senderOrError(): ClientSender
    {
        if ($this->sender === null) {
            throw new RuntimeException($this->lastError ?? 'Service not started');
        }

        return $this->sender;
    }

    private function sendUpdates(Sender $sender): void
    {
        try {
            if ($this->profile !== null) {
                $sender->send('hub/profile/update', $this->profile);
            }
        } catch (\Throwable) {
            // The connection dropped mid-send; the next connect re-sends it.
        }
        try {
            $sender->send('hub/service/update', $this->update());
        } catch (\Throwable) {
            // The connection dropped mid-send; the next connect re-sends it.
        }
        if ($this->network->hasShares()) {
            try {
                $this->network->republishAll($this->serviceKey(), $this->signChallenge, $sender);
            } catch (\Throwable $error) {
                error_log('Failed to republish network shares: ' . $error->getMessage());
            }
        }
    }

    /**
     * The key this service connects with (the key in its auth token).
     */
    public function serviceKey(): string
    {
        return $this->serviceKey ?? Keychain::publicKey();
    }

    /**
     * Declares a Hub Network share before start(): the declared set is
     * published on connect and after every reconnect. Default policy: private.
     *
     * @param array<string, mixed>|null $policy
     */
    public function share(string $name, string $protocol, string $host, int $port, ?array $policy = null): self
    {
        $this->network->declareShare(self::shareArray($name, $protocol, $host, $port, $policy));

        return $this;
    }

    /**
     * Publishes a local TCP/UDP port through Hub Network; returns every
     * publication (resourceId, authority, overlayAddress, port, ...).
     *
     * @param array<string, mixed>|null $policy
     * @return list<array<string, mixed>>
     */
    public function publishShare(string $name, string $protocol, string $host, int $port, ?array $policy = null): array
    {
        return $this->network->publishShare(
            self::shareArray($name, $protocol, $host, $port, $policy),
            $this->serviceKey(),
            $this->signChallenge,
            $this->senderOrError(),
        );
    }

    /**
     * Changes a share's policy or target port and republishes it.
     *
     * @param array<string, mixed>|null $policy
     * @return list<array<string, mixed>>
     */
    public function updateShare(string $name, ?array $policy = null, ?int $port = null): array
    {
        $current = null;
        foreach ($this->network->declaredShares() as $share) {
            if ($share['name'] === $name) {
                $current = $share;
            }
        }
        if ($current === null) {
            throw new RuntimeException("Share '$name' not found");
        }
        if ($policy !== null) {
            $current['policy'] = $policy;
        }
        if ($port !== null) {
            $current['target']['port'] = $port;
        }

        return $this->network->publishShare($current, $this->serviceKey(), $this->signChallenge, $this->senderOrError());
    }

    /**
     * Removes a share from Hub Network.
     *
     * @return list<array<string, mixed>>
     */
    public function removeShare(string $name): array
    {
        return $this->network->removeShare($name, $this->serviceKey(), $this->signChallenge, $this->senderOrError());
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function sharePublications(): array
    {
        return $this->network->publications();
    }

    /**
     * @return array<string, mixed>|null
     */
    public function sharePublication(string $name): ?array
    {
        return $this->network->publication($name);
    }

    /**
     * @param array<string, mixed>|null $policy
     * @return array<string, mixed>
     */
    private static function shareArray(string $name, string $protocol, string $host, int $port, ?array $policy): array
    {
        return [
            'name' => $name,
            'protocol' => $protocol,
            'target' => ['host' => $host, 'port' => $port],
            'policy' => $policy ?? ['mode' => 'private'],
        ];
    }

    /**
     * Adapts a ``(body)`` or ``(body, Request)`` handler to channel-php.
     */
    private function adapt(callable $handler): \Closure
    {
        if (self::wantsRequest($handler)) {
            return fn (array $request): mixed => $handler($request['body'] ?? null, Request::fromChannel($request, $this->hubKey()));
        }

        return static fn (array $request): mixed => $handler($request['body'] ?? null);
    }

    /**
     * Whether a handler's second parameter can take the Request: it exists and
     * is untyped, or typed to accept a Request (so ``'trim'`` gets the body only).
     */
    private static function wantsRequest(callable $handler): bool
    {
        $parameter = self::reflect($handler)->getParameters()[1] ?? null;
        if ($parameter === null) {
            return false;
        }
        $type = $parameter->getType();
        if ($type === null) {
            return true;
        }
        $types = $type instanceof \ReflectionUnionType ? $type->getTypes() : [$type];
        foreach ($types as $named) {
            if ($named instanceof \ReflectionNamedType && in_array($named->getName(), [Request::class, 'mixed', 'object'], true)) {
                return true;
            }
        }

        return false;
    }

    private static function reflect(callable $callable): \ReflectionFunctionAbstract
    {
        return is_array($callable)
            ? new \ReflectionMethod($callable[0], $callable[1])
            : (is_string($callable) && str_contains($callable, '::')
                ? new \ReflectionMethod($callable)
                : new \ReflectionFunction(\Closure::fromCallable($callable)));
    }

    private function addPath(string $path, array $settings): void
    {
        $this->paths[$path] = true;

        if ($settings === []) {
            return;
        }

        if (isset($settings['permissions']) && is_array($settings['permissions'])) {
            $permissions = $settings['permissions'];
            if (!isset($permissions['group']) || $permissions['group'] === '') {
                $permissions['group'] = explode('/', $path)[0];
            }
            // Wire order: group, name, allows.
            $ordered = ['group' => $permissions['group']];
            if (isset($permissions['name'])) {
                $ordered['name'] = $permissions['name'];
            }
            if (array_key_exists('allows', $permissions)) {
                $ordered['allows'] = $permissions['allows'];
            }
            $settings['permissions'] = $ordered;
        }

        $this->settings[$path] = $settings;
    }
}
