<?php

declare(strict_types=1);

namespace HubServicePhp;

use ChannelPhp\Channel;
use ChannelPhp\ClientSender;
use ChannelPhp\Sender;
use ChannelPhp\Values;
use Generator;
use RuntimeException;

/**
 * Service registers API endpoints on a hub and serves calls forwarded by it.
 *
 * Port of hub-service (TS reference): on every (re)connect the service sends
 * hub/profile/update (if a profile is set) and hub/service/update with the
 * current services + apps lists. For hub-pro, an ``auth`` header with a fresh
 * keychain token (plus ``v: '0'``) is attached to every connect — the hub
 * drops services on disconnect, so both the auth token and the updates are
 * re-issued on each reconnect.
 */
final class Service
{
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

    /** @var callable(int): string */
    private $sign;

    /**
     * @param array{address?: int|string, name?: string, icon?: mixed, sign?: callable(int): string} $options
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
     * Registers a request/response API endpoint.
     *
     * @param callable(mixed): mixed $handler
     * @param array{permissions?: array{group?: string, name?: string, allows?: bool}, limit?: mixed} $settings
     */
    public function post(string $path, callable $handler, array $settings = []): self
    {
        $this->addPath($path, $settings);
        $this->channel->post($path, static function (array $request) use ($handler): mixed {
            return $handler($request['body'] ?? null);
        });

        return $this;
    }

    /**
     * Registers a streaming API endpoint. The handler receives the request body
     * and returns a \Generator whose yielded values are streamed to the caller.
     *
     * @param callable(mixed): \Generator $handler
     * @param array{permissions?: array{group?: string, name?: string, allows?: bool}, limit?: mixed} $settings
     */
    public function stream(string $path, callable $handler, array $settings = []): self
    {
        $this->addPath($path, $settings);
        $this->channel->stream($path, static function (array $request) use ($handler): mixed {
            return $handler($request['body'] ?? null);
        });

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
     * Connects to the hub. On every (re)connect it attaches a fresh auth token
     * (hub-pro) and sends hub/profile/update (if a profile is set) plus
     * hub/service/update with the current services+apps.
     */
    public function start(): self
    {
        if ($this->sender !== null) {
            return $this;
        }

        $service = $this;
        $this->sender = $this->channel->connect($this->address, [
            'headers' => static function () use ($service): array {
                // Fresh token per connect: the client resolves the provider on
                // every (re)connect, so each upgrade carries a new signature.
                return ['auth' => ($service->sign)(10), 'v' => '0'];
            },
            'onConnect' => static function (Sender $sender) use ($service): void {
                $service->sendUpdates($sender);
            },
        ]);

        return $this;
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
            throw new RuntimeException('Service not started');
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
            // hub-lite always responds; ignore failures to keep reconnects going.
        }
        $sender->send('hub/service/update', $this->update());
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
