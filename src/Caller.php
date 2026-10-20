<?php

declare(strict_types=1);

namespace HubServicePhp;

/**
 * Who is calling, as the hub saw it (``context.hub.caller``,
 * Docs/Devices/protocol.md §4). ``key`` is null for anonymous callers,
 * ``device`` null for clients without one; ``via`` and ``claimed`` are set for
 * calls through a merged hub (``claimed`` is unverified).
 */
final class Caller
{
    /**
     * @param list<string> $groups every group the key or its device belongs to
     */
    public function __construct(
        public readonly ?string $key = null,
        public readonly ?CallerDevice $device = null,
        public readonly array $groups = [],
        public readonly bool $owner = false,
        public readonly ?string $via = null,
        public readonly ?Caller $claimed = null,
    ) {
    }

    public static function parse(mixed $value): ?self
    {
        if (!is_array($value)) {
            return null;
        }
        $device = $value['device'] ?? null;
        $groups = $value['groups'] ?? null;

        return new self(
            key: is_string($value['key'] ?? null) ? $value['key'] : null,
            device: is_array($device) ? new CallerDevice((string) ($device['id'] ?? ''), (string) ($device['name'] ?? '')) : null,
            groups: is_array($groups) ? array_values(array_filter($groups, 'is_string')) : [],
            owner: ($value['owner'] ?? null) === true,
            via: is_string($value['via'] ?? null) ? $value['via'] : null,
            claimed: self::parse($value['claimed'] ?? null),
        );
    }
}
