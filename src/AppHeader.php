<?php

declare(strict_types=1);

namespace HubServicePhp;

/**
 * Identifies an app in the hub apps list (one entry of the hub/service/update
 * apps array). Serialized as {"type":"app","name":...,"path":...} — see
 * toArray(), which emits the exact wire key order.
 */
final class AppHeader
{
    public function __construct(
        public string $name,
        public string $path,
        public string $type = 'app',
    ) {
    }

    /**
     * Wire-shape payload: type, name, path (matches the TS reference order).
     *
     * @return array{type: string, name: string, path: string}
     */
    public function toArray(): array
    {
        return ['type' => $this->type, 'name' => $this->name, 'path' => $this->path];
    }
}
