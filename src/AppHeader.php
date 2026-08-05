<?php

declare(strict_types=1);

namespace HubServicePhp;

/**
 * Identifies an app in the hub apps list (one entry of the hub/service/update
 * apps array). Serialized as {"type":"app","name":...,"path":...}.
 */
final class AppHeader
{
    public function __construct(
        public string $type = 'app',
        public string $name = '',
        public string $path = '',
    ) {
    }
}
