<?php

declare(strict_types=1);

namespace HubServicePhp;

/** The caller's device, when its connection is device-attached. */
final class CallerDevice
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
    ) {
    }
}
