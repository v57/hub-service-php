<?php

declare(strict_types=1);

// Keep every test off the real ~/.hub/device.key.
$deviceDir = sys_get_temp_dir() . '/hub-device-php-' . bin2hex(random_bytes(4));
putenv('HUB_DEVICE_KEY=' . $deviceDir . '/device.key');
register_shutdown_function(static function () use ($deviceDir): void {
    exec('rm -rf ' . escapeshellarg($deviceDir));
});

require __DIR__ . '/../vendor/autoload.php';
