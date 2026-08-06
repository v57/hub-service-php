#!/usr/bin/env php
<?php

declare(strict_types=1);

// Echo service: hosts post endpoints (echo, echo/upper) and an app UI on a
// hub (default ws://127.0.0.1:1997, or $HUB). For hub-pro, an ``auth`` file
// (ed25519 keychain) in the working directory is loaded and a signed token is
// attached to every connect. Run:
//   php example/echo.php
// then call it through the hub from any language:
//   bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
//   bun ../hub-service/tests/appcheck.ts echo/ui Echo

require dirname(__DIR__) . '/vendor/autoload.php';

use HubServicePhp\App;
use HubServicePhp\AppHeader;
use HubServicePhp\Service;
use OpenSwoole\Coroutine;

Coroutine::run(static function (): void {
    $service = new Service([
        'name' => 'Echo',
        'icon' => ['symbol' => 'speaker.wave.2', 'text' => 'E'],
    ]);

    $service
        ->post('echo', static fn (mixed $body): mixed => $body)
        ->post('echo/upper', static fn (mixed $body): string => strtoupper((string) $body))
        ->app(new App(
            new AppHeader('Echo', 'echo/ui'),
            [
                'Hello from PHP',
                App::textField('echo', 'Text to echo', App::action('echo/upper', 'value', 'value')),
                App::cell('$Echo', 'value'),
                App::button('Upper', App::action('echo/upper', 'value', 'value')),
            ],
            ['hello' => 'world'],
        ))
        ->start();

    $hub = getenv('HUB');
    fwrite(STDOUT, 'echo service started (' . ($hub !== false && $hub !== '' ? $hub : 'hub :1997') . ")\n");

    // Keep the OpenSwoole event loop alive; the client coroutine does the rest.
    while (true) {
        Coroutine::usleep(1_000_000);
    }
});
