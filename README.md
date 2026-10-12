<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-php
</h1>

PHP port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`, or
`$HUB`), host your own post/stream API endpoints, register apps, and call API
through the hub.

Lite port: no auth, no keychain, no crypto (hub-pro territory). The wire
contract matches the TS reference (`hub/profile/update`, `hub/service/update`,
AppInterface + element DSL).

Built on [channel-php](https://github.com/v57/channel-php) (OpenSwoole
coroutines; PHP ^8.3 + ext-openswoole).

## Install

```bash
composer require v57/hub-service-php
```

In this monorepo the dependency is wired by path:

```json
{
  "repositories": [
    { "type": "path", "url": "../../Channel/channel-php", "options": { "symlink": true } }
  ],
  "require": { "dimas/channel-php": "dev-main" }
}
```

## Usage

Start a hub first (`new Hub()` from hub-lite, listens on 1997), then:

```php
<?php
require 'vendor/autoload.php';

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
});
```

Call it through the hub (any language):

```php
$response = $service->send('echo/upper', 'hello'); // "HELLO"
```

## API

- `new Service(array $options = [])` — `address` (port or `ws://` URL; default
  `1997` or `$HUB`), `name`, `icon` (string or `['symbol'=>..,'text'=>..]`)
- `post(string $path, callable $handler, array $settings = []): self`
  — handler receives the decoded request body, returns the response value
- `stream(string $path, callable $handler, array $settings = []): self`
  — handler receives the body, returns a `\Generator` of streamed values
- `app(App $app): self` — app header goes to the hub apps list; the app path
  streams the AppInterface (header + body + top + bottom + data)
- `send(string $path, mixed $body = null, mixed $context = null): mixed`
  — client call through the hub (throws `Service not started` before `start()`)
- `values(string $path, mixed $body = null, mixed $context = null): Values`
  — stream call through the hub
- `start(): self` — connect; re-announces `hub/profile/update` (if set) and
  `hub/service/update` on every (re)connect (the hub drops services on
  disconnect)

`$settings` carries `permissions` (`group` auto-filled from the first path
segment, TS parity), `allows`, and `limit` — wire-parity fields that hub-lite
ignores. Element helpers (`App::text`, `progress`, `textField`, `button`,
`slider`, `list`, `picker`, `cell`, `files`, `fileOperation`, `hstack`,
`vstack`, `zstack`, `spacer`, `action`) produce the TS app.ts wire shapes.

## Test

```bash
./scripts/test                  # unit tests (phpunit)
php example/echo.php            # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
bun ../hub-service/tests/appcheck.ts echo/ui Echo
```
