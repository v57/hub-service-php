<?php

declare(strict_types=1);

// A hub for the live tests, run as its own PHP process (see FakeHub).
// Usage: php fake-hub.php <port> <log file> <pro|lite> [caller <results file>]

use ChannelPhp\Channel;

require __DIR__ . '/../../vendor/autoload.php';

[, $port, $log, $mode] = $argv;
$scenario = $argv[4] ?? 'none';
$results = $argv[5] ?? '';
$hubKey = 'MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=';

$append = static function (array $entry) use ($log): void {
    file_put_contents($log, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);
};

$channel = new Channel();
if ($mode !== 'lite') {
    $channel->post('hub/info', static fn (): array => [
        'key' => $hubKey, 'protocol' => 1, 'pro' => true, 'mode' => 'default-allow',
    ]);
}
foreach (['hub/profile/update', 'hub/service/update'] as $path) {
    $channel->post($path, static function (array $request) use ($append, $path): mixed {
        $append(['path' => $path, 'body' => $request['body'] ?? null]);
        return null;
    });
}
$channel->post('network/shares/replace', static function (array $request) use ($append): array {
    $append(['replaced' => $request['body']]);
    return ['shares' => array_map(static fn (array $share): array => [
        'version' => 1, 'resourceId' => 'hnr1_' . $share['name'], 'authority' => $share['name'] . '.hub.invalid',
        'providerId' => 'provider', 'protocol' => $share['protocol'], 'overlayAddress' => '100.96.0.2',
        'port' => $share['target']['port'],
    ], $request['body']['shares'])];
});
if ($scenario === 'caller') {
    // Calls the service back with the vectors' caller context.
    $vectors = json_decode((string) file_get_contents(__DIR__ . '/../../../../Docs/Devices/vectors.json'), true);
    $context = $vectors['caller']['context'];
    $channel->post('test/run', static function (array $request) use ($context, $results): mixed {
        $sender = $request['sender'];
        file_put_contents($results, json_encode([
            'post' => $sender->send('whoami', 'hi', $context),
            'plain' => $sender->send('echo', 'hi', $context),
            'internal' => $sender->send('trim', ' hi ', $context),
            'stream' => iterator_to_array($sender->values('whoami/values', null, $context), false),
            'anonymous' => $sender->send('whoami', 'hi', ['service' => 'x']),
            'spoofed' => $sender->send('whoami', 'hi', ['hub' => ['hubKey' => 'OTHER'] + $context['hub']]),
        ]));
        return true;
    });
}

$server = $channel->listen('127.0.0.1:' . $port, [
    'state' => static function (array $headers) use ($append): \stdClass {
        $append(['headers' => $headers]);
        return new \stdClass();
    },
]);
pcntl_signal(SIGTERM, static function () use ($server): void {
    $server->stop();
    exit(0);
});
while (true) {
    pcntl_signal_dispatch();
    usleep(50_000);
}
