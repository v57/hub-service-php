<?php

declare(strict_types=1);

// A hub for the live tests, run as its own PHP process (see FakeHub).
// Usage: php fake-hub.php <port> <log file> <proof|no-proof|another-signs|another-key> [caller <results file>]

use ChannelPhp\Channel;
use HubServicePhp\HubProof;
use HubServicePhp\Keychain;

require __DIR__ . '/../../vendor/autoload.php';

[, $port, $log, $answer] = $argv;
$scenario = $argv[4] ?? 'none';
$results = $argv[5] ?? '';
$vectors = json_decode((string) file_get_contents(__DIR__ . '/../../../../Docs/Devices/vectors.json'), true);
$hub = $vectors['keys']['hub'];
$other = $vectors['keys']['service'];

$append = static function (array $entry) use ($log): void {
    file_put_contents($log, json_encode($entry) . "\n", FILE_APPEND | LOCK_EX);
};

$channel = new Channel();
$channel->post('hub/info', static function (array $request) use ($answer, $hub, $other, $append): array {
    $nonce = $request['body']['nonce'] ?? '';
    $append(['nonce' => $nonce]);
    $signer = $answer === 'proof' || $answer === 'no-proof' ? $hub : $other;
    $key = $answer === 'another-key' ? $other : $hub;
    $info = ['key' => $key['publicKey'], 'protocol' => 2, 'challenge' => 'challenge-' . bin2hex(random_bytes(8))];
    if ($answer !== 'no-proof') {
        $info['proof'] = Keychain::signData(Keychain::decodeKeyFile($signer['keyFile']), HubProof::signedData($key['publicKey'], $nonce));
    }
    return $info;
});
$channel->post('test/echo', static fn (array $request): mixed => $request['body'] ?? null);
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
