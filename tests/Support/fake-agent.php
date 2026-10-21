<?php

declare(strict_types=1);

// The hub-net agent's /challenge and /attest on a Unix socket, for the tests.
// Usage: php fake-agent.php <socket path> <fresh|expired>

[, $path, $mode] = $argv;
@unlink($path);
$server = stream_socket_server('unix://' . $path, $code, $message);
if ($server === false) {
    fwrite(STDERR, "fake agent: $message\n");
    exit(1);
}
$nonces = [];
pcntl_async_signals(true);
pcntl_signal(SIGTERM, static function () use ($path): void {
    @unlink($path);
    exit(0);
});

while ($client = @stream_socket_accept($server, -1)) {
    $raw = '';
    while (!str_contains($raw, "\r\n\r\n")) {
        $raw .= (string) fread($client, 4096);
    }
    [$head, $body] = explode("\r\n\r\n", $raw, 2);
    preg_match('/content-length: *(\d+)/i', $head, $m);
    while (strlen($body) < (int) $m[1]) {
        $body .= (string) fread($client, 4096);
    }
    $request = json_decode($body, true);
    $route = explode(' ', $head)[1];
    $name = $request['shareName'];
    $status = 200;
    if ($route === '/challenge') {
        $nonces[$name] = "nonce-$name";
        $reply = json_encode(['nonce' => $nonces[$name]]);
    } elseif ($route === '/attest') {
        $signature = (string) base64_decode($request['signature']);
        $valid = strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES && sodium_crypto_sign_verify_detached(
            $signature,
            $nonces[$name] ?? '',
            substr((string) base64_decode($request['serviceKey']), 12),
        );
        $issued = time() - ($mode === 'expired' ? 600 : 0);
        $reply = $valid ? json_encode([
            'version' => 1, 'attestationId' => "att-$name", 'serviceKey' => $request['serviceKey'],
            'key' => 'agent-key', 'shareName' => $name, 'protocol' => $request['protocol'],
            'target' => $request['target'], 'issuedAt' => gmdate('Y-m-d\TH:i:s\Z', $issued),
            'expiresAt' => gmdate('Y-m-d\TH:i:s\Z', $issued + 300), 'signature' => 'c2lnbmF0dXJl',
        ], JSON_UNESCAPED_SLASHES) : 'bad signature';
        $status = $valid ? 200 : 403;
    } else {
        [$status, $reply] = [404, 'not found'];
    }
    fwrite($client, "HTTP/1.1 $status OK\r\nContent-Length: " . strlen($reply) . "\r\n\r\n" . $reply);
    fclose($client);
}
