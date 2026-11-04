<?php

declare(strict_types=1);

namespace HubServicePhp;

use ChannelPhp\Channel;
use OpenSwoole\Coroutine;
use RuntimeException;

/**
 * Auth v2's client side (Docs/Devices/protocol.md section 2): before every
 * connect the service asks hub/info on an anonymous connection with a fresh
 * nonce, and sends its token only if the hub proved the key it claims, over
 * that nonce.
 */
final class HubProof
{
    public const ENCRYPTED = 'encrypted';

    public const LOOPBACK = 'loopback';

    public const OVERLAY = 'overlay';

    public const LOCAL_NETWORK = 'localNetwork';

    /** Plain ws:// beyond loopback, the overlay and the LAN: not dialed unless ``allowPlaintext`` says so. */
    public const REFUSED = 'refused';

    private const SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

    /**
     * Classifies an address before anything is dialed.
     */
    public static function hubTransportOf(int|string $address): string
    {
        if (is_int($address) || ctype_digit($address)) {
            return self::LOOPBACK;
        }
        if (preg_match('#^([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/?\#@]*@)?(\[[^\]]*\]|[^/?\#:]*)#', $address, $match) !== 1) {
            return self::REFUSED;
        }
        $scheme = strtolower($match[1]);
        $host = strtolower($match[2]);
        if (str_ends_with($host, '.')) {
            $host = substr($host, 0, -1);
        }
        if (in_array($scheme, ['wss', 'https', 'quic'], true)) {
            return self::ENCRYPTED;
        }
        if ($scheme !== 'ws' && $scheme !== 'http') {
            return self::REFUSED;
        }
        if (str_starts_with($host, '[')) {
            $v6 = substr($host, 1, -1);
            if ($v6 === '::1') {
                return self::LOOPBACK;
            }

            return preg_match('/^(f[cd]|fe[89ab])/', $v6) === 1 ? self::LOCAL_NETWORK : self::REFUSED;
        }
        $v4 = self::ipv4($host);
        if ($v4 !== null) {
            [$a, $b] = $v4;
            if ($a === 127) {
                return self::LOOPBACK;
            }
            if ($a === 100 && $b >= 64 && $b <= 127) {
                return self::OVERLAY;
            }
            if ($a === 10 || ($a === 172 && $b >= 16 && $b <= 31) || ($a === 192 && $b === 168) || ($a === 169 && $b === 254)) {
                return self::LOCAL_NETWORK;
            }

            return self::REFUSED;
        }
        if ($host === 'localhost' || str_ends_with($host, '.localhost')) {
            return self::LOOPBACK;
        }
        if (str_ends_with($host, '.hub.invalid')) {
            return self::OVERLAY;
        }

        return str_ends_with($host, '.local') ? self::LOCAL_NETWORK : self::REFUSED;
    }

    /**
     * The nonce for one hub/info: 32 fresh random bytes in base64url.
     */
    public static function makeClientNonce(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * The string a hub/info proof signs.
     */
    public static function signedData(string $hubKey, string $nonce): string
    {
        return "hubinfo1:$hubKey:$nonce";
    }

    /**
     * Whether a hub/info answer proves its key over $nonce. A relayed answer
     * passes too, so it never decides which credentials a hub gets.
     */
    public static function verify(mixed $info, string $nonce): bool
    {
        if (!is_array($info)) {
            return false;
        }
        $key = $info['key'] ?? null;
        $proof = $info['proof'] ?? null;
        if (!is_string($key) || !is_string($proof) || !is_string($info['challenge'] ?? null)) {
            return false;
        }
        $spki = base64_decode($key, true);
        $signature = base64_decode($proof, true);
        if ($spki === false || $signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || strlen($spki) !== 44 || !str_starts_with($spki, self::SPKI_PREFIX)) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, self::signedData($key, $nonce), substr($spki, 12));
    }

    /**
     * Asks the hub at $address for its key and a challenge, on a short
     * anonymous connection, and returns the answer only with a valid proof.
     * Call it inside a coroutine. $cancelled ends the wait early.
     *
     * @param (callable(): bool)|null $cancelled
     * @return array{key: string, challenge: string}
     */
    public static function ask(int|string $address, float $timeout = 5.0, ?callable $cancelled = null): array
    {
        $nonce = self::makeClientNonce();
        $channel = new Channel();
        $probe = $channel->connect($address);
        $done = new Coroutine\Channel(1);
        go(static function () use ($probe, $nonce, $done): void {
            try {
                $done->push([true, $probe->send('hub/info', ['nonce' => $nonce])]);
            } catch (\Throwable $error) {
                $done->push([false, $error->getMessage()]);
            }
        });
        $deadline = microtime(true) + $timeout;
        do {
            $result = $done->pop(0.05);
        } while ($result === false && microtime(true) < $deadline && ($cancelled === null || !$cancelled()));
        $probe->stop();
        // Stopping leaves a call that got no answer waiting, and its coroutine with it.
        foreach ($channel->requests as $request) {
            $channel->failRequests($request->sender, 'hub/info timed out');
        }
        if ($result === false) {
            throw new RuntimeException('hub/info timed out');
        }
        [$answered, $info] = $result;
        if (!$answered) {
            throw new RuntimeException((string) $info);
        }
        if (!self::verify($info, $nonce)) {
            throw new RuntimeException("hub didn't prove its key");
        }

        return ['key' => $info['key'], 'challenge' => $info['challenge']];
    }

    /**
     * @return array{int, int, int, int}|null
     */
    private static function ipv4(string $host): ?array
    {
        $parts = explode('.', $host);
        if (count($parts) !== 4) {
            return null;
        }
        $bytes = [];
        foreach ($parts as $part) {
            if (preg_match('/^[0-9]{1,3}$/', $part) !== 1 || (int) $part > 255) {
                return null;
            }
            $bytes[] = (int) $part;
        }

        return $bytes;
    }
}
