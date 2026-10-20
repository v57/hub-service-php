<?php

declare(strict_types=1);

namespace HubServicePhp;

use RuntimeException;

/**
 * Device key and service certificates (Docs/Devices/protocol.md).
 *
 * - The device key lives in ``~/.hub/device.key`` (``/var/lib/hub/device.key``
 *   for a Linux system service, ``HUB_DEVICE_KEY`` overrides both) in the same
 *   layout as the ``auth`` file. It is created atomically on first use.
 * - A service certificate is ``<base64url(JSON)>.<base64 signature>``, signed by
 *   the device key over the payload string, and sent in the ``device`` header.
 *   It names the service key, the instance and the device's suggested name.
 *
 * Usage::
 *
 *     $device = new Device();                  // ~/.hub/device.key
 *     $header = $device->certificate($serviceKey, 's3-local/Backup Disk');
 */
final class Device
{
    /** Certificates live up to 7 days and are renewed at connect with < 24 h left. */
    public const CERTIFICATE_LIFETIME = 7 * 24 * 3600;

    public const CERTIFICATE_RENEWAL = 24 * 3600;

    private ?string $key;

    private ?string $name;

    public readonly string $platform;

    /** @var array<string, string> */
    private array $certificates = [];

    /**
     * @param string|null $path     the key file (default: Device::defaultKeyPath())
     * @param string|null $key      key file bytes to use instead of a file (tests, or a key kept in another store)
     * @param string|null $name     suggested device name (default: the computer name)
     * @param string|null $platform protocol platform string (default: from the OS)
     * @param string|null $parent   declared parent device name, for containers and VMs
     */
    public function __construct(
        private readonly ?string $path = null,
        ?string $key = null,
        ?string $name = null,
        ?string $platform = null,
        public readonly ?string $parent = null,
    ) {
        $this->key = $key;
        $this->name = $name;
        $this->platform = $platform ?? self::defaultPlatform();
    }

    /**
     * ``HUB_DEVICE_KEY``, else the system or user location.
     */
    public static function defaultKeyPath(): string
    {
        $env = getenv('HUB_DEVICE_KEY');
        if ($env !== false && $env !== '') {
            return $env;
        }
        if (PHP_OS_FAMILY === 'Linux' && function_exists('posix_geteuid') && posix_geteuid() === 0) {
            return '/var/lib/hub/device.key';
        }
        $home = getenv('HOME') ?: (function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['dir'] ?? '') : '');

        return rtrim((string) $home, '/') . '/.hub/device.key';
    }

    /**
     * First 32 hex characters of SHA-256 over the device SPKI DER.
     */
    public static function deviceId(string $publicKey): string
    {
        return substr(hash('sha256', base64_decode($publicKey, true) ?: ''), 0, 32);
    }

    /**
     * The code shown on both sides when approving a device: ``"ddd ddd"``.
     */
    public static function safetyCode(string $publicKey): string
    {
        $n = hexdec(substr(hash('sha256', base64_decode($publicKey, true) ?: ''), 0, 8)) % 1_000_000;

        return sprintf('%03d %03d', intdiv($n, 1000), $n % 1000);
    }

    public static function defaultPlatform(): string
    {
        return match (PHP_OS_FAMILY) {
            'Darwin' => 'macos',
            'Linux' => 'linux',
            'Windows' => 'windows',
            default => 'other',
        };
    }

    /**
     * The macOS computer name, else the host name.
     */
    public static function defaultName(): string
    {
        if (PHP_OS_FAMILY === 'Darwin') {
            $name = trim((string) @shell_exec('scutil --get ComputerName 2>/dev/null'));
            if ($name !== '') {
                return $name;
            }
        }
        $name = (string) gethostname();

        return $name === '' ? 'device' : preg_replace('/\.local$/', '', $name);
    }

    /**
     * A service certificate from device key file bytes, fields in protocol
     * order with no whitespace.
     */
    public static function issue(
        string $deviceKey,
        string $service,
        string $instance,
        int $iat,
        int $exp,
        ?string $deviceName = null,
        ?string $platform = null,
        ?string $parent = null,
    ): string {
        if (strlen($instance) < 1 || strlen($instance) > 128) {
            throw new RuntimeException('instance must be 1-128 UTF-8 bytes');
        }
        if ($parent !== null && strlen($parent) > 64) {
            throw new RuntimeException('parent must be at most 64 UTF-8 bytes');
        }

        $payload = ['v' => 1, 'device' => Keychain::spki($deviceKey), 'service' => $service, 'instance' => $instance];
        if ($deviceName !== null) {
            $payload['deviceName'] = $deviceName;
        }
        if ($platform !== null) {
            $payload['platform'] = $platform;
        }
        if ($parent !== null) {
            $payload['parent'] = $parent;
        }
        $payload['iat'] = $iat;
        $payload['exp'] = $exp;
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        $encoded = rtrim(strtr(base64_encode($json), '+/', '-_'), '=');

        return $encoded . '.' . Keychain::signData($deviceKey, $encoded);
    }

    /**
     * The ``exp`` of a certificate header.
     */
    public static function certificateExpiry(string $header): int
    {
        $payload = explode('.', $header, 2)[0];
        $json = base64_decode(strtr($payload, '-_', '+/'), true);
        $data = json_decode((string) $json, true);

        return (int) ($data['exp'] ?? 0);
    }

    /**
     * Device key file bytes, loaded or created on first use.
     */
    public function key(): string
    {
        return $this->key ??= Keychain::loadKeyFile($this->path ?? self::defaultKeyPath(), private: true);
    }

    public function name(): string
    {
        // At most 64 UTF-8 bytes, cut on a character boundary.
        return $this->name ??= mb_strcut(self::defaultName(), 0, 64, 'UTF-8');
    }

    public function publicKey(): string
    {
        return Keychain::spki($this->key());
    }

    public function id(): string
    {
        return self::deviceId($this->publicKey());
    }

    public function safety(): string
    {
        return self::safetyCode($this->publicKey());
    }

    /**
     * The certificate for a service key, renewed with < 24 h left.
     */
    public function certificate(string $service, string $instance, ?int $now = null): string
    {
        $now ??= time();
        $id = $service . "\n" . $instance;
        $cached = $this->certificates[$id] ?? null;
        if ($cached !== null && self::certificateExpiry($cached) - $now >= self::CERTIFICATE_RENEWAL) {
            return $cached;
        }

        return $this->certificates[$id] = self::issue(
            $this->key(),
            $service,
            $instance,
            $now,
            $now + self::CERTIFICATE_LIFETIME,
            $this->name(),
            $this->platform,
            $this->parent,
        );
    }
}
