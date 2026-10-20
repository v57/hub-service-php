<?php

declare(strict_types=1);

namespace HubServicePhp;

use RuntimeException;

/**
 * Hub keys pinned per address in ``hubs.json`` (beside the service key file):
 * ``{"<address>": "<hub SPKI>"}`` (Docs/Devices/protocol.md §2).
 */
final class HubPins
{
    public function __construct(public readonly string $path)
    {
    }

    public function get(string $address): ?string
    {
        $value = $this->load()[$address] ?? null;

        return is_string($value) ? $value : null;
    }

    public function set(string $address, string $hubKey): void
    {
        $pins = $this->load();
        $pins[$address] = $hubKey;
        $this->write($pins);
    }

    public function forget(string $address): void
    {
        $pins = $this->load();
        if (array_key_exists($address, $pins)) {
            unset($pins[$address]);
            $this->write($pins);
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function load(): array
    {
        if (!is_file($this->path)) {
            return [];
        }
        $data = json_decode((string) file_get_contents($this->path), true);

        return is_array($data) ? $data : [];
    }

    /**
     * @param array<string, mixed> $pins
     */
    private function write(array $pins): void
    {
        $dir = dirname($this->path);
        if (!is_dir($dir) && !@mkdir($dir, 0777, true) && !is_dir($dir)) {
            throw new RuntimeException("Cannot create directory: $dir");
        }
        $temp = tempnam($dir, '.hubs.');
        if ($temp === false) {
            throw new RuntimeException("Cannot write hub pins: {$this->path}");
        }
        $json = json_encode((object) $pins, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        file_put_contents($temp, $json);
        rename($temp, $this->path);
    }
}
