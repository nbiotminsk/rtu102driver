<?php

declare(strict_types=1);

namespace RtuReceiver;

use InvalidArgumentException;

final class Config
{
    public string $listenHost;
    public int $listenPort;
    public string $logDir;
    public bool $decodeEnabled;
    public ?string $defaultKey;

    /**
     * @var array<string, string>
     */
    public array $keysByImei;

    /**
     * @param array<string, mixed> $raw
     */
    private function __construct(array $raw)
    {
        $this->listenHost = self::expectString($raw, 'listen_host', '127.0.0.1');
        $this->listenPort = self::expectInt($raw, 'listen_port', 5000);
        if ($this->listenPort < 1 || $this->listenPort > 65535) {
            throw new InvalidArgumentException('listen_port must be in range 1..65535');
        }

        $this->logDir = self::expectString($raw, 'log_dir', './logs');
        $this->decodeEnabled = self::expectBool($raw, 'decode_enabled', true);

        $keys = $raw['keys'] ?? [];
        if (!is_array($keys)) {
            throw new InvalidArgumentException('keys must be an object');
        }

        $defaultHex = $keys['default_hex'] ?? null;
        $this->defaultKey = self::parseHexKey($defaultHex, 'keys.default_hex', true);

        $byImei = $keys['by_imei'] ?? [];
        if (!is_array($byImei)) {
            throw new InvalidArgumentException('keys.by_imei must be an object');
        }

        $this->keysByImei = [];
        foreach ($byImei as $imei => $hex) {
            if (!is_string($imei) || $imei === '' || !ctype_digit($imei)) {
                throw new InvalidArgumentException('keys.by_imei keys must be digit IMEI strings');
            }
            $parsed = self::parseHexKey($hex, "keys.by_imei[$imei]", false);
            if ($parsed === null) {
                throw new InvalidArgumentException("keys.by_imei[$imei] cannot be null");
            }
            $this->keysByImei[$imei] = $parsed;
        }
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new InvalidArgumentException("config file not found: $path");
        }

        $rawText = file_get_contents($path);
        if ($rawText === false) {
            throw new InvalidArgumentException("cannot read config file: $path");
        }

        /** @var mixed $decoded */
        $decoded = json_decode($rawText, true);
        if (!is_array($decoded)) {
            throw new InvalidArgumentException('invalid JSON config');
        }

        return new self($decoded);
    }

    public function resolveKey(string $imei): ?string
    {
        if (array_key_exists($imei, $this->keysByImei)) {
            return $this->keysByImei[$imei];
        }
        return $this->defaultKey;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function expectString(array $raw, string $key, string $default): string
    {
        $value = $raw[$key] ?? $default;
        if (!is_string($value) || $value === '') {
            throw new InvalidArgumentException("$key must be non-empty string");
        }
        return $value;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function expectInt(array $raw, string $key, int $default): int
    {
        $value = $raw[$key] ?? $default;
        if (!is_int($value)) {
            throw new InvalidArgumentException("$key must be integer");
        }
        return $value;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function expectBool(array $raw, string $key, bool $default): bool
    {
        $value = $raw[$key] ?? $default;
        if (!is_bool($value)) {
            throw new InvalidArgumentException("$key must be boolean");
        }
        return $value;
    }

    private static function parseHexKey(mixed $value, string $field, bool $nullable): ?string
    {
        if ($value === null) {
            if ($nullable) {
                return null;
            }
            throw new InvalidArgumentException("$field cannot be null");
        }

        if (!is_string($value)) {
            throw new InvalidArgumentException("$field must be hex string");
        }
        if (strlen($value) !== 32) {
            throw new InvalidArgumentException("$field must be 32 hex chars");
        }
        if (!ctype_xdigit($value)) {
            throw new InvalidArgumentException("$field must contain valid hex chars");
        }

        $bin = hex2bin($value);
        if ($bin === false || strlen($bin) !== 16) {
            throw new InvalidArgumentException("$field must decode to 16 bytes");
        }

        return $bin;
    }
}
