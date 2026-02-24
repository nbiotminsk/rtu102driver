<?php

declare(strict_types=1);

namespace RtuReceiver;

use InvalidArgumentException;

final class Xtea
{
    private const DELTA = 0x9E3779B9;
    private const MASK32 = 0xFFFFFFFF;

    /**
     * @return array<int, int>
     */
    private static function keyWordsLe(string $key16): array
    {
        if (strlen($key16) !== 16) {
            throw new InvalidArgumentException('XTEA key must be 16 bytes');
        }
        /** @var array<int, int> $words */
        $words = array_values(unpack('V4', $key16));
        return $words;
    }

    public static function decryptBlockLe(string $block8, string $key16, int $rounds = 32): string
    {
        if (strlen($block8) !== 8) {
            throw new InvalidArgumentException('XTEA block must be 8 bytes');
        }
        if ($rounds <= 0) {
            throw new InvalidArgumentException('rounds must be positive');
        }

        /** @var array<int, int> $parts */
        $parts = array_values(unpack('V2', $block8));
        $v0 = $parts[0];
        $v1 = $parts[1];
        $k = self::keyWordsLe($key16);

        $sum = (self::DELTA * $rounds) & self::MASK32;

        for ($i = 0; $i < $rounds; $i++) {
            $idx1 = ($sum >> 11) & 3;
            $mx1 = ((((($v0 << 4) & self::MASK32) ^ (($v0 >> 5) & self::MASK32)) + $v0) & self::MASK32) ^ (($sum + $k[$idx1]) & self::MASK32);
            $v1 = ($v1 - $mx1) & self::MASK32;

            $sum = ($sum - self::DELTA) & self::MASK32;

            $idx0 = $sum & 3;
            $mx0 = ((((($v1 << 4) & self::MASK32) ^ (($v1 >> 5) & self::MASK32)) + $v1) & self::MASK32) ^ (($sum + $k[$idx0]) & self::MASK32);
            $v0 = ($v0 - $mx0) & self::MASK32;
        }

        return pack('V2', $v0, $v1);
    }

    public static function encryptBlockLe(string $block8, string $key16, int $rounds = 32): string
    {
        if (strlen($block8) !== 8) {
            throw new InvalidArgumentException('XTEA block must be 8 bytes');
        }
        if ($rounds <= 0) {
            throw new InvalidArgumentException('rounds must be positive');
        }

        /** @var array<int, int> $parts */
        $parts = array_values(unpack('V2', $block8));
        $v0 = $parts[0];
        $v1 = $parts[1];
        $k = self::keyWordsLe($key16);

        $sum = 0;

        for ($i = 0; $i < $rounds; $i++) {
            $idx0 = $sum & 3;
            $mx0 = ((((($v1 << 4) & self::MASK32) ^ (($v1 >> 5) & self::MASK32)) + $v1) & self::MASK32) ^ (($sum + $k[$idx0]) & self::MASK32);
            $v0 = ($v0 + $mx0) & self::MASK32;

            $sum = ($sum + self::DELTA) & self::MASK32;

            $idx1 = ($sum >> 11) & 3;
            $mx1 = ((((($v0 << 4) & self::MASK32) ^ (($v0 >> 5) & self::MASK32)) + $v0) & self::MASK32) ^ (($sum + $k[$idx1]) & self::MASK32);
            $v1 = ($v1 + $mx1) & self::MASK32;
        }

        return pack('V2', $v0, $v1);
    }

    public static function decryptEcbLe(string $ciphertext, string $key16, int $rounds = 32): string
    {
        $length = strlen($ciphertext);
        if ($length === 0 || ($length % 8) !== 0) {
            throw new InvalidArgumentException('ciphertext length must be positive and divisible by 8');
        }

        $out = '';
        for ($offset = 0; $offset < $length; $offset += 8) {
            $out .= self::decryptBlockLe(substr($ciphertext, $offset, 8), $key16, $rounds);
        }

        return $out;
    }

    public static function encryptEcbLe(string $plaintext, string $key16, int $rounds = 32): string
    {
        $length = strlen($plaintext);
        if ($length === 0 || ($length % 8) !== 0) {
            throw new InvalidArgumentException('plaintext length must be positive and divisible by 8');
        }

        $out = '';
        for ($offset = 0; $offset < $length; $offset += 8) {
            $out .= self::encryptBlockLe(substr($plaintext, $offset, 8), $key16, $rounds);
        }

        return $out;
    }
}
