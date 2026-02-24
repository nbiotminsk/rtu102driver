<?php

declare(strict_types=1);

namespace RtuReceiver;

use RuntimeException;

final class ProtocolException extends RuntimeException
{
    public function __construct(
        public readonly string $stage,
        public readonly string $reason,
        /** @var array<string, mixed> */
        public readonly array $details = [],
        public readonly ?string $imei = null,
    ) {
        parent::__construct($stage . ':' . $reason);
    }
}

final class ProtocolDecoder
{
    public const FRAME_START = 0xC0;
    public const FRAME_END = 0xC2;
    public const ESCAPE = 0xC4;

    /** @var array<int, int> */
    private const ESC_DECODE = [
        0xC1 => 0xC0,
        0xC3 => 0xC2,
        0xC4 => 0xC4,
    ];

    /** @var array<int, string> */
    private const ESC_ENCODE = [
        0xC0 => "\xC4\xC1",
        0xC2 => "\xC4\xC3",
        0xC4 => "\xC4\xC4",
    ];

    /** @var array<int, int> */
    private const EVENT_TYPE_LENGTHS = [
        0 => 4,
        1 => 4,
        2 => 4,
        3 => 4,
        6 => 4,
        7 => 1,
        8 => 1,
        9 => 1,
        10 => 1,
        11 => 1,
        12 => 4,
        13 => 4,
        14 => 4,
        15 => 4,
        16 => 4,
        17 => 4,
        18 => 4,
        19 => 4,
        20 => 1,
        21 => 4,
        22 => 1,
        23 => 1,
        24 => 1,
        25 => 1,
        26 => 1,
        27 => 4,
        28 => 4,
        29 => 4,
        30 => 4,
        31 => 1,
        32 => 1,
        33 => 1,
        37 => 4,
        38 => 4,
        39 => 4,
        40 => 4,
        41 => 4,
        42 => 4,
        43 => 4,
        44 => 1,
        45 => 1,
        46 => 1,
        47 => 1,
        48 => 1,
        49 => 1,
        50 => 4,
        51 => 1,
    ];

    public static function stuffPayload(string $raw): string
    {
        $out = '';
        $length = strlen($raw);
        for ($i = 0; $i < $length; $i++) {
            $byte = ord($raw[$i]);
            if (array_key_exists($byte, self::ESC_ENCODE)) {
                $out .= self::ESC_ENCODE[$byte];
            } else {
                $out .= $raw[$i];
            }
        }
        return $out;
    }

    public static function unstuffPayload(string $stuffed): string
    {
        $out = '';
        $length = strlen($stuffed);

        for ($i = 0; $i < $length; $i++) {
            $byte = ord($stuffed[$i]);
            if ($byte !== self::ESCAPE) {
                $out .= $stuffed[$i];
                continue;
            }

            if ($i + 1 >= $length) {
                throw new ProtocolException('unstuff', 'dangling_escape_byte', ['offset' => $i]);
            }

            $esc = ord($stuffed[$i + 1]);
            if (!array_key_exists($esc, self::ESC_DECODE)) {
                throw new ProtocolException('unstuff', 'invalid_escape_sequence', ['offset' => $i, 'escape_byte' => $esc]);
            }

            $out .= chr(self::ESC_DECODE[$esc]);
            $i++;
        }

        return $out;
    }

    public static function parseImei(string $imeiBytes): string
    {
        if (strlen($imeiBytes) !== 8) {
            throw new ProtocolException('imei', 'invalid_imei_bytes_length', ['length' => strlen($imeiBytes)]);
        }

        /** @var array<int, int> $parts */
        $parts = array_values(unpack('V2', $imeiBytes));
        $value = ($parts[1] << 32) | $parts[0];
        return (string)$value;
    }

    public static function buildPlainForEncrypt(string $payload): string
    {
        $padLen = (8 - ((strlen($payload) + 2) % 8)) % 8;
        $padded = $payload . str_repeat("\x00", $padLen);
        $crc = Crc16::ccittFalse($padded);
        return $padded . pack('v', $crc);
    }

    public static function buildFrame(string $imei, string $encryptedPayload): string
    {
        $imeiInt = (int)$imei;
        $imeiBytes = pack('V2', $imeiInt & 0xFFFFFFFF, ($imeiInt >> 32) & 0xFFFFFFFF);
        $body = $imeiBytes . $encryptedPayload;
        return chr(self::FRAME_START) . self::stuffPayload($body) . chr(self::FRAME_END);
    }

    /**
     * @param callable(string):(?string) $keyResolver
     * @return array<string, mixed>
     */
    public static function decodeDatagram(string $datagram, callable $keyResolver): array
    {
        $datagramLen = strlen($datagram);
        if ($datagramLen < 2) {
            throw new ProtocolException('frame', 'too_short', ['length' => $datagramLen]);
        }

        $start = ord($datagram[0]);
        $end = ord($datagram[$datagramLen - 1]);
        if ($start !== self::FRAME_START || $end !== self::FRAME_END) {
            throw new ProtocolException('frame', 'invalid_boundaries', ['start' => $start, 'end' => $end]);
        }

        $stuffedBody = substr($datagram, 1, -1);
        $body = self::unstuffPayload($stuffedBody);

        if (strlen($body) < 16) {
            throw new ProtocolException('frame', 'body_too_short', ['body_len' => strlen($body)]);
        }

        $imei = self::parseImei(substr($body, 0, 8));
        $ciphertext = substr($body, 8);

        if ($ciphertext === '' || (strlen($ciphertext) % 8) !== 0) {
            throw new ProtocolException('xtea', 'invalid_ciphertext_length', ['cipher_len' => strlen($ciphertext)], $imei);
        }

        $key = $keyResolver($imei);
        if ($key === null) {
            throw new ProtocolException('key_lookup', 'missing_key_for_imei', ['imei' => $imei], $imei);
        }
        if (strlen($key) !== 16) {
            throw new ProtocolException('key_lookup', 'invalid_key_length', ['imei' => $imei, 'key_len' => strlen($key)], $imei);
        }

        $plaintext = Xtea::decryptEcbLe($ciphertext, $key);
        if (strlen($plaintext) < 2) {
            throw new ProtocolException('crc', 'plaintext_too_short', ['plain_len' => strlen($plaintext)], $imei);
        }

        $plainNoCrc = substr($plaintext, 0, -2);
        $crcRecv = unpack('v', substr($plaintext, -2))[1];
        $crcCalc = Crc16::ccittFalse($plainNoCrc);
        if ($crcRecv !== $crcCalc) {
            throw new ProtocolException(
                'crc',
                'crc_mismatch',
                ['received' => $crcRecv, 'calculated' => $crcCalc],
                $imei
            );
        }

        $parsed = self::parsePayload($plainNoCrc);

        return [
            'imei' => $imei,
            'frame_ok' => true,
            'crc_ok' => true,
            'payload_hex' => bin2hex($parsed['payload_used']),
            'records' => $parsed['records'],
            'warnings' => $parsed['warnings'],
            'nonfatal_errors' => $parsed['nonfatal_errors'],
        ];
    }

    /**
     * @return array{payload_used:string,padding_len:int,records:array<int, array<string,mixed>>,warnings:array<int,string>,nonfatal_errors:array<int,array<string,mixed>>}
     */
    public static function parsePayload(string $payloadWithPad): array
    {
        $records = [];
        $warnings = [];
        $nonfatalErrors = [];

        $offset = 0;
        $length = strlen($payloadWithPad);

        while ($offset < $length) {
            if (ord($payloadWithPad[$offset]) === 0 && self::allZero(substr($payloadWithPad, $offset))) {
                break;
            }

            $dataId = ord($payloadWithPad[$offset]);
            $offset++;

            try {
                [$record, $offset, $parseWarnings, $parseErrors] = self::parseRecord($dataId, $payloadWithPad, $offset);
            } catch (RuntimeException $e) {
                $warnings[] = 'payload_parse_error';
                $nonfatalErrors[] = [
                    'stage' => 'payload_parse',
                    'reason' => 'record_parse_failed',
                    'details' => [
                        'data_id' => $dataId,
                        'offset' => $offset,
                        'message' => $e->getMessage(),
                    ],
                ];
                $records[] = [
                    'id' => $dataId,
                    'type' => 'unknown',
                    'raw_hex' => bin2hex(substr($payloadWithPad, $offset)),
                    'parse_error' => $e->getMessage(),
                ];
                $offset = $length;
                break;
            }

            $records[] = $record;
            foreach ($parseWarnings as $w) {
                $warnings[] = $w;
            }
            foreach ($parseErrors as $err) {
                $nonfatalErrors[] = $err;
            }
        }

        return [
            'payload_used' => substr($payloadWithPad, 0, $offset),
            'padding_len' => $length - $offset,
            'records' => $records,
            'warnings' => $warnings,
            'nonfatal_errors' => $nonfatalErrors,
        ];
    }

    /**
     * @return array{0:array<string,mixed>,1:int,2:array<int,string>,3:array<int,array<string,mixed>>}
     */
    private static function parseRecord(int $dataId, string $buf, int $offset): array
    {
        $warnings = [];
        $nonfatalErrors = [];

        if ($dataId === 1 || $dataId === 6) {
            [$paramId, $value, $offset] = self::parseParamLenData($buf, $offset);
            return [[
                'id' => $dataId,
                'type' => $dataId === 1 ? 'config_command' : 'read_command',
                'param_id' => $paramId,
                'len' => strlen($value),
                'data_hex' => bin2hex($value),
            ], $offset, $warnings, $nonfatalErrors];
        }

        if ($dataId === 2) {
            self::requireLen($buf, $offset, 2, 'truncated_response');
            $paramId = ord($buf[$offset]);
            $resultCode = ord($buf[$offset + 1]);
            return [[
                'id' => 2,
                'type' => 'config_response',
                'param_id' => $paramId,
                'result_code' => $resultCode,
            ], $offset + 2, $warnings, $nonfatalErrors];
        }

        if ($dataId === 3) {
            self::requireLen($buf, $offset, 1, 'truncated_archive_seq');
            $seq = ord($buf[$offset]);
            $offset++;

            $events = [];
            $len = strlen($buf);
            while ($offset < $len) {
                if (ord($buf[$offset]) === 0 && self::allZero(substr($buf, $offset))) {
                    break;
                }

                self::requireLen($buf, $offset, 6, 'truncated_event_header');
                $eventCode = ord($buf[$offset]);
                $eventTime = unpack('V', substr($buf, $offset + 1, 4))[1];
                $eventDataLen = ord($buf[$offset + 5]);
                $offset += 6;

                self::requireLen($buf, $offset, $eventDataLen, 'truncated_event_data');
                $eventData = substr($buf, $offset, $eventDataLen);
                $offset += $eventDataLen;

                $parsedEvent = self::parseEventData($eventData);
                foreach ($parsedEvent['warnings'] as $w) {
                    $warnings[] = $w;
                }
                foreach ($parsedEvent['nonfatal_errors'] as $err) {
                    $nonfatalErrors[] = $err;
                }

                $events[] = [
                    'event_code' => $eventCode,
                    'event_time' => $eventTime,
                    'event_data_len' => $eventDataLen,
                    'event_data' => $parsedEvent['entries'],
                ];
            }

            return [[
                'id' => 3,
                'type' => 'archive',
                'seq' => $seq,
                'events' => $events,
            ], $offset, $warnings, $nonfatalErrors];
        }

        if ($dataId === 4) {
            self::requireLen($buf, $offset, 1, 'truncated_archive_ack');
            return [[
                'id' => 4,
                'type' => 'archive_ack',
                'seq' => ord($buf[$offset]),
            ], $offset + 1, $warnings, $nonfatalErrors];
        }

        if ($dataId === 7) {
            self::requireLen($buf, $offset, 3, 'truncated_read_response_header');
            $paramId = ord($buf[$offset]);
            $resultCode = ord($buf[$offset + 1]);
            $dataLen = ord($buf[$offset + 2]);
            $offset += 3;
            self::requireLen($buf, $offset, $dataLen, 'truncated_read_response_data');
            $value = substr($buf, $offset, $dataLen);
            return [[
                'id' => 7,
                'type' => 'read_response',
                'param_id' => $paramId,
                'result_code' => $resultCode,
                'len' => $dataLen,
                'data_hex' => bin2hex($value),
            ], $offset + $dataLen, $warnings, $nonfatalErrors];
        }

        if ($dataId === 8) {
            $raw = substr($buf, $offset);
            return [[
                'id' => 8,
                'type' => 'auth',
                'raw_hex' => bin2hex($raw),
            ], strlen($buf), $warnings, $nonfatalErrors];
        }

        if ($dataId === 9) {
            self::requireLen($buf, $offset, 1, 'truncated_telemetry_count');
            $count = ord($buf[$offset]);
            $offset++;

            $items = [];
            for ($i = 0; $i < $count; $i++) {
                self::requireLen($buf, $offset, 2, 'truncated_telemetry_item_header');
                $paramId = ord($buf[$offset]);
                $dataLen = ord($buf[$offset + 1]);
                $offset += 2;
                self::requireLen($buf, $offset, $dataLen, 'truncated_telemetry_item_data');
                $value = substr($buf, $offset, $dataLen);
                $offset += $dataLen;
                $items[] = [
                    'param_id' => $paramId,
                    'len' => $dataLen,
                    'data_hex' => bin2hex($value),
                ];
            }

            return [[
                'id' => 9,
                'type' => 'telemetry',
                'count' => $count,
                'items' => $items,
            ], $offset, $warnings, $nonfatalErrors];
        }

        if ($dataId >= 10 && $dataId <= 14) {
            $raw = substr($buf, $offset);
            $warnings[] = 'rtu800_extended_id';
            $nonfatalErrors[] = [
                'stage' => 'payload_parse',
                'reason' => 'rtu800_extended_id',
                'details' => ['data_id' => $dataId],
            ];
            return [[
                'id' => $dataId,
                'type' => 'rtu800_extended',
                'raw_hex' => bin2hex($raw),
            ], strlen($buf), $warnings, $nonfatalErrors];
        }

        $raw = substr($buf, $offset);
        $warnings[] = 'unknown_data_id';
        $nonfatalErrors[] = [
            'stage' => 'payload_parse',
            'reason' => 'unknown_data_id',
            'details' => ['data_id' => $dataId],
        ];

        return [[
            'id' => $dataId,
            'type' => 'unknown',
            'raw_hex' => bin2hex($raw),
        ], strlen($buf), $warnings, $nonfatalErrors];
    }

    /**
     * @return array{0:int,1:string,2:int}
     */
    private static function parseParamLenData(string $buf, int $offset): array
    {
        self::requireLen($buf, $offset, 2, 'truncated_param_len_data_header');
        $paramId = ord($buf[$offset]);
        $dataLen = ord($buf[$offset + 1]);
        $offset += 2;

        self::requireLen($buf, $offset, $dataLen, 'truncated_param_len_data_value');
        $value = substr($buf, $offset, $dataLen);

        return [$paramId, $value, $offset + $dataLen];
    }

    /**
     * @return array{entries:array<int,array<string,mixed>>,warnings:array<int,string>,nonfatal_errors:array<int,array<string,mixed>>}
     */
    private static function parseEventData(string $eventData): array
    {
        $entries = [];
        $warnings = [];
        $nonfatalErrors = [];

        $offset = 0;
        $len = strlen($eventData);

        while ($offset < $len) {
            $typeId = ord($eventData[$offset]);
            $offset++;

            if (!array_key_exists($typeId, self::EVENT_TYPE_LENGTHS)) {
                $warnings[] = 'unknown_type_id';
                $nonfatalErrors[] = [
                    'stage' => 'payload_parse',
                    'reason' => 'unknown_type_id',
                    'details' => ['type_id' => $typeId],
                ];
                $entries[] = [
                    'type_id' => $typeId,
                    'raw_hex' => bin2hex(substr($eventData, $offset)),
                    'unknown' => true,
                ];
                break;
            }

            $fixedLen = self::EVENT_TYPE_LENGTHS[$typeId];
            if ($offset + $fixedLen > $len) {
                $warnings[] = 'event_type_len_mismatch';
                $nonfatalErrors[] = [
                    'stage' => 'payload_parse',
                    'reason' => 'event_type_len_mismatch',
                    'details' => [
                        'type_id' => $typeId,
                        'expected_len' => $fixedLen,
                        'available' => $len - $offset,
                    ],
                ];
                $entries[] = [
                    'type_id' => $typeId,
                    'raw_hex' => bin2hex(substr($eventData, $offset)),
                    'len_mismatch' => true,
                ];
                break;
            }

            $value = substr($eventData, $offset, $fixedLen);
            $offset += $fixedLen;

            $entries[] = [
                'type_id' => $typeId,
                'len' => $fixedLen,
                'raw_hex' => bin2hex($value),
            ];
        }

        return [
            'entries' => $entries,
            'warnings' => $warnings,
            'nonfatal_errors' => $nonfatalErrors,
        ];
    }

    private static function allZero(string $bytes): bool
    {
        $len = strlen($bytes);
        for ($i = 0; $i < $len; $i++) {
            if (ord($bytes[$i]) !== 0) {
                return false;
            }
        }
        return true;
    }

    private static function requireLen(string $buf, int $offset, int $needed, string $reason): void
    {
        if ($offset + $needed > strlen($buf)) {
            throw new RuntimeException($reason);
        }
    }
}
