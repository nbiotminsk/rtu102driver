<?php

declare(strict_types=1);

namespace RtuReceiver\Tests;

use PHPUnit\Framework\TestCase;
use RtuReceiver\Crc16;
use RtuReceiver\ProtocolDecoder;
use RtuReceiver\Xtea;

final class ProtocolVectorsTest extends TestCase
{
    public function testStuffingRoundTrip(): void
    {
        $raw = hex2bin('00c001c202c403');
        self::assertNotFalse($raw);

        $stuffed = ProtocolDecoder::stuffPayload($raw);
        self::assertSame($raw, ProtocolDecoder::unstuffPayload($stuffed));
    }

    public function testImeiParseVector(): void
    {
        $imeiBytes = hex2bin('cb9b558888110300');
        self::assertNotFalse($imeiBytes);
        self::assertSame('863703030668235', ProtocolDecoder::parseImei($imeiBytes));
    }

    public function testCrcReferenceVector(): void
    {
        self::assertSame(0x29B1, Crc16::ccittFalse('123456789'));
    }

    public function testXteaDecryptDocumentVector(): void
    {
        $key = hex2bin('79757975797579756f706f706f706f70');
        self::assertNotFalse($key);

        $ciphertext = hex2bin(
            '60614e680e705d0fefcf7ac8102c4452ecb0c85768f2f2dc52415c43a36712f0'
            . '31c9037dafd31f01ecb0c85768f2f2dc7b00be7e5a15fee1e78c63c58c2c6861'
            . 'fef9a1c4130a354c846448512e6a97ce4a9005690d1e3808f065c957538e1bac'
            . '87e7228322ab39a6900146786840dc0bc536ad6afb6e4e3267fb045dd9c7e670'
            . 'f1c2d2ac1fcc71ad06b7b194de4031f4046744610aafa7b92fd3f392c3a5eeb1'
            . '474ffa60c0587e68ecb0c85768f2f2dc2a88827461b41c99b2539b6bfdcd4325'
            . 'be3ced59be7b594addb3366e076f6e470cc41df1eb3a8d93c99eb7bdad5a474c'
            . '33659653762910d0ecb0c85768f2f2dcecb0c85768f2f2dc82e715e7952a79c4'
            . '660074ccc50741cab5eabb873ae706b4c8b008128df0af80fece91741fc5f641'
            . '1145aab35ac9f6e0f8a937baed012d00c3be705a5e8c3440ddc1cd4e0051cccc'
        );
        self::assertNotFalse($ciphertext);

        $plain = Xtea::decryptEcbLe($ciphertext, $key);
        self::assertStringStartsWith(hex2bin('09300004100e00000104f4779559'), $plain);

        $plainNoCrc = substr($plain, 0, -2);
        $crcRecv = unpack('v', substr($plain, -2))[1];
        self::assertSame(Crc16::ccittFalse($plainNoCrc), $crcRecv);
    }

    public function testParsePayloadIds(): void
    {
        $payload = hex2bin(
            '01010478563412'
            . '020100'
            . '0407'
            . '060300'
            . '07030003313233'
            . '09020101aa0202bbcc'
        );
        self::assertNotFalse($payload);

        $parsed = ProtocolDecoder::parsePayload($payload);
        self::assertSame(0, $parsed['padding_len']);
        self::assertSame([1, 2, 4, 6, 7, 9], array_map(static fn(array $r): int => $r['id'], $parsed['records']));
    }

    public function testParseId3SyntheticEvent(): void
    {
        $eventTime = pack('V', 1700000000);
        $eventData = hex2bin('00010203041405');
        self::assertNotFalse($eventData);

        $payload = "\x03\x13\x01" . $eventTime . chr(strlen($eventData)) . $eventData;
        $parsed = ProtocolDecoder::parsePayload($payload);

        $record = $parsed['records'][0];
        self::assertSame(3, $record['id']);
        self::assertSame(0x13, $record['seq']);
        self::assertSame(1, $record['events'][0]['event_code']);
    }
}
