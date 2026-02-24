<?php

declare(strict_types=1);

namespace RtuReceiver\Tests;

use PHPUnit\Framework\TestCase;
use RtuReceiver\ProtocolDecoder;
use RtuReceiver\Xtea;

final class UdpLoopbackTest extends TestCase
{
    public function testUdpOnceWritesRawAndDecoded(): void
    {
        if (!extension_loaded('sockets')) {
            self::markTestSkipped('ext-sockets is required');
        }

        $imei = '863703030668235';
        $keyHex = '79757975797579756f706f706f706f70';
        $key = hex2bin($keyHex);
        self::assertNotFalse($key);

        $tmp = sys_get_temp_dir() . '/rtu_php_' . bin2hex(random_bytes(6));
        mkdir($tmp, 0775, true);
        $logDir = $tmp . '/logs';

        $port = $this->pickPort();
        $configPath = $tmp . '/receiver.json';
        file_put_contents($configPath, json_encode([
            'listen_host' => '127.0.0.1',
            'listen_port' => $port,
            'log_dir' => $logDir,
            'decode_enabled' => true,
            'keys' => [
                'default_hex' => null,
                'by_imei' => [
                    $imei => $keyHex,
                ],
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        $plain = ProtocolDecoder::buildPlainForEncrypt("\x09\x00");
        $frame = ProtocolDecoder::buildFrame($imei, Xtea::encryptEcbLe($plain, $key));

        $cmd = escapeshellarg(PHP_BINARY)
            . ' '
            . escapeshellarg(dirname(__DIR__) . '/bin/receiver.php')
            . ' --config '
            . escapeshellarg($configPath)
            . ' --once --log-level debug';

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $proc = proc_open($cmd, $descriptors, $pipes, dirname(__DIR__));
        self::assertIsResource($proc);

        usleep(200000);

        $sender = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        self::assertNotFalse($sender);
        socket_sendto($sender, $frame, strlen($frame), 0, '127.0.0.1', $port);
        socket_close($sender);

        $exited = false;
        $deadline = microtime(true) + 5.0;
        do {
            $status = proc_get_status($proc);
            if ($status['running'] === false) {
                $exited = true;
                break;
            }
            usleep(50000);
        } while (microtime(true) < $deadline);

        if (!$exited) {
            proc_terminate($proc, 9);
            self::fail('receiver process did not exit in time');
        }

        $stderr = stream_get_contents($pipes[2]);
        foreach ($pipes as $pipe) {
            fclose($pipe);
        }
        $exitCode = proc_close($proc);

        self::assertSame(0, $exitCode, $stderr ?: 'receiver exited with non-zero code');

        $suffix = gmdate('Ymd');
        $rawPath = $logDir . '/raw-' . $suffix . '.jsonl';
        $decodedPath = $logDir . '/decoded-' . $suffix . '.jsonl';

        self::assertFileExists($rawPath);
        self::assertFileExists($decodedPath);

        $rawLines = file($rawPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $decodedLines = file($decodedPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        self::assertIsArray($rawLines);
        self::assertIsArray($decodedLines);
        self::assertCount(1, $rawLines);
        self::assertCount(1, $decodedLines);

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($decodedLines[0], true);
        self::assertSame($imei, $decoded['imei']);
        self::assertTrue($decoded['frame_ok']);
        self::assertTrue($decoded['crc_ok']);
        self::assertSame(9, $decoded['records'][0]['id']);
    }

    private function pickPort(): int
    {
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        self::assertNotFalse($sock);
        socket_bind($sock, '127.0.0.1', 0);
        socket_getsockname($sock, $addr, $port);
        socket_close($sock);
        return (int)$port;
    }
}
