<?php

declare(strict_types=1);

namespace RtuReceiver;

use RuntimeException;

final class UdpReceiver
{
    public function __construct(
        private readonly Config $config,
        private readonly JsonlWriter $writer,
        private readonly string $logLevel = 'info',
    ) {
    }

    public function run(bool $once = false): void
    {
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($sock === false) {
            throw new RuntimeException('socket_create failed: ' . socket_strerror(socket_last_error()));
        }

        try {
            if (!socket_bind($sock, $this->config->listenHost, $this->config->listenPort)) {
                throw new RuntimeException('socket_bind failed: ' . socket_strerror(socket_last_error($sock)));
            }

            if ($once) {
                socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 5, 'usec' => 0]);
            }

            if ($this->logLevel === 'debug') {
                fwrite(STDOUT, "listening on udp://{$this->config->listenHost}:{$this->config->listenPort}\n");
            }

            while (true) {
                $buf = '';
                $from = '';
                $port = 0;
                $bytes = @socket_recvfrom($sock, $buf, 65535, 0, $from, $port);

                if ($bytes === false) {
                    $code = socket_last_error($sock);
                    if ($once && ($code === SOCKET_EAGAIN || $code === SOCKET_EWOULDBLOCK)) {
                        throw new RuntimeException('timeout waiting for UDP datagram');
                    }
                    throw new RuntimeException('socket_recvfrom failed: ' . socket_strerror($code));
                }

                $this->handleDatagram($buf, $from, $port);

                if ($once) {
                    break;
                }
            }
        } finally {
            socket_close($sock);
        }
    }

    public function handleDatagram(string $datagram, string $srcIp, int $srcPort): void
    {
        $ts = JsonlWriter::utcNowIso();
        $datagramHex = bin2hex($datagram);

        $this->writer->writeRaw([
            'ts_utc' => $ts,
            'src_ip' => $srcIp,
            'src_port' => $srcPort,
            'len' => strlen($datagram),
            'datagram_hex' => $datagramHex,
        ]);

        if (!$this->config->decodeEnabled) {
            return;
        }

        try {
            $result = ProtocolDecoder::decodeDatagram(
                $datagram,
                fn(string $imei): ?string => $this->config->resolveKey($imei)
            );

            $decoded = [
                'ts_utc' => $ts,
                'src_ip' => $srcIp,
                'src_port' => $srcPort,
                'imei' => $result['imei'],
                'frame_ok' => $result['frame_ok'],
                'crc_ok' => $result['crc_ok'],
                'payload_hex' => $result['payload_hex'],
                'records' => $result['records'],
                'warnings' => $result['warnings'],
            ];
            $this->writer->writeDecoded($decoded);

            foreach ($result['nonfatal_errors'] as $err) {
                $this->writer->writeError([
                    'ts_utc' => $ts,
                    'src_ip' => $srcIp,
                    'src_port' => $srcPort,
                    'stage' => $err['stage'] ?? 'payload_parse',
                    'reason' => $err['reason'] ?? 'nonfatal_parse_warning',
                    'imei' => $result['imei'],
                    'datagram_hex' => $datagramHex,
                    'details' => $err['details'] ?? [],
                ]);
            }
        } catch (ProtocolException $e) {
            $this->writer->writeError([
                'ts_utc' => $ts,
                'src_ip' => $srcIp,
                'src_port' => $srcPort,
                'stage' => $e->stage,
                'reason' => $e->reason,
                'imei' => $e->imei,
                'datagram_hex' => $datagramHex,
                'details' => $e->details,
            ]);
        }
    }
}
