<?php

declare(strict_types=1);

namespace RtuReceiver;

use RuntimeException;

final class JsonlWriter
{
    public function __construct(private readonly string $logDir)
    {
        if (!is_dir($this->logDir) && !mkdir($concurrentDirectory = $this->logDir, 0775, true) && !is_dir($concurrentDirectory)) {
            throw new RuntimeException("cannot create log dir: {$this->logDir}");
        }
    }

    public static function utcNowIso(): string
    {
        return gmdate('c');
    }

    /** @param array<string, mixed> $record */
    public function writeRaw(array $record): void
    {
        $this->write('raw', $record);
    }

    /** @param array<string, mixed> $record */
    public function writeDecoded(array $record): void
    {
        $this->write('decoded', $record);
    }

    /** @param array<string, mixed> $record */
    public function writeError(array $record): void
    {
        $this->write('errors', $record);
    }

    /** @param array<string, mixed> $record */
    private function write(string $stream, array $record): void
    {
        $suffix = gmdate('Ymd');
        $path = rtrim($this->logDir, '/')."/{$stream}-{$suffix}.jsonl";
        $json = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException('cannot encode JSON log record');
        }

        $ok = file_put_contents($path, $json . PHP_EOL, FILE_APPEND | LOCK_EX);
        if ($ok === false) {
            throw new RuntimeException("cannot append to log file: $path");
        }
    }
}
