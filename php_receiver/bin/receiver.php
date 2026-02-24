#!/usr/bin/env php
<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/vendor/autoload.php';

use RtuReceiver\Config;
use RtuReceiver\JsonlWriter;
use RtuReceiver\UdpReceiver;

/** @var array<int, string> $argv */
$args = $argv;
array_shift($args);

$configPath = null;
$once = false;
$logLevel = 'info';

for ($i = 0; $i < count($args); $i++) {
    $arg = $args[$i];
    if ($arg === '--config') {
        $configPath = $args[$i + 1] ?? null;
        $i++;
        continue;
    }
    if ($arg === '--once') {
        $once = true;
        continue;
    }
    if ($arg === '--log-level') {
        $logLevel = $args[$i + 1] ?? 'info';
        $i++;
        continue;
    }
}

if ($configPath === null) {
    fwrite(STDERR, "Usage: php bin/receiver.php --config /path/to/receiver.json [--once] [--log-level info|debug]\n");
    exit(2);
}

if ($logLevel !== 'info' && $logLevel !== 'debug') {
    fwrite(STDERR, "Invalid --log-level. Allowed: info, debug\n");
    exit(2);
}

try {
    $config = Config::fromFile($configPath);
    $receiver = new UdpReceiver($config, new JsonlWriter($config->logDir), $logLevel);
    $receiver->run($once);
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage() . PHP_EOL);
    exit(1);
}
