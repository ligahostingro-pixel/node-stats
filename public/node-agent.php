<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');

$token = (string)($_GET['token'] ?? '');
if (NODE_AGENT_TOKEN !== '' && !hash_equals(NODE_AGENT_TOKEN, $token)) {
    http_response_code(403);
    echo json_encode([
        'ok' => false,
        'error' => 'Forbidden',
    ], JSON_UNESCAPED_SLASHES);
    exit;
}

$metrics = collect_local_metrics();

echo json_encode([
    'ok' => true,
    'hostname' => gethostname() ?: 'unknown',
    'os_name' => php_uname('s') . ' ' . php_uname('r'),
    'ts' => time(),
    'cpu_pct' => $metrics['cpu_pct'],
    'cpu_name' => $metrics['cpu_name'],
    'cpu_cores' => $metrics['cpu_cores'],
    'mem_total_mb' => $metrics['mem_total_mb'],
    'mem_used_mb' => $metrics['mem_used_mb'],
    'mem_used_pct' => $metrics['mem_used_pct'],
    'swap_total_mb' => $metrics['swap_total_mb'],
    'swap_used_mb' => $metrics['swap_used_mb'],
    'swap_used_pct' => $metrics['swap_used_pct'],
    'disk_total_gb' => $metrics['disk_total_gb'],
    'disk_used_gb' => $metrics['disk_used_gb'],
    'disk_used_pct' => $metrics['disk_used_pct'],
    'net_rx_bytes' => $metrics['net_rx_bytes'],
    'net_tx_bytes' => $metrics['net_tx_bytes'],
    'load1' => $metrics['load1'],
    'load5' => $metrics['load5'],
    'load15' => $metrics['load15'],
    'uptime_seconds' => $metrics['uptime_seconds'],
], JSON_UNESCAPED_SLASHES);
