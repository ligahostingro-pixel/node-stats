<?php
/**
 * Node Agent — deploy this on every remote node.
 *
 * Copy this entire folder to /var/www/html/ on the target server.
 * Then in the main Node Status admin panel, add the node with:
 *   - Endpoint URL: http(s)://<server-ip>/agent.php
 *   - API Token:    (same value as AGENT_TOKEN below)
 *
 * Requirements: PHP 8.0+, /proc filesystem (Linux)
 */

declare(strict_types=1);

/* ── Configuration ─────────────────────────────────────────── */

// Set this token to secure the endpoint. Must match the API Token in the admin panel.
define('AGENT_TOKEN', getenv('NODE_AGENT_TOKEN') ?: 'CHANGE-ME-TO-A-RANDOM-STRING');

/* ── Security headers ──────────────────────────────────────── */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');

/* ── Token check ───────────────────────────────────────────── */

$token = (string)($_GET['token'] ?? '');
if (AGENT_TOKEN !== '' && AGENT_TOKEN !== 'CHANGE-ME-TO-A-RANDOM-STRING' && !hash_equals(AGENT_TOKEN, $token)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Forbidden'], JSON_UNESCAPED_SLASHES);
    exit;
}

/* ── Metric collectors ─────────────────────────────────────── */

function get_cpu_times(): ?array
{
    $content = @file('/proc/stat');
    if ($content === false || empty($content)) {
        return null;
    }
    $line = trim($content[0]);
    if (!str_starts_with($line, 'cpu ')) {
        return null;
    }
    $parts = preg_split('/\s+/', $line);
    if ($parts === false || count($parts) < 8) {
        return null;
    }
    $values = array_map('intval', array_slice($parts, 1));
    $idle = ($values[3] ?? 0) + ($values[4] ?? 0);
    $total = array_sum($values);
    return ['idle' => $idle, 'total' => $total];
}

function get_cpu_usage_percent(): ?float
{
    $start = get_cpu_times();
    if ($start === null) {
        return null;
    }
    usleep(120000);
    $end = get_cpu_times();
    if ($end === null) {
        return null;
    }
    $deltaTotal = $end['total'] - $start['total'];
    $deltaIdle = $end['idle'] - $start['idle'];
    if ($deltaTotal <= 0) {
        return null;
    }
    return round(max(0, min(100, (1 - ($deltaIdle / $deltaTotal)) * 100)), 2);
}

function get_cpu_details(): array
{
    $cpuinfo = @file('/proc/cpuinfo', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($cpuinfo === false) {
        return ['cpu_name' => null, 'cpu_cores' => null];
    }
    $cpuName = null;
    $coreCount = 0;
    foreach ($cpuinfo as $line) {
        $trimmed = trim($line);
        if ($cpuName === null && preg_match('/^model name\s*:\s*(.+)$/i', $trimmed, $matches) === 1) {
            $cpuName = trim($matches[1]);
        }
        if (preg_match('/^processor\s*:\s*\d+$/i', $trimmed) === 1) {
            $coreCount++;
        }
    }
    return [
        'cpu_name' => $cpuName !== null && $cpuName !== '' ? $cpuName : null,
        'cpu_cores' => $coreCount > 0 ? $coreCount : null,
    ];
}

function get_memory_stats(): array
{
    $meminfo = @file('/proc/meminfo');
    $totalKb = 0;
    $availableKb = 0;
    if ($meminfo !== false) {
        foreach ($meminfo as $line) {
            if (preg_match('/^MemTotal:\s+(\d+)\s+kB$/', trim($line), $m) === 1) {
                $totalKb = (int)$m[1];
            }
            if (preg_match('/^MemAvailable:\s+(\d+)\s+kB$/', trim($line), $m) === 1) {
                $availableKb = (int)$m[1];
            }
        }
    }
    $usedKb = max(0, $totalKb - $availableKb);
    return [
        'total_mb' => round($totalKb / 1024, 2),
        'used_mb' => round($usedKb / 1024, 2),
        'used_pct' => $totalKb > 0 ? round(($usedKb / $totalKb) * 100, 2) : 0,
    ];
}

function get_swap_stats(): array
{
    $meminfo = @file('/proc/meminfo');
    $swapTotalKb = 0;
    $swapFreeKb = 0;
    if ($meminfo !== false) {
        foreach ($meminfo as $line) {
            if (preg_match('/^SwapTotal:\s+(\d+)\s+kB$/', trim($line), $m) === 1) {
                $swapTotalKb = (int)$m[1];
            }
            if (preg_match('/^SwapFree:\s+(\d+)\s+kB$/', trim($line), $m) === 1) {
                $swapFreeKb = (int)$m[1];
            }
        }
    }
    $swapUsedKb = max(0, $swapTotalKb - $swapFreeKb);
    return [
        'total_mb' => round($swapTotalKb / 1024, 2),
        'used_mb' => round($swapUsedKb / 1024, 2),
        'used_pct' => $swapTotalKb > 0 ? round(($swapUsedKb / $swapTotalKb) * 100, 2) : 0,
    ];
}

function get_disk_stats(string $path = '/'): array
{
    $total = @disk_total_space($path);
    $free = @disk_free_space($path);
    if (!is_numeric($total) || !is_numeric($free) || (float)$total <= 0) {
        return ['total_gb' => null, 'used_gb' => null, 'used_pct' => null];
    }
    $usedF = max(0.0, (float)$total - (float)$free);
    return [
        'total_gb' => round((float)$total / 1073741824, 2),
        'used_gb' => round($usedF / 1073741824, 2),
        'used_pct' => round(($usedF / (float)$total) * 100, 2),
    ];
}

function get_network_totals(): array
{
    $lines = @file('/proc/net/dev');
    if ($lines === false) {
        return ['rx_bytes' => 0, 'tx_bytes' => 0];
    }
    $rx = 0;
    $tx = 0;
    foreach ($lines as $line) {
        if (!str_contains($line, ':')) {
            continue;
        }
        $clean = preg_replace('/\s+/', ' ', trim(str_replace(':', ' ', $line)));
        if ($clean === null) {
            continue;
        }
        $parts = explode(' ', $clean);
        if (count($parts) < 10) {
            continue;
        }
        if ($parts[0] === 'lo') {
            continue;
        }
        $rx += (int)$parts[1];
        $tx += (int)$parts[9];
    }
    return ['rx_bytes' => $rx, 'tx_bytes' => $tx];
}

function get_system_uptime(): ?int
{
    $raw = @file_get_contents('/proc/uptime');
    if (!is_string($raw) || $raw === '') {
        return null;
    }
    $parts = explode(' ', trim($raw));
    return is_numeric($parts[0] ?? null) ? (int)((float)$parts[0]) : null;
}

/* ── Collect & respond ─────────────────────────────────────── */

$mem  = get_memory_stats();
$swap = get_swap_stats();
$disk = get_disk_stats('/');
$net  = get_network_totals();
$load = sys_getloadavg();
$cpu  = get_cpu_details();

echo json_encode([
    'ok'             => true,
    'hostname'       => gethostname() ?: 'unknown',
    'os_name'        => php_uname('s') . ' ' . php_uname('r'),
    'ts'             => time(),
    'cpu_pct'        => get_cpu_usage_percent(),
    'cpu_name'       => $cpu['cpu_name'],
    'cpu_cores'      => $cpu['cpu_cores'],
    'mem_total_mb'   => $mem['total_mb'],
    'mem_used_mb'    => $mem['used_mb'],
    'mem_used_pct'   => $mem['used_pct'],
    'swap_total_mb'  => $swap['total_mb'],
    'swap_used_mb'   => $swap['used_mb'],
    'swap_used_pct'  => $swap['used_pct'],
    'disk_total_gb'  => $disk['total_gb'],
    'disk_used_gb'   => $disk['used_gb'],
    'disk_used_pct'  => $disk['used_pct'],
    'net_rx_bytes'   => $net['rx_bytes'],
    'net_tx_bytes'   => $net['tx_bytes'],
    'load1'          => $load[0] ?? null,
    'load5'          => $load[1] ?? null,
    'load15'         => $load[2] ?? null,
    'uptime_seconds' => get_system_uptime(),
], JSON_UNESCAPED_SLASHES);
