<?php

declare(strict_types=1);

function ensure_storage(): void
{
    if (!is_dir(DATA_DIR)) {
        mkdir(DATA_DIR, 0775, true);
    }

    if (!is_dir(SAMPLES_DIR)) {
        mkdir(SAMPLES_DIR, 0775, true);
    }

    if (!file_exists(ANNOUNCEMENTS_FILE)) {
        file_put_contents(ANNOUNCEMENTS_FILE, json_encode([], JSON_PRETTY_PRINT));
    }

    if (!file_exists(STATE_FILE)) {
        $initialState = [
            'last_collected' => 0,
            'last_sample' => null,
        ];
        file_put_contents(STATE_FILE, json_encode($initialState, JSON_PRETTY_PRINT));
    }
}

function read_json_file(string $path, mixed $default): mixed
{
    if (!file_exists($path)) {
        return $default;
    }

    $raw = file_get_contents($path);
    if ($raw === false || $raw === '') {
        return $default;
    }

    $decoded = json_decode($raw, true);
    return $decoded === null ? $default : $decoded;
}

function write_json_file(string $path, mixed $data): void
{
    file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
}

function load_state(): array
{
    $state = read_json_file(STATE_FILE, []);

    return [
        'last_collected' => (int)($state['last_collected'] ?? 0),
        'last_sample' => is_array($state['last_sample'] ?? null) ? $state['last_sample'] : null,
    ];
}

function save_state(array $state): void
{
    write_json_file(STATE_FILE, $state);
}

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

    return [
        'idle' => $idle,
        'total' => $total,
    ];
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

    $usage = (1 - ($deltaIdle / $deltaTotal)) * 100;
    return round(max(0, min(100, $usage)), 2);
}

function get_memory_stats(): array
{
    $meminfo = @file('/proc/meminfo');
    $totalKb = 0;
    $availableKb = 0;

    if ($meminfo !== false) {
        foreach ($meminfo as $line) {
            if (preg_match('/^MemTotal:\s+(\d+)\s+kB$/', trim($line), $matches) === 1) {
                $totalKb = (int)$matches[1];
            }

            if (preg_match('/^MemAvailable:\s+(\d+)\s+kB$/', trim($line), $matches) === 1) {
                $availableKb = (int)$matches[1];
            }
        }
    }

    $usedKb = max(0, $totalKb - $availableKb);
    $usedPct = $totalKb > 0 ? ($usedKb / $totalKb) * 100 : 0;

    return [
        'total_mb' => round($totalKb / 1024, 2),
        'used_mb' => round($usedKb / 1024, 2),
        'used_pct' => round($usedPct, 2),
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

        $iface = $parts[0];
        if ($iface === 'lo') {
            continue;
        }

        $rx += (int)$parts[1];
        $tx += (int)$parts[9];
    }

    return ['rx_bytes' => $rx, 'tx_bytes' => $tx];
}

function collect_sample(): array
{
    $timestamp = time();
    $mem = get_memory_stats();
    $net = get_network_totals();
    $load = sys_getloadavg();

    $sample = [
        'ts' => $timestamp,
        'cpu_pct' => get_cpu_usage_percent(),
        'mem_total_mb' => $mem['total_mb'],
        'mem_used_mb' => $mem['used_mb'],
        'mem_used_pct' => $mem['used_pct'],
        'net_rx_bytes' => $net['rx_bytes'],
        'net_tx_bytes' => $net['tx_bytes'],
        'load1' => $load[0] ?? null,
        'load5' => $load[1] ?? null,
        'load15' => $load[2] ?? null,
        'hostname' => gethostname() ?: 'unknown',
    ];

    $dailyFile = SAMPLES_DIR . '/' . date('Y-m-d', $timestamp) . '.jsonl';
    file_put_contents($dailyFile, json_encode($sample, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);

    prune_old_samples(MAX_DAYS_TO_KEEP);

    return $sample;
}

function maybe_collect_sample(int $intervalSeconds = SAMPLE_INTERVAL_SECONDS, bool $force = false): array
{
    $lock = fopen(LOCK_FILE, 'c');
    if ($lock === false) {
        return ['collected' => false, 'sample' => null];
    }

    if (!flock($lock, LOCK_EX)) {
        fclose($lock);
        return ['collected' => false, 'sample' => null];
    }

    $state = load_state();
    $now = time();
    $due = ($now - (int)$state['last_collected']) >= $intervalSeconds;

    if ($force || $due) {
        $sample = collect_sample();
        $state['last_collected'] = $now;
        $state['last_sample'] = $sample;
        save_state($state);
        flock($lock, LOCK_UN);
        fclose($lock);

        return ['collected' => true, 'sample' => $sample];
    }

    flock($lock, LOCK_UN);
    fclose($lock);

    return ['collected' => false, 'sample' => $state['last_sample']];
}

function read_daily_samples(string $date): array
{
    $file = SAMPLES_DIR . '/' . $date . '.jsonl';
    if (!file_exists($file)) {
        return [];
    }

    $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return [];
    }

    $samples = [];
    foreach ($lines as $line) {
        $decoded = json_decode($line, true);
        if (is_array($decoded)) {
            $samples[] = $decoded;
        }
    }

    usort($samples, fn(array $a, array $b): int => ($a['ts'] ?? 0) <=> ($b['ts'] ?? 0));

    return $samples;
}

function summarize_samples(array $samples): array
{
    if (count($samples) === 0) {
        return [
            'samples' => 0,
            'cpu_avg' => null,
            'cpu_min' => null,
            'cpu_max' => null,
            'ram_avg_mb' => null,
            'ram_max_mb' => null,
            'rx_total' => 0,
            'tx_total' => 0,
        ];
    }

    $cpuValues = array_values(array_filter(array_map(
        fn(array $sample): ?float => is_numeric($sample['cpu_pct'] ?? null) ? (float)$sample['cpu_pct'] : null,
        $samples
    ), fn(?float $value): bool => $value !== null));

    $ramValues = array_values(array_filter(array_map(
        fn(array $sample): ?float => is_numeric($sample['mem_used_mb'] ?? null) ? (float)$sample['mem_used_mb'] : null,
        $samples
    ), fn(?float $value): bool => $value !== null));

    $rxTotal = 0;
    $txTotal = 0;

    for ($i = 1; $i < count($samples); $i++) {
        $prevRx = (int)($samples[$i - 1]['net_rx_bytes'] ?? 0);
        $currRx = (int)($samples[$i]['net_rx_bytes'] ?? 0);
        $prevTx = (int)($samples[$i - 1]['net_tx_bytes'] ?? 0);
        $currTx = (int)($samples[$i]['net_tx_bytes'] ?? 0);

        $rxTotal += $currRx >= $prevRx ? ($currRx - $prevRx) : $currRx;
        $txTotal += $currTx >= $prevTx ? ($currTx - $prevTx) : $currTx;
    }

    return [
        'samples' => count($samples),
        'cpu_avg' => count($cpuValues) > 0 ? round(array_sum($cpuValues) / count($cpuValues), 2) : null,
        'cpu_min' => count($cpuValues) > 0 ? round(min($cpuValues), 2) : null,
        'cpu_max' => count($cpuValues) > 0 ? round(max($cpuValues), 2) : null,
        'ram_avg_mb' => count($ramValues) > 0 ? round(array_sum($ramValues) / count($ramValues), 2) : null,
        'ram_max_mb' => count($ramValues) > 0 ? round(max($ramValues), 2) : null,
        'rx_total' => $rxTotal,
        'tx_total' => $txTotal,
    ];
}

function format_bytes(float|int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $value = (float)$bytes;
    $index = 0;

    while ($value >= 1024 && $index < count($units) - 1) {
        $value /= 1024;
        $index++;
    }

    return number_format($value, 2) . ' ' . $units[$index];
}

function list_available_days(): array
{
    $files = glob(SAMPLES_DIR . '/*.jsonl');
    if ($files === false) {
        return [];
    }

    $days = array_map(static function (string $path): string {
        return basename($path, '.jsonl');
    }, $files);

    rsort($days);
    return $days;
}

function prune_old_samples(int $daysToKeep): void
{
    $days = list_available_days();
    if (count($days) <= $daysToKeep) {
        return;
    }

    $toDelete = array_slice($days, $daysToKeep);
    foreach ($toDelete as $day) {
        $file = SAMPLES_DIR . '/' . $day . '.jsonl';
        if (file_exists($file)) {
            @unlink($file);
        }
    }
}

function load_announcements(): array
{
    $announcements = read_json_file(ANNOUNCEMENTS_FILE, []);
    if (!is_array($announcements)) {
        return [];
    }

    usort($announcements, static function (array $a, array $b): int {
        $aPinned = (bool)($a['pinned'] ?? false);
        $bPinned = (bool)($b['pinned'] ?? false);
        if ($aPinned !== $bPinned) {
            return $aPinned ? -1 : 1;
        }

        return ((int)($b['created_at'] ?? 0)) <=> ((int)($a['created_at'] ?? 0));
    });

    return $announcements;
}

function save_announcements(array $announcements): void
{
    write_json_file(ANNOUNCEMENTS_FILE, $announcements);
}

function add_announcement(string $title, string $message, bool $pinned): bool
{
    $title = trim($title);
    $message = trim($message);

    if ($title === '' || $message === '') {
        return false;
    }

    $announcements = load_announcements();
    $announcements[] = [
        'id' => bin2hex(random_bytes(8)),
        'title' => substr($title, 0, 120),
        'message' => substr($message, 0, 5000),
        'pinned' => $pinned,
        'created_at' => time(),
    ];

    save_announcements($announcements);
    return true;
}

function delete_announcement(string $id): void
{
    $announcements = load_announcements();
    $announcements = array_values(array_filter(
        $announcements,
        static fn(array $item): bool => (string)($item['id'] ?? '') !== $id
    ));

    save_announcements($announcements);
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }

    return $_SESSION['csrf_token'];
}

function csrf_valid(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals((string)$_SESSION['csrf_token'], $token);
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}
