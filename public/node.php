<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

secure_session_start();
send_security_headers();

ensure_storage();
maybe_collect_sample(SAMPLE_INTERVAL_SECONDS);

$selectedDate = date('Y-m-d');
if (isset($_GET['date']) && is_string($_GET['date']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['date']) === 1) {
    $selectedDate = $_GET['date'];
}

$nodeId = isset($_GET['node_id']) ? (int)$_GET['node_id'] : 0;
$nodes = all_nodes(true);
$selectedNode = null;
foreach ($nodes as $node) {
    if ((int)$node['id'] === $nodeId) {
        $selectedNode = $node;
        break;
    }
}

$locationsMap = get_locations_map();

$availableDays = list_available_days(30);
$samples = $selectedNode !== null ? read_daily_samples((int)$selectedNode['id'], $selectedDate) : [];
$summary = summarize_samples($samples);

$perPageOptions = [25, 50, 100];
$perPage = isset($_GET['per_page']) && in_array((int)$_GET['per_page'], $perPageOptions, true) ? (int)$_GET['per_page'] : 25;
$totalSamples = count($samples);
$totalPages = $totalSamples > 0 ? (int)ceil($totalSamples / $perPage) : 1;
$currentPage = isset($_GET['page']) ? max(1, min((int)$_GET['page'], $totalPages)) : 1;
$samplesPage = array_slice($samples, ($currentPage - 1) * $perPage, $perPage);
$latest = $selectedNode !== null ? latest_sample_for_node((int)$selectedNode['id']) : null;
$liveStatus = node_live_status($latest);
$uptime30 = $selectedNode !== null ? node_uptime_percent((int)$selectedNode['id'], 30) : null;
$uptime7 = $selectedNode !== null ? node_uptime_percent((int)$selectedNode['id'], 7) : null;
$days30 = last_days(30);
$dayStatuses = [];
if ($selectedNode !== null) {
  foreach ($days30 as $day) {
    $dayStatuses[$day] = node_day_status((int)$selectedNode['id'], $day);
  }
}
$hostName = is_string($latest['hostname'] ?? null) && trim((string)$latest['hostname']) !== '' ? (string)$latest['hostname'] : 'N/A';
$osName = is_string($latest['os_name'] ?? null) && trim((string)$latest['os_name']) !== '' ? (string)$latest['os_name'] : 'N/A';
$cpuName = is_string($latest['cpu_name'] ?? null) && trim((string)$latest['cpu_name']) !== '' ? (string)$latest['cpu_name'] : 'N/A';
$cpuCores = is_numeric($latest['cpu_cores'] ?? null) ? (int)$latest['cpu_cores'] : null;
$memTotal = is_numeric($latest['mem_total_mb'] ?? null) ? (float)$latest['mem_total_mb'] : null;
$memUsed = is_numeric($latest['mem_used_mb'] ?? null) ? (float)$latest['mem_used_mb'] : null;
$memPctNow = is_numeric($latest['mem_used_pct'] ?? null) ? (float)$latest['mem_used_pct'] : null;
$swapTotal = is_numeric($latest['swap_total_mb'] ?? null) ? (float)$latest['swap_total_mb'] : null;
$swapUsed = is_numeric($latest['swap_used_mb'] ?? null) ? (float)$latest['swap_used_mb'] : null;
$swapPctNow = is_numeric($latest['swap_used_pct'] ?? null) ? (float)$latest['swap_used_pct'] : null;
$diskTotal = is_numeric($latest['disk_total_gb'] ?? null) ? (float)$latest['disk_total_gb'] : null;
$diskUsed = is_numeric($latest['disk_used_gb'] ?? null) ? (float)$latest['disk_used_gb'] : null;
$diskPctNow = is_numeric($latest['disk_used_pct'] ?? null) ? (float)$latest['disk_used_pct'] : null;
$cpuPctNow = is_numeric($latest['cpu_pct'] ?? null) ? (float)$latest['cpu_pct'] : null;
$load1 = is_numeric($latest['load1'] ?? null) ? (float)$latest['load1'] : null;
$load5 = is_numeric($latest['load5'] ?? null) ? (float)$latest['load5'] : null;
$load15 = is_numeric($latest['load15'] ?? null) ? (float)$latest['load15'] : null;
$uptimeSeconds = is_numeric($latest['uptime_seconds'] ?? null) ? (int)$latest['uptime_seconds'] : null;

$uptimeHuman = 'N/A';
if ($uptimeSeconds !== null) {
    $d = (int)floor($uptimeSeconds / 86400);
    $h = (int)floor(($uptimeSeconds % 86400) / 3600);
    $m = (int)floor(($uptimeSeconds % 3600) / 60);
    $parts = [];
    if ($d > 0) { $parts[] = $d . 'd'; }
    if ($h > 0 || $d > 0) { $parts[] = $h . 'h'; }
    $parts[] = $m . 'm';
    $uptimeHuman = implode(' ', $parts);
}

$nodeCountry = $selectedNode !== null ? strtoupper(trim((string)($selectedNode['country'] ?? ''))) : '';
$nodeLocation = $nodeCountry !== '' ? ($locationsMap[$nodeCountry] ?? $nodeCountry) : '';

$metricClass = static function (?float $value): string {
    if ($value === null) { return 'usage-na'; }
    if ($value >= 90) { return 'usage-critical'; }
    if ($value >= 75) { return 'usage-warn'; }
    return 'usage-ok';
};

$labels = [];
$cpuSeries = [];
$ramSeries = [];
foreach ($samples as $sample) {
    $labels[] = date('H:i', (int)($sample['ts'] ?? 0));
    $cpuSeries[] = is_numeric($sample['cpu_pct'] ?? null) ? (float)$sample['cpu_pct'] : 0.0;
    $ramSeries[] = is_numeric($sample['mem_used_pct'] ?? null) ? (float)$sample['mem_used_pct'] : 0.0;
}

$statusText = match ($liveStatus) {
    'up' => 'ONLINE',
    'down' => 'OFFLINE',
    'degraded' => 'DEGRADED',
    'stale' => 'STALE',
    default => 'UNKNOWN',
};
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="300">
  <meta name="description" content="Detailed metrics and uptime history for <?= $selectedNode !== null ? e((string)$selectedNode['name']) : 'node' ?> — CPU, RAM, disk, network monitoring.">
  <meta name="robots" content="index, follow">
  <title><?= e(APP_NAME) ?> - <?= $selectedNode !== null ? e((string)$selectedNode['name']) : 'Node Details' ?></title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-wrap">
      <a class="brand" href="/">
        <span class="brand-as"><?= e(trim(get_state_value('network_asn', 'AS201131'))) ?></span>
        <span class="brand-name"><?= e(trim(get_state_value('network_org', 'Liga Hosting Ltd'))) ?></span>
      </a>
      <nav class="topbar-nav">
        <a class="nav-link" href="/">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15.41 7.41 14 6l-6 6 6 6 1.41-1.41L10.83 12z"/></svg>
          Back to Fleet
        </a>
      </nav>
    </div>
  </header>

  <main class="wrap">
    <?php if ($selectedNode === null): ?>
      <section class="panel detail-placeholder">
        <div class="panel-head compact-head">
          <div>
            <h2>Node not found</h2>
            <p>Select a valid node from the overview table.</p>
          </div>
          <a class="btn-secondary reset-link" href="/">Go back</a>
        </div>
      </section>
    <?php else: ?>

      <!-- Node identity header -->
      <section class="nd-header">
        <div class="nd-identity">
          <div class="nd-title-row">
            <h1><?= e((string)$selectedNode['name']) ?></h1>
            <span class="status-chip sc-<?= e($liveStatus) ?>"><?= e($statusText) ?></span>
          </div>
          <div class="nd-meta-row">
            <span><?= e($hostName) ?></span>
            <?php if ($nodeLocation !== ''): ?>
              <span class="nd-sep">&bull;</span>
              <span class="fleet-location-tag"><?= e($nodeCountry) ?></span>
              <span><?= e($nodeLocation) ?></span>
            <?php endif; ?>
            <span class="nd-sep">&bull;</span>
            <span><?= e((string)$selectedNode['node_type']) ?></span>
          </div>
        </div>
        <form method="get" class="nd-date-picker">
          <input type="hidden" name="node_id" value="<?= e((string)$selectedNode['id']) ?>">
          <input type="date" name="date" value="<?= e($selectedDate) ?>">
          <button class="btn-primary" type="submit">Load</button>
        </form>
      </section>

      <!-- Uptime strip (30d) -->
      <section class="panel nd-uptime-panel">
        <div class="nd-uptime-head">
          <div>
            <h2>Uptime</h2>
            <p>30-day availability history</p>
          </div>
          <div class="nd-uptime-stats">
            <div class="nd-uptime-badge">
              <span class="summary-label">30d</span>
              <strong><?= $uptime30 !== null ? e(number_format((float)$uptime30, 3)) . '%' : 'N/A' ?></strong>
            </div>
            <div class="nd-uptime-badge">
              <span class="summary-label">7d</span>
              <strong><?= $uptime7 !== null ? e(number_format((float)$uptime7, 3)) . '%' : 'N/A' ?></strong>
            </div>
          </div>
        </div>
        <div class="uptime-strip nd-uptime-strip">
          <?php foreach ($dayStatuses as $day => $dayStatus): ?>
            <span class="uptime-block ub-<?= e($dayStatus) ?>" title="<?= e($day . ' — ' . $dayStatus) ?>"></span>
          <?php endforeach; ?>
        </div>
        <div class="nd-uptime-legend">
          <span class="nd-legend-item"><span class="nd-legend-dot ub-up"></span> Up</span>
          <span class="nd-legend-item"><span class="nd-legend-dot ub-degraded"></span> Degraded</span>
          <span class="nd-legend-item"><span class="nd-legend-dot ub-down"></span> Down</span>
          <span class="nd-legend-item"><span class="nd-legend-dot ub-unknown"></span> No data</span>
          <span class="nd-legend-dates"><?= e($days30[0]) ?> &mdash; <?= e($days30[count($days30) - 1]) ?></span>
        </div>
      </section>

      <!-- Hardware & Resource cards -->
      <div class="nd-cards-grid">
        <section class="panel nd-card">
          <h3>System</h3>
          <div class="nd-kv-list">
            <div class="nd-kv"><span>Hostname</span><strong><?= e($hostName) ?></strong></div>
            <div class="nd-kv"><span>OS</span><strong><?= e($osName) ?></strong></div>
            <div class="nd-kv"><span>CPU</span><strong><?= e($cpuName) ?></strong></div>
            <div class="nd-kv"><span>Cores</span><strong><?= $cpuCores !== null ? e((string)$cpuCores) : 'N/A' ?></strong></div>
            <?php if ($load1 !== null): ?>
              <div class="nd-kv"><span>Load avg</span><strong><?= e(number_format($load1, 2)) ?> / <?= e(number_format($load5 ?? 0, 2)) ?> / <?= e(number_format($load15 ?? 0, 2)) ?></strong></div>
            <?php endif; ?>
            <div class="nd-kv"><span>Uptime</span><strong><?= e($uptimeHuman) ?></strong></div>
          </div>
        </section>

        <section class="panel nd-card">
          <h3>Resources (live)</h3>
          <div class="nd-resource-bars">
            <div class="nd-bar-group">
              <div class="nd-bar-label">
                <span>CPU</span>
                <span class="<?= e($metricClass($cpuPctNow)) ?>"><?= $cpuPctNow !== null ? e(number_format($cpuPctNow, 1)) . '%' : 'N/A' ?></span>
              </div>
              <div class="nd-bar-track"><div class="nd-bar-fill <?= e($metricClass($cpuPctNow)) ?>" style="width:<?= $cpuPctNow !== null ? e(number_format(min($cpuPctNow, 100), 1)) : '0' ?>%"></div></div>
            </div>
            <div class="nd-bar-group">
              <div class="nd-bar-label">
                <span>RAM<?= $memTotal !== null ? ' (' . e(number_format($memUsed !== null ? $memUsed / 1024 : 0, 1)) . '/' . e(number_format($memTotal / 1024, 1)) . ' GB)' : '' ?></span>
                <span class="<?= e($metricClass($memPctNow)) ?>"><?= $memPctNow !== null ? e(number_format($memPctNow, 1)) . '%' : 'N/A' ?></span>
              </div>
              <div class="nd-bar-track"><div class="nd-bar-fill <?= e($metricClass($memPctNow)) ?>" style="width:<?= $memPctNow !== null ? e(number_format(min($memPctNow, 100), 1)) : '0' ?>%"></div></div>
            </div>
            <div class="nd-bar-group">
              <div class="nd-bar-label">
                <span>Disk<?= $diskTotal !== null ? ' (' . e(number_format($diskUsed ?? 0, 1)) . '/' . e(number_format($diskTotal, 1)) . ' GB)' : '' ?></span>
                <span class="<?= e($metricClass($diskPctNow)) ?>"><?= $diskPctNow !== null ? e(number_format($diskPctNow, 1)) . '%' : 'N/A' ?></span>
              </div>
              <div class="nd-bar-track"><div class="nd-bar-fill <?= e($metricClass($diskPctNow)) ?>" style="width:<?= $diskPctNow !== null ? e(number_format(min($diskPctNow, 100), 1)) : '0' ?>%"></div></div>
            </div>
            <div class="nd-bar-group">
              <div class="nd-bar-label">
                <span>Swap<?= $swapTotal !== null && $swapTotal > 0 ? ' (' . e(number_format(($swapUsed ?? 0) / 1024, 2)) . '/' . e(number_format($swapTotal / 1024, 2)) . ' GB)' : '' ?></span>
                <span class="<?= e($metricClass($swapPctNow)) ?>"><?= $swapPctNow !== null ? e(number_format($swapPctNow, 1)) . '%' : 'N/A' ?></span>
              </div>
              <div class="nd-bar-track"><div class="nd-bar-fill <?= e($metricClass($swapPctNow)) ?>" style="width:<?= $swapPctNow !== null ? e(number_format(min($swapPctNow, 100), 1)) : '0' ?>%"></div></div>
            </div>
          </div>
        </section>

        <section class="panel nd-card">
          <h3>Daily summary (<?= e($selectedDate) ?>)</h3>
          <div class="nd-kv-list">
            <div class="nd-kv"><span>CPU avg</span><strong><?= $summary['cpu_avg'] !== null ? e((string)$summary['cpu_avg']) . '%' : 'N/A' ?></strong></div>
            <div class="nd-kv"><span>RAM avg</span><strong><?= $summary['ram_avg_mb'] !== null ? e(number_format((float)$summary['ram_avg_mb'], 0)) . ' MB' : 'N/A' ?></strong></div>
            <div class="nd-kv"><span>Traffic RX</span><strong><?= e(format_bytes((int)$summary['rx_total'])) ?></strong></div>
            <div class="nd-kv"><span>Traffic TX</span><strong><?= e(format_bytes((int)$summary['tx_total'])) ?></strong></div>
            <div class="nd-kv"><span>Samples</span><strong><?= e((string)$summary['samples']) ?></strong></div>
          </div>
        </section>
      </div>

      <!-- Trend chart -->
      <section class="panel nd-chart-panel">
        <div class="panel-head compact-head">
          <div>
            <h2>CPU &amp; RAM trend</h2>
            <p><?= e($selectedDate) ?> &bull; <?= e((string)count($samples)) ?> samples</p>
          </div>
          <div class="nd-chart-legend">
            <span class="nd-cl-item"><span class="nd-cl-dot" style="background:#3fb950"></span> CPU</span>
            <span class="nd-cl-item"><span class="nd-cl-dot" style="background:#58a6ff"></span> RAM</span>
          </div>
        </div>
        <canvas id="trendChart" height="200"></canvas>
      </section>

      <!-- Available days -->
      <?php if (count($availableDays) > 0): ?>
        <section class="panel nd-days-panel">
          <div class="panel-head compact-head">
            <h2>Available days</h2>
          </div>
          <div class="days-list">
            <?php foreach ($availableDays as $day): ?>
              <a class="<?= $day === $selectedDate ? 'day-active' : '' ?>" href="/node.php?node_id=<?= e((string)$selectedNode['id']) ?>&date=<?= e($day) ?>"><?= e($day) ?></a>
            <?php endforeach; ?>
          </div>
        </section>
      <?php endif; ?>

      <!-- Sample table -->
      <section class="panel nd-table-panel">
        <div class="panel-head compact-head">
          <div>
            <h2>Raw samples</h2>
            <p>All data points collected on <?= e($selectedDate) ?> &bull; <?= e((string)$totalSamples) ?> total &bull; page <?= e((string)$currentPage) ?>/<?= e((string)$totalPages) ?></p>
          </div>
          <div class="nd-pagination-controls">
            <form method="get" class="nd-per-page-form">
              <input type="hidden" name="node_id" value="<?= e((string)$selectedNode['id']) ?>">
              <input type="hidden" name="date" value="<?= e($selectedDate) ?>">
              <label>
                <select name="per_page" onchange="this.form.submit()">
                  <?php foreach ($perPageOptions as $opt): ?>
                    <option value="<?= e((string)$opt) ?>" <?= $opt === $perPage ? 'selected' : '' ?>><?= e((string)$opt) ?> / page</option>
                  <?php endforeach; ?>
                </select>
              </label>
            </form>
          </div>
        </div>
        <div class="table-wrap">
          <table class="nd-samples-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Status</th>
                <th>CPU</th>
                <th>RAM</th>
                <th>Disk</th>
                <th>Swap</th>
                <th>RX</th>
                <th>TX</th>
                <th>Load</th>
              </tr>
            </thead>
            <tbody>
              <?php if (count($samplesPage) === 0): ?>
                <tr><td colspan="9" class="empty-state">No data for this node and day.</td></tr>
              <?php else: ?>
                <?php foreach ($samplesPage as $sample): ?>
                  <tr>
                    <td><?= e(date('H:i:s', (int)$sample['ts'])) ?></td>
                    <td><span class="pill pill-<?= e((string)$sample['status']) ?>"><?= e((string)$sample['status']) ?></span></td>
                    <td><?= is_numeric($sample['cpu_pct'] ?? null) ? e(number_format((float)$sample['cpu_pct'], 1)) . '%' : '-' ?></td>
                    <td><?= is_numeric($sample['mem_used_pct'] ?? null) ? e(number_format((float)$sample['mem_used_pct'], 1)) . '%' : '-' ?></td>
                    <td><?= is_numeric($sample['disk_used_pct'] ?? null) ? e(number_format((float)$sample['disk_used_pct'], 1)) . '%' : '-' ?></td>
                    <td><?= is_numeric($sample['swap_used_pct'] ?? null) ? e(number_format((float)$sample['swap_used_pct'], 1)) . '%' : '-' ?></td>
                    <td><?= e(format_bytes(isset($sample['net_rx_bytes']) ? (int)$sample['net_rx_bytes'] : null)) ?></td>
                    <td><?= e(format_bytes(isset($sample['net_tx_bytes']) ? (int)$sample['net_tx_bytes'] : null)) ?></td>
                    <td><?= is_numeric($sample['load1'] ?? null) ? e(number_format((float)$sample['load1'], 2)) : '-' ?></td>
                  </tr>
                <?php endforeach; ?>
              <?php endif; ?>
            </tbody>
          </table>
        </div>
        <?php if ($totalPages > 1): ?>
          <nav class="nd-pagination">
            <?php
            $pageUrl = static function (int $p) use ($selectedNode, $selectedDate, $perPage): string {
                $params = ['node_id' => (string)$selectedNode['id'], 'date' => $selectedDate, 'page' => (string)$p];
                if ($perPage !== 25) { $params['per_page'] = (string)$perPage; }
                return '/node.php?' . http_build_query($params);
            };
            ?>
            <?php if ($currentPage > 1): ?>
              <a class="nd-page-link" href="<?= e($pageUrl(1)) ?>">&laquo;</a>
              <a class="nd-page-link" href="<?= e($pageUrl($currentPage - 1)) ?>">&lsaquo;</a>
            <?php endif; ?>
            <?php
            $startP = max(1, $currentPage - 2);
            $endP = min($totalPages, $currentPage + 2);
            for ($p = $startP; $p <= $endP; $p++): ?>
              <a class="nd-page-link<?= $p === $currentPage ? ' nd-page-active' : '' ?>" href="<?= e($pageUrl($p)) ?>"><?= e((string)$p) ?></a>
            <?php endfor; ?>
            <?php if ($currentPage < $totalPages): ?>
              <a class="nd-page-link" href="<?= e($pageUrl($currentPage + 1)) ?>">&rsaquo;</a>
              <a class="nd-page-link" href="<?= e($pageUrl($totalPages)) ?>">&raquo;</a>
            <?php endif; ?>
          </nav>
        <?php endif; ?>
      </section>
    <?php endif; ?>
  </main>

  <script>
    const labels = <?= json_encode($labels, JSON_UNESCAPED_SLASHES) ?>;
    const cpuSeries = <?= json_encode($cpuSeries, JSON_UNESCAPED_SLASHES) ?>;
    const ramSeries = <?= json_encode($ramSeries, JSON_UNESCAPED_SLASHES) ?>;
    const canvas = document.getElementById('trendChart');

    function drawChart() {
      if (!canvas) {
        return;
      }

      const ctx = canvas.getContext('2d');
      const dpr = window.devicePixelRatio || 1;
      const width = canvas.clientWidth;
      const height = 200;
      const pad = { top: 16, right: 12, bottom: 24, left: 36 };
      const plotWidth = width - pad.left - pad.right;
      const plotHeight = height - pad.top - pad.bottom;

      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(dpr, dpr);

      const dark = true;
      const bg = '#0e1520';
      const grid = 'rgba(148, 163, 184, 0.18)';
      const text = '#94a3b8';

      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = bg;
      ctx.fillRect(0, 0, width, height);

      ctx.strokeStyle = grid;
      ctx.lineWidth = 1;
      ctx.font = '10px Space Grotesk, sans-serif';
      ctx.fillStyle = text;
      ctx.textAlign = 'right';

      for (let i = 0; i <= 4; i += 1) {
        const gy = pad.top + (i / 4) * plotHeight;
        ctx.beginPath();
        ctx.moveTo(pad.left, gy);
        ctx.lineTo(pad.left + plotWidth, gy);
        ctx.stroke();
        ctx.fillText(String(100 - i * 25) + '%', pad.left - 6, gy + 3);
      }

      if (labels.length < 2) {
        ctx.textAlign = 'center';
        ctx.fillText('No chart data for this day', width / 2, height / 2);
        return;
      }

      const x = (index) => pad.left + (index / (labels.length - 1)) * plotWidth;
      const y = (value) => pad.top + (1 - Math.max(0, Math.min(100, value)) / 100) * plotHeight;

      function drawSeries(series, color) {
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        series.forEach((value, index) => {
          const px = x(index);
          const py = y(Number(value) || 0);
          if (index === 0) {
            ctx.moveTo(px, py);
          } else {
            ctx.lineTo(px, py);
          }
        });
        ctx.stroke();
      }

      drawSeries(cpuSeries, '#3fb950');
      drawSeries(ramSeries, '#58a6ff');

      ctx.textAlign = 'center';
      const step = Math.max(1, Math.floor(labels.length / 6));
      labels.forEach((label, index) => {
        if (index % step === 0 || index === labels.length - 1) {
          ctx.fillStyle = text;
          ctx.fillText(label, x(index), height - 6);
        }
      });
    }

    drawChart();
    window.addEventListener('resize', drawChart);
  </script>

  <footer class="site-footer">
    <div class="topbar-wrap footer-wrap">
      <div class="footer-left">
        <span class="footer-brand"><?= e(trim(get_state_value('network_asn', 'AS201131'))) ?></span>
        <span class="footer-org"><?= e(trim(get_state_value('network_org', 'LIGA HOSTING LTD'))) ?></span>
      </div>
      <div class="footer-right">
        <span>Last refresh <?= e(date('H:i:s')) ?> UTC</span>
        <span class="footer-sep">&bull;</span>
        <span>Auto-refresh 5 min</span>
      </div>
    </div>
  </footer>
</body>
</html>
