<?php

declare(strict_types=1);

session_start();

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

ensure_storage();
maybe_collect_sample(SAMPLE_INTERVAL_SECONDS);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string)($_POST['csrf_token'] ?? '');
    $action = (string)($_POST['action'] ?? '');

    if (csrf_valid($token)) {
        if ($action === 'add_announcement') {
            $title = (string)($_POST['title'] ?? '');
            $message = (string)($_POST['message'] ?? '');
            $pinned = isset($_POST['pinned']) && $_POST['pinned'] === '1';
            add_announcement($title, $message, $pinned);
        }

        if ($action === 'delete_announcement') {
            $id = (string)($_POST['id'] ?? '');
            if ($id !== '') {
                delete_announcement($id);
            }
        }

        header('Location: /');
        exit;
    }
}

$selectedDate = date('Y-m-d');
if (isset($_GET['date']) && is_string($_GET['date']) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET['date']) === 1) {
    $selectedDate = $_GET['date'];
}

$samples = read_daily_samples($selectedDate);
$summary = summarize_samples($samples);
$days = list_available_days();
$announcements = load_announcements();
$state = load_state();
$lastSample = $state['last_sample'];

$labels = [];
$cpuSeries = [];
$ramSeries = [];
foreach ($samples as $sample) {
    $labels[] = date('H:i', (int)($sample['ts'] ?? 0));
    $cpuSeries[] = (float)($sample['cpu_pct'] ?? 0);
    $ramSeries[] = (float)($sample['mem_used_pct'] ?? 0);
}

function severity_class(?float $value, float $warnAt, float $criticalAt): string
{
  if ($value === null) {
    return 'neutral';
  }

  if ($value >= $criticalAt) {
    return 'critical';
  }

  if ($value >= $warnAt) {
    return 'warn';
  }

  return 'ok';
}

function sparkline_points(array $series, int $width = 132, int $height = 30): string
{
  if (count($series) < 2) {
    return '';
  }

  $count = count($series);
  $points = [];

  foreach ($series as $i => $value) {
    $x = $count === 1 ? 0 : ($i / ($count - 1)) * $width;
    $safe = max(0, min(100, (float)$value));
    $y = (1 - ($safe / 100)) * $height;
    $points[] = number_format($x, 2, '.', '') . ',' . number_format($y, 2, '.', '');
  }

  return implode(' ', $points);
}

$cpuAvg = is_numeric($summary['cpu_avg']) ? (float)$summary['cpu_avg'] : null;
$ramNowPct = is_numeric($lastSample['mem_used_pct'] ?? null) ? (float)$lastSample['mem_used_pct'] : null;
$cpuSeverity = severity_class($cpuAvg, 65, 85);
$ramSeverity = severity_class($ramNowPct, 75, 90);
$sampleCoverage = (int)$summary['samples'];
$sampleSeverity = $sampleCoverage < 3 ? 'warn' : 'ok';
$cpuSparkline = sparkline_points($cpuSeries);
$ramSparkline = sparkline_points($ramSeries);

$discordLink = 'https://discord.gg/';
$companyLinks = [
  [
    'name' => 'ligahosting.ro',
    'subtitle' => 'Game Hosting',
    'url' => 'https://ligahosting.ro',
    'badge' => 'RO',
  ],
  [
    'name' => 'ligahosting.com',
    'subtitle' => 'VPS Hosting',
    'url' => 'https://ligahosting.com',
    'badge' => 'COM',
  ],
];
?>
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="300">
  <title><?= e(APP_NAME) ?> - Status</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="bg-shape"></div>
  <main class="container">
    <header class="hero">
      <div class="hero-head top-ribbon">
        <span class="infra-pill">GLOBAL INFRASTRUCTURE</span>
        <div class="hero-actions">
          <a class="link-btn" href="<?= e($discordLink) ?>" target="_blank" rel="noopener noreferrer">Discord Server</a>
          <button type="button" id="themeToggle" class="ghost-btn">Toggle Theme</button>
        </div>
      </div>
      <div class="brand-mark">
        <h1><span>AS</span>201131</h1>
        <p>LIGA HOSTING LTD</p>
      </div>
      <div class="hero-meta">
        <span>Gazda: <?= e((string)($lastSample['hostname'] ?? gethostname() ?: 'unknown')) ?></span>
        <span>Ultima colectare: <?= $lastSample ? e(date('Y-m-d H:i:s', (int)$lastSample['ts'])) : 'N/A' ?></span>
      </div>
    </header>

    <section class="grid company-links">
      <?php foreach ($companyLinks as $company): ?>
        <a class="company-card" href="<?= e((string)$company['url']) ?>" target="_blank" rel="noopener noreferrer">
          <div class="company-badge"><?= e((string)$company['badge']) ?></div>
          <div>
            <h2><?= e((string)$company['name']) ?></h2>
            <p><?= e((string)$company['subtitle']) ?></p>
          </div>
          <span class="company-arrow">-></span>
        </a>
      <?php endforeach; ?>
    </section>

    <section class="grid stats">
      <article class="card severity-<?= e($cpuSeverity) ?>">
        <h2>CPU (zi)</h2>
        <p class="metric"><?= $summary['cpu_avg'] !== null ? e((string)$summary['cpu_avg']) . '%' : 'N/A' ?></p>
        <p>Min: <?= $summary['cpu_min'] !== null ? e((string)$summary['cpu_min']) . '%' : 'N/A' ?> / Max: <?= $summary['cpu_max'] !== null ? e((string)$summary['cpu_max']) . '%' : 'N/A' ?></p>
        <?php if ($cpuSparkline !== ''): ?>
          <svg class="sparkline" viewBox="0 0 132 30" preserveAspectRatio="none" aria-label="CPU sparkline">
            <polyline points="<?= e($cpuSparkline) ?>"></polyline>
          </svg>
        <?php endif; ?>
      </article>
      <article class="card severity-<?= e($ramSeverity) ?>">
        <h2>RAM (zi)</h2>
        <p class="metric"><?= $summary['ram_avg_mb'] !== null ? e(number_format((float)$summary['ram_avg_mb'], 2)) . ' MB' : 'N/A' ?></p>
        <p>Varf: <?= $summary['ram_max_mb'] !== null ? e(number_format((float)$summary['ram_max_mb'], 2)) . ' MB' : 'N/A' ?></p>
        <?php if ($ramSparkline !== ''): ?>
          <svg class="sparkline" viewBox="0 0 132 30" preserveAspectRatio="none" aria-label="RAM sparkline">
            <polyline points="<?= e($ramSparkline) ?>"></polyline>
          </svg>
        <?php endif; ?>
      </article>
      <article class="card">
        <h2>Network (zi)</h2>
        <p class="metric"><?= e(format_bytes((int)$summary['rx_total'])) ?></p>
        <p>RX total, TX total: <?= e(format_bytes((int)$summary['tx_total'])) ?></p>
      </article>
      <article class="card severity-<?= e($sampleSeverity) ?>">
        <h2>Esantioane</h2>
        <p class="metric"><?= e((string)$summary['samples']) ?></p>
        <p>Granularitate: 5 minute</p>
      </article>
    </section>

    <section class="grid two-cols">
      <article class="card">
        <div class="card-head">
          <h2>Anunturi</h2>
        </div>

        <form method="post" class="announce-form">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="add_announcement">
          <label>Titlu
            <input type="text" name="title" maxlength="120" required>
          </label>
          <label>Mesaj
            <textarea name="message" rows="4" maxlength="5000" required></textarea>
          </label>
          <label class="checkbox">
            <input type="checkbox" name="pinned" value="1"> Pin in partea de sus
          </label>
          <button type="submit">Publica anunt</button>
        </form>

        <div class="announce-list">
          <?php if (count($announcements) === 0): ?>
            <p class="empty">Nu exista anunturi momentan.</p>
          <?php endif; ?>

          <?php foreach ($announcements as $item): ?>
            <article class="announcement">
              <div class="announcement-head">
                <h3><?= e((string)$item['title']) ?></h3>
                <span><?= e(date('Y-m-d H:i', (int)$item['created_at'])) ?></span>
              </div>
              <?php if (!empty($item['pinned'])): ?>
                <div class="badge">PINNED</div>
              <?php endif; ?>
              <p><?= nl2br(e((string)$item['message'])) ?></p>
              <form method="post">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                <input type="hidden" name="action" value="delete_announcement">
                <input type="hidden" name="id" value="<?= e((string)$item['id']) ?>">
                <button class="danger" type="submit">Sterge</button>
              </form>
            </article>
          <?php endforeach; ?>
        </div>
      </article>

      <article class="card">
        <div class="card-head">
          <h2>Trend zilnic</h2>
          <form method="get">
            <label>
              Data
              <input type="date" name="date" value="<?= e($selectedDate) ?>">
            </label>
            <button type="submit">Vezi</button>
          </form>
        </div>

        <canvas id="trendChart" height="220"></canvas>

        <details>
          <summary>Zile disponibile</summary>
          <ul class="days">
            <?php foreach ($days as $day): ?>
              <li><a href="/?date=<?= e($day) ?>"><?= e($day) ?></a></li>
            <?php endforeach; ?>
          </ul>
        </details>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Ora</th>
                <th>CPU %</th>
                <th>RAM %</th>
                <th>RAM MB</th>
                <th>RX total</th>
                <th>TX total</th>
              </tr>
            </thead>
            <tbody>
            <?php if (count($samples) === 0): ?>
              <tr>
                <td colspan="6">Nu exista date pentru aceasta zi.</td>
              </tr>
            <?php else: ?>
              <?php foreach ($samples as $sample): ?>
              <tr>
                <td><?= e(date('H:i:s', (int)$sample['ts'])) ?></td>
                <td><?= e((string)($sample['cpu_pct'] ?? 'N/A')) ?></td>
                <td><?= e((string)($sample['mem_used_pct'] ?? 'N/A')) ?></td>
                <td><?= e((string)($sample['mem_used_mb'] ?? 'N/A')) ?></td>
                <td><?= e(format_bytes((int)($sample['net_rx_bytes'] ?? 0))) ?></td>
                <td><?= e(format_bytes((int)($sample['net_tx_bytes'] ?? 0))) ?></td>
              </tr>
              <?php endforeach; ?>
            <?php endif; ?>
            </tbody>
          </table>
        </div>
      </article>
    </section>
  </main>

  <script>
    const labels = <?= json_encode($labels, JSON_UNESCAPED_SLASHES) ?>;
    const cpuSeries = <?= json_encode($cpuSeries, JSON_UNESCAPED_SLASHES) ?>;
    const ramSeries = <?= json_encode($ramSeries, JSON_UNESCAPED_SLASHES) ?>;

    const canvas = document.getElementById('trendChart');
    const ctx = canvas.getContext('2d');

    function drawLineChart() {
      const w = canvas.width = canvas.clientWidth * devicePixelRatio;
      const h = canvas.height = 220 * devicePixelRatio;
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.scale(devicePixelRatio, devicePixelRatio);

      ctx.clearRect(0, 0, w, h);
      const width = canvas.clientWidth;
      const height = 220;
      const pad = 28;
      const plotW = width - pad * 2;
      const plotH = height - pad * 2;

      ctx.fillStyle = '#f6f7fb';
      ctx.fillRect(0, 0, width, height);
      ctx.strokeStyle = '#d5d8e3';
      ctx.strokeRect(pad, pad, plotW, plotH);

      if (labels.length < 2) {
        ctx.fillStyle = '#4f5568';
        ctx.fillText('Insuficiente date pentru grafic.', pad + 4, pad + 20);
        return;
      }

      const maxValue = 100;
      const x = (idx) => pad + (idx / (labels.length - 1)) * plotW;
      const y = (value) => pad + (1 - value / maxValue) * plotH;

      function strokeSeries(series, color) {
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        series.forEach((value, idx) => {
          const px = x(idx);
          const py = y(Math.min(maxValue, Math.max(0, Number(value) || 0)));
          if (idx === 0) {
            ctx.moveTo(px, py);
          } else {
            ctx.lineTo(px, py);
          }
        });
        ctx.stroke();
      }

      strokeSeries(cpuSeries, '#006d77');
      strokeSeries(ramSeries, '#e76f51');

      ctx.fillStyle = '#1f2433';
      ctx.fillRect(pad + 6, 8, 10, 10);
      ctx.fillText('CPU %', pad + 22, 17);
      ctx.fillStyle = '#e76f51';
      ctx.fillRect(pad + 74, 8, 10, 10);
      ctx.fillStyle = '#1f2433';
      ctx.fillText('RAM %', pad + 90, 17);
    }

    drawLineChart();
    window.addEventListener('resize', drawLineChart);

    const themeToggle = document.getElementById('themeToggle');
    const savedTheme = localStorage.getItem('status-theme');
    if (savedTheme === 'dark') {
      document.body.setAttribute('data-theme', 'dark');
    }

    themeToggle.addEventListener('click', () => {
      const isDark = document.body.getAttribute('data-theme') === 'dark';
      if (isDark) {
        document.body.removeAttribute('data-theme');
        localStorage.setItem('status-theme', 'light');
      } else {
        document.body.setAttribute('data-theme', 'dark');
        localStorage.setItem('status-theme', 'dark');
      }
    });
  </script>
</body>
</html>
