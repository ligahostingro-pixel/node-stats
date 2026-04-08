<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';
require_once dirname(__DIR__) . '/lib/world_map_paths.php';

secure_session_start();
send_security_headers();

ensure_storage();
maybe_collect_sample(SAMPLE_INTERVAL_SECONDS);

$nodes = all_nodes(true);
$announcements = load_announcements();
$allAnnouncementUpdates = load_all_announcement_updates();
$days7 = last_days(7);

$statusFilter = isset($_GET['status']) && is_string($_GET['status']) ? trim($_GET['status']) : 'all';
$typeFilter = isset($_GET['type']) && is_string($_GET['type']) ? trim($_GET['type']) : 'all';
$sort = isset($_GET['sort']) && is_string($_GET['sort']) ? trim($_GET['sort']) : 'uptime_desc';
$search = isset($_GET['q']) && is_string($_GET['q']) ? trim($_GET['q']) : '';
$announcementFilter = isset($_GET['ann']) && is_string($_GET['ann']) ? trim($_GET['ann']) : 'active';

$networkAsn = trim(get_state_value('network_asn', 'AS201131'));
$networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
$networkPrefixesRaw = trim(get_state_value('network_prefixes', "2.27.119.0/24\n5.180.33.0/24\n87.76.205.0/24\n163.5.26.0/24"));
$networkCountriesRaw = trim(get_state_value('network_countries', 'RO, NL, DE, US'));
$networkPowerLabel = trim(get_state_value('network_power_label', 'Anycast-ready edge, transit, anti-DDoS and low-latency backbone.'));

$networkPrefixes = array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $networkPrefixesRaw) ?: []), static fn(string $v): bool => $v !== ''));
$networkCountries = array_values(array_filter(array_map('trim', explode(',', $networkCountriesRaw)), static fn(string $v): bool => $v !== ''));
$networkPrefixesV6Raw = trim(get_state_value('network_prefixes_v6', ''));
$networkPrefixesV6 = $networkPrefixesV6Raw !== '' ? array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $networkPrefixesV6Raw) ?: []), static fn(string $v): bool => $v !== '')) : [];
if (count($networkPrefixes) === 0) {
  $networkPrefixes = ['2.27.119.0/24', '5.180.33.0/24'];
}
if (count($networkCountries) === 0) {
  $networkCountries = ['RO', 'DE', 'NL'];
}

$allowedStatus = ['all', 'up', 'degraded', 'down', 'stale', 'unknown'];
$allowedType = ['all', 'local', 'remote'];
$allowedSort = ['uptime_desc', 'uptime_asc', 'name_asc', 'name_desc', 'last_check_desc', 'last_check_asc', 'status'];

if (!in_array($statusFilter, $allowedStatus, true)) {
    $statusFilter = 'all';
}
if (!in_array($typeFilter, $allowedType, true)) {
    $typeFilter = 'all';
}
if (!in_array($sort, $allowedSort, true)) {
    $sort = 'uptime_desc';
}
if (!in_array($announcementFilter, ['all', 'active', 'upcoming', 'resolved'], true)) {
  $announcementFilter = 'active';
}
$annPgNum = max(1, (int)($_GET['ann_pg'] ?? 1));
$annPgSize = 5;

$now = time();
$levelRank = [
  'info' => 0,
  'maintenance' => 1,
  'degraded' => 2,
  'critical' => 3,
];

$globalIncidentLevel = null;
$nodeIncidentLevels = [];
$maintenanceTimeline = [];
$announcementRows = [];
$activeIncidentsCount = 0;
$scheduledMaintenancesCount = 0;

foreach ($announcements as $item) {
  $level = is_string($item['level'] ?? null) ? (string)$item['level'] : 'info';
  $startsAt = is_numeric($item['starts_at'] ?? null) ? (int)$item['starts_at'] : null;
  $endsAt = is_numeric($item['ends_at'] ?? null) ? (int)$item['ends_at'] : null;
  $nodeId = is_numeric($item['node_id'] ?? null) ? (int)$item['node_id'] : null;

  $isIncident = in_array($level, ['maintenance', 'degraded', 'critical'], true);
  $hasWindow = $startsAt !== null || $endsAt !== null;
  $isActiveWindow = ($startsAt === null || $startsAt <= $now) && ($endsAt === null || $endsAt >= $now);
  $isResolved = !empty($item['resolved_at']);
  $isActiveIncident = $isIncident && !$isResolved && ($hasWindow ? $isActiveWindow : true);
  $isUpcomingMaintenance = $level === 'maintenance' && !$isResolved && $startsAt !== null && $startsAt > $now;

  $item['is_active_incident'] = $isActiveIncident;
  $item['is_upcoming_maintenance'] = $isUpcomingMaintenance;
  $announcementRows[] = $item;

  if ($isActiveIncident) {
    $activeIncidentsCount++;
    if ($nodeId === null || $nodeId <= 0) {
      if ($globalIncidentLevel === null || ($levelRank[$level] ?? -1) > ($levelRank[$globalIncidentLevel] ?? -1)) {
        $globalIncidentLevel = $level;
      }
    } else {
      $current = $nodeIncidentLevels[$nodeId] ?? null;
      if ($current === null || ($levelRank[$level] ?? -1) > ($levelRank[$current] ?? -1)) {
        $nodeIncidentLevels[$nodeId] = $level;
      }
    }
  }

  if ($level === 'maintenance' && ($isActiveIncident || $isUpcomingMaintenance) && empty($item['resolved_at'])) {
    $maintenanceTimeline[] = $item;
  }
  if ($isUpcomingMaintenance) {
    $scheduledMaintenancesCount++;
  }
}

usort(
  $maintenanceTimeline,
  static function (array $left, array $right): int {
    $leftStart = is_numeric($left['starts_at'] ?? null) ? (int)$left['starts_at'] : PHP_INT_MAX;
    $rightStart = is_numeric($right['starts_at'] ?? null) ? (int)$right['starts_at'] : PHP_INT_MAX;
    return $leftStart <=> $rightStart;
  }
);

if ($announcementFilter === 'active') {
  $announcementRows = array_values(array_filter(
    $announcementRows,
    static fn(array $item): bool => (bool)($item['is_active_incident'] ?? false) && empty($item['resolved_at'])
  ));
} elseif ($announcementFilter === 'upcoming') {
  $announcementRows = array_values(array_filter(
    $announcementRows,
    static fn(array $item): bool => (bool)($item['is_upcoming_maintenance'] ?? false)
  ));
} elseif ($announcementFilter === 'resolved') {
  $announcementRows = array_values(array_filter(
    $announcementRows,
    static fn(array $item): bool => !empty($item['resolved_at'])
  ));
}

usort($announcementRows, static function (array $a, array $b) use ($levelRank): int {
  $aPinned = !empty($a['pinned']) ? 1 : 0;
  $bPinned = !empty($b['pinned']) ? 1 : 0;
  if ($aPinned !== $bPinned) {
    return $bPinned <=> $aPinned;
  }

  $aActive = !empty($a['is_active_incident']) ? 1 : 0;
  $bActive = !empty($b['is_active_incident']) ? 1 : 0;
  if ($aActive !== $bActive) {
    return $bActive <=> $aActive;
  }

  $aRank = $levelRank[is_string($a['level'] ?? null) ? (string)$a['level'] : 'info'] ?? -1;
  $bRank = $levelRank[is_string($b['level'] ?? null) ? (string)$b['level'] : 'info'] ?? -1;
  if ($aRank !== $bRank) {
    return $bRank <=> $aRank;
  }

  return ((int)($b['created_at'] ?? 0)) <=> ((int)($a['created_at'] ?? 0));
});

$annTotalFiltered = count($announcementRows);
$annTotalPg = max(1, (int)ceil($annTotalFiltered / $annPgSize));
if ($annPgNum > $annTotalPg) { $annPgNum = $annTotalPg; }
$announcementRowsPaged = array_slice($announcementRows, ($annPgNum - 1) * $annPgSize, $annPgSize);

$statusRank = [
    'down' => 0,
    'degraded' => 1,
    'stale' => 2,
    'unknown' => 3,
    'up' => 4,
];

$nodeRows = [];
$overallStatus = 'up';
$latestSamplesMap = all_latest_samples();
foreach ($nodes as $node) {
    $nodeId = (int)$node['id'];
    $latest = $latestSamplesMap[$nodeId] ?? null;
    $liveStatus = node_live_status($latest);
    $uptime = node_uptime_percent($nodeId, 7);
    $days = [];
    foreach ($days7 as $day) {
        $days[$day] = node_day_status($nodeId, $day);
    }

    $row = [
        'node' => $node,
        'latest' => $latest,
        'live_status' => $liveStatus,
      'incident_level' => $nodeIncidentLevels[$nodeId] ?? $globalIncidentLevel,
        'uptime' => $uptime,
        'days' => $days,
        'last_check_ts' => $latest !== null ? (int)($latest['ts'] ?? 0) : 0,
    ];

    $matchesStatus = $statusFilter === 'all' || $liveStatus === $statusFilter;
    $matchesType = $typeFilter === 'all' || (string)($node['node_type'] ?? '') === $typeFilter;
    $matchesSearch = $search === '' || stripos((string)($node['name'] ?? ''), $search) !== false;

    if ($matchesStatus && $matchesType && $matchesSearch) {
        $nodeRows[] = $row;
    }

    if ($liveStatus === 'down') {
        $overallStatus = 'down';
    } elseif (in_array($liveStatus, ['degraded', 'stale', 'unknown'], true) && $overallStatus === 'up') {
        $overallStatus = 'degraded';
    }
}

usort(
    $nodeRows,
    static function (array $left, array $right) use ($sort, $statusRank): int {
        return match ($sort) {
            'uptime_asc' => ($left['uptime'] ?? -1) <=> ($right['uptime'] ?? -1),
            'uptime_desc' => ($right['uptime'] ?? -1) <=> ($left['uptime'] ?? -1),
            'name_desc' => strcasecmp((string)$right['node']['name'], (string)$left['node']['name']),
            'last_check_asc' => (int)$left['last_check_ts'] <=> (int)$right['last_check_ts'],
            'last_check_desc' => (int)$right['last_check_ts'] <=> (int)$left['last_check_ts'],
            'status' => ($statusRank[(string)$left['live_status']] ?? 999) <=> ($statusRank[(string)$right['live_status']] ?? 999),
            default => strcasecmp((string)$left['node']['name'], (string)$right['node']['name']),
        };
    }
);

$overallMap = [
  'up' => ['All systems operational', 'ob-up'],
  'degraded' => ['Partial degradation detected', 'ob-degraded'],
  'down' => ['Major incident in progress', 'ob-down'],
];
[$overallLabel, $overallClass] = $overallMap[$overallStatus] ?? $overallMap['up'];

// Compute aggregate fleet stats
$fleetCpuValues = [];
$fleetRamValues = [];
$fleetDiskValues = [];
$fleetTotalRamMb = 0.0;
$fleetTotalDiskGb = 0.0;
$fleetTotalCores = 0;
$fleetOnlineCount = 0;
$fleetNetRxRate = 0;
$fleetNetTxRate = 0;
$locationsMap = get_locations_map();
foreach ($nodeRows as $row) {
  $l = $row['latest'];
  if ($l === null) { continue; }
  if ((string)$row['live_status'] === 'up') { $fleetOnlineCount++; }
  if (is_numeric($l['cpu_pct'] ?? null)) { $fleetCpuValues[] = (float)$l['cpu_pct']; }
  if (is_numeric($l['mem_used_pct'] ?? null)) { $fleetRamValues[] = (float)$l['mem_used_pct']; }
  if (is_numeric($l['disk_used_pct'] ?? null)) { $fleetDiskValues[] = (float)$l['disk_used_pct']; }
  if (is_numeric($l['mem_total_mb'] ?? null)) { $fleetTotalRamMb += (float)$l['mem_total_mb']; }
  if (is_numeric($l['disk_total_gb'] ?? null)) { $fleetTotalDiskGb += (float)$l['disk_total_gb']; }
  if (is_numeric($l['cpu_cores'] ?? null)) { $fleetTotalCores += (int)$l['cpu_cores']; }
  [$nRx, $nTx] = node_net_rate((int)$row['node']['id']);
  $fleetNetRxRate += $nRx;
  $fleetNetTxRate += $nTx;
}
$fleetAvgCpu = count($fleetCpuValues) > 0 ? round(array_sum($fleetCpuValues) / count($fleetCpuValues), 1) : null;
$fleetAvgRam = count($fleetRamValues) > 0 ? round(array_sum($fleetRamValues) / count($fleetRamValues), 1) : null;
$fleetAvgDisk = count($fleetDiskValues) > 0 ? round(array_sum($fleetDiskValues) / count($fleetDiskValues), 1) : null;

// Map location coordinates (approximate center of each country as % of a 1000x500 equirectangular map)
$countryCoords = [
  'RO' => [57.3, 12.7], 'NL' => [51.4, 10.4], 'DE' => [53.7, 10.4], 'US' => [22.8, 14.4],
  'GB' => [50.0, 10.7], 'FR' => [50.6, 11.4], 'PL' => [55.8, 10.5], 'FI' => [56.9, 8.3],
  'SE' => [55.0, 8.5], 'NO' => [53.0, 8.4], 'ES' => [49.0, 13.8], 'IT' => [53.5, 13.4],
  'CH' => [52.1, 12.0], 'AT' => [54.6, 11.6], 'BE' => [51.2, 10.9], 'PT' => [47.5, 14.3],
  'RU' => [60.4, 9.5], 'UA' => [58.5, 11.0], 'BG' => [56.5, 13.1], 'CZ' => [54.0, 11.1],
  'DK' => [53.5, 9.5], 'HU' => [55.3, 11.8], 'IE' => [48.3, 10.2], 'LT' => [57.0, 9.8],
  'LV' => [56.7, 9.2], 'EE' => [56.9, 8.5], 'HR' => [54.4, 12.3], 'RS' => [55.7, 12.6],
  'SK' => [54.8, 11.6], 'SI' => [54.0, 12.2], 'LU' => [51.7, 11.2], 'MD' => [58.0, 11.9],
  'GR' => [56.6, 14.4], 'TR' => [59.1, 13.9], 'CY' => [59.3, 15.2], 'MT' => [54.0, 15.0],
  'CA' => [29.0, 12.4], 'BR' => [36.7, 29.4], 'AR' => [33.8, 34.6], 'MX' => [22.5, 19.6],
  'JP' => [88.8, 15.1], 'KR' => [85.3, 14.6], 'CN' => [82.3, 13.9], 'IN' => [71.4, 17.1],
  'SG' => [78.8, 24.6], 'AU' => [91.4, 34.8], 'NZ' => [98.6, 36.5], 'ZA' => [57.8, 32.1],
  'AE' => [65.4, 18.0], 'IL' => [59.7, 16.1], 'EG' => [58.7, 16.7], 'NG' => [52.1, 22.5],
  'KE' => [60.2, 25.4], 'CL' => [30.4, 34.3], 'CO' => [29.4, 23.7], 'PE' => [28.6, 28.3],
  'TH' => [77.9, 21.2], 'VN' => [79.4, 19.2], 'MY' => [78.3, 24.1], 'PH' => [83.6, 20.9],
  'ID' => [79.7, 26.7], 'TW' => [83.8, 18.1], 'HK' => [81.7, 18.8], 'PK' => [70.3, 15.6],
];

$mapLocations = [];
$nodesByCountry = [];
foreach ($nodes as $node) {
  $cc = strtoupper(trim((string)($node['country'] ?? '')));
  if ($cc === '') { continue; }
  if (!isset($nodesByCountry[$cc])) { $nodesByCountry[$cc] = ['total' => 0, 'up' => 0]; }
  $nodesByCountry[$cc]['total']++;
  $nLatest = latest_sample_for_node((int)$node['id']);
  if (node_live_status($nLatest) === 'up') { $nodesByCountry[$cc]['up']++; }
}

// Always include configured network countries on the map even if no node has that country set
foreach ($networkCountries as $cc) {
  $cc = strtoupper(trim($cc));
  if ($cc === '' || isset($nodesByCountry[$cc])) { continue; }
  $nodesByCountry[$cc] = ['total' => 0, 'up' => 0];
}

foreach ($nodesByCountry as $cc => $info) {
  if (!isset($countryCoords[$cc])) { continue; }
  [$cx, $cy] = $countryCoords[$cc];
  $allUp = $info['total'] === 0 || $info['up'] === $info['total'];
  $mapLocations[] = [
    'cc' => $cc,
    'x' => $cx,
    'y' => $cy,
    'count' => $info['total'],
    'up' => $info['up'],
    'status' => $info['total'] === 0 ? 'up' : ($allUp ? 'up' : ($info['up'] > 0 ? 'degraded' : 'down')),
    'label' => $locationsMap[$cc] ?? $cc,
  ];
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="refresh" content="60">
  <meta name="description" content="Real-time infrastructure status and uptime monitoring for <?= e($networkOrg) ?> (<?= e($networkAsn) ?>). View fleet health, network locations, and operational announcements.">
  <meta name="robots" content="index, follow">
  <meta property="og:title" content="<?= e(APP_NAME) ?> - <?= e($networkOrg) ?>">
  <meta property="og:description" content="Live status page for <?= e($networkOrg) ?> infrastructure. Monitor node health, uptime, and incidents.">
  <meta property="og:type" content="website">
  <title><?= e(APP_NAME) ?> - Fleet Overview</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-wrap">
      <a class="brand" href="/">
        <span class="brand-as"><?= e($networkAsn !== '' ? $networkAsn : 'AS201131') ?></span>
        <span class="brand-name"><?= e($networkOrg !== '' ? $networkOrg : 'Liga Hosting Ltd') ?></span>
      </a>

      <nav class="topbar-nav">
        <div class="nav-dropdown">
          <button class="nav-link nav-dropdown-btn" type="button" aria-expanded="false">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2Zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93Zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39Z"/></svg>
            Website
            <svg class="dd-arrow" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10l5 5 5-5z"/></svg>
          </button>
          <div class="nav-dropdown-menu">
            <a class="dd-item" href="https://ligahosting.ro" target="_blank" rel="noopener noreferrer">
              <strong>ligahosting.ro</strong>
              <span>Game Hosting &mdash; Minecraft, FiveM, CS2 &amp; more</span>
            </a>
            <a class="dd-item" href="https://ligahosting.com" target="_blank" rel="noopener noreferrer">
              <strong>ligahosting.com</strong>
              <span>VPS &amp; Dedicated &mdash; Cloud infrastructure</span>
            </a>
          </div>
        </div>
        <a class="nav-link" href="https://discord.gg/liga" target="_blank" rel="noopener noreferrer">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20.32 4.37a19.8 19.8 0 0 0-4.93-1.52.07.07 0 0 0-.07.03c-.21.37-.44.86-.61 1.24a18.37 18.37 0 0 0-5.43 0c-.17-.39-.41-.87-.62-1.24a.08.08 0 0 0-.07-.03c-1.7.3-3.35.82-4.93 1.52a.07.07 0 0 0-.03.03C.53 9.12-.33 13.72.09 18.27a.08.08 0 0 0 .03.05 19.9 19.9 0 0 0 6.04 3.06.08.08 0 0 0 .08-.03c.47-.64.9-1.32 1.27-2.03a.08.08 0 0 0-.04-.11 13 13 0 0 1-1.9-.91.08.08 0 0 1-.01-.13c.13-.1.26-.21.39-.32a.08.08 0 0 1 .08-.01c3.98 1.82 8.3 1.82 12.23 0a.08.08 0 0 1 .09.01c.13.11.26.22.39.32a.08.08 0 0 1-.01.13c-.6.35-1.24.65-1.9.91a.08.08 0 0 0-.04.11c.38.71.8 1.39 1.27 2.03a.08.08 0 0 0 .08.03 19.84 19.84 0 0 0 6.05-3.06.08.08 0 0 0 .03-.05c.5-5.26-.84-9.82-3.55-13.87a.06.06 0 0 0-.03-.03ZM8.02 15.5c-1.2 0-2.19-1.1-2.19-2.45s.96-2.45 2.19-2.45c1.24 0 2.22 1.1 2.2 2.45 0 1.35-.97 2.45-2.2 2.45Zm7.96 0c-1.2 0-2.19-1.1-2.19-2.45s.96-2.45 2.19-2.45c1.24 0 2.22 1.1 2.2 2.45 0 1.35-.96 2.45-2.2 2.45Z"/></svg>
          Discord
        </a>
        <a class="nav-link" href="https://bgp.tools/as/201131" target="_blank" rel="noopener noreferrer">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2ZM4 9h10.5v3.5H4V9Zm0 5.5h10.5V18H4v-3.5ZM20 18h-3.5V9H20v9Z"/></svg>
          BGP
        </a>
        <a class="nav-link" href="/subscribe">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z"/></svg>
          Subscribe
        </a>
      </nav>
    </div>
  </header>

  <main class="wrap">
    <div class="status-banner <?= e($overallClass) ?>">
      <span class="ob-dot<?= $overallStatus === 'up' ? ' animate' : '' ?>"></span>
      <?= e($overallLabel) ?>
    </div>

    <section class="hero">
      <div class="hero-text">
        <p class="eyebrow">NOC Overview</p>
        <h1>Infrastructure operational status</h1>
        <p class="hero-copy">Centralized per-node monitoring with quick filters, visible severity levels, and operational announcements linked to affected nodes.</p>
      </div>
      <div class="hero-cards">
        <div class="hero-stat">
          <span class="hero-label">Nodes online</span>
          <strong><?= e((string)$fleetOnlineCount) ?> / <?= e((string)count($nodeRows)) ?></strong>
        </div>
        <div class="hero-stat">
          <span class="hero-label">Collect interval</span>
          <strong>1 min</strong>
        </div>
        <div class="hero-stat">
          <span class="hero-label">Locations</span>
          <strong><?= e((string)count($networkCountries)) ?> countries</strong>
        </div>
      </div>
    </section>

    <section class="panel incident-strip-panel">
      <div class="incident-strip">
        <span class="incident-pill incident-live"><?= e((string)$activeIncidentsCount) ?> active incident<?= $activeIncidentsCount !== 1 ? 's' : '' ?></span>
        <span class="incident-pill incident-plan"><?= e((string)$scheduledMaintenancesCount) ?> scheduled maintenance<?= $scheduledMaintenancesCount !== 1 ? 's' : '' ?></span>
        <span class="incident-note">Click a node link in any announcement to highlight it in the fleet table.</span>
      </div>
    </section>

    <section class="panel asn-panel">
      <div class="panel-head compact-head">
        <div>
          <h2>Announced Prefixes</h2>
          <p><?= e($networkAsn !== '' ? $networkAsn : 'AS201131') ?> &bull; <?= e($networkOrg !== '' ? $networkOrg : 'LIGA HOSTING LTD') ?></p>
        </div>
        <div class="prefix-toggle-group">
          <button class="prefix-toggle is-active" data-prefix-target="v4" type="button">IPv4 <small>(<?= e((string)count($networkPrefixes)) ?>)</small></button>
          <button class="prefix-toggle" data-prefix-target="v6" type="button">IPv6 <small>(<?= e((string)count($networkPrefixesV6)) ?>)</small></button>
        </div>
      </div>

      <div class="prefix-grid" id="prefixGridV4">
        <?php foreach ($networkPrefixes as $prefix): ?>
          <article class="prefix-card">
            <div>
              <span class="prefix-type-tag">IPv4</span>
              <h3><?= e($prefix) ?></h3>
              <p><?= e($networkOrg !== '' ? $networkOrg : 'LIGA HOSTING LTD') ?></p>
            </div>
            <span class="prefix-state">ACTIVE</span>
          </article>
        <?php endforeach; ?>
      </div>

      <div class="prefix-grid" id="prefixGridV6" hidden>
        <?php if (count($networkPrefixesV6) === 0): ?>
          <p class="empty-state" style="grid-column:1/-1">No IPv6 prefixes announced yet.</p>
        <?php else: ?>
          <?php foreach ($networkPrefixesV6 as $prefix): ?>
            <article class="prefix-card prefix-card-v6">
              <div>
                <span class="prefix-type-tag">IPv6</span>
                <h3><?= e($prefix) ?></h3>
                <p><?= e($networkOrg !== '' ? $networkOrg : 'LIGA HOSTING LTD') ?></p>
              </div>
              <span class="prefix-state">ACTIVE</span>
            </article>
          <?php endforeach; ?>
        <?php endif; ?>
      </div>

      <div class="asn-stats-grid">
        <article class="asn-stat-card">
          <span class="summary-label">Total nodes</span>
          <strong><?= e((string)count($nodes)) ?></strong>
        </article>
        <article class="asn-stat-card">
          <span class="summary-label">IPv4 / IPv6 prefixes</span>
          <strong><?= e((string)count($networkPrefixes)) ?> / <?= e((string)count($networkPrefixesV6)) ?></strong>
        </article>
        <article class="asn-stat-card">
          <span class="summary-label">Presence countries</span>
          <div class="country-chips">
            <?php foreach ($networkCountries as $country): ?>
              <span class="country-chip"><?= e($country) ?></span>
            <?php endforeach; ?>
          </div>
        </article>
        <article class="asn-stat-card">
          <span class="summary-label">Network power</span>
          <p><?= e($networkPowerLabel !== '' ? $networkPowerLabel : 'Edge, transit and operational capacity across announced prefixes.') ?></p>
        </article>
      </div>
    </section>

    <section class="panel fleet-power-panel">
      <div class="panel-head compact-head">
        <div>
          <h2>Fleet aggregate</h2>
          <p>Combined resource capacity and current utilization across all monitored nodes.</p>
        </div>
      </div>
      <div class="fleet-power-grid">
        <article class="fp-card">
          <span class="summary-label">Total CPU cores</span>
          <strong><?= e($fleetTotalCores > 0 ? (string)$fleetTotalCores : 'N/A') ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">Total RAM</span>
          <strong><?= $fleetTotalRamMb > 0 ? e(number_format($fleetTotalRamMb / 1024, 1)) . ' GB' : 'N/A' ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">Total Disk</span>
          <strong><?= $fleetTotalDiskGb > 0 ? e(number_format($fleetTotalDiskGb, 0)) . ' GB' : 'N/A' ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">Net In</span>
          <strong><?= $fleetNetRxRate > 0 ? e(format_bytes($fleetNetRxRate)) . '/s' : 'N/A' ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">Avg CPU usage</span>
          <strong class="<?= $fleetAvgCpu !== null && $fleetAvgCpu >= 90 ? 'fp-critical' : ($fleetAvgCpu !== null && $fleetAvgCpu >= 75 ? 'fp-warn' : 'fp-ok') ?>"><?= $fleetAvgCpu !== null ? e(number_format($fleetAvgCpu, 1)) . '%' : 'N/A' ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">RAM usage</span>
          <strong class="<?= $fleetAvgRam !== null && $fleetAvgRam >= 90 ? 'fp-critical' : ($fleetAvgRam !== null && $fleetAvgRam >= 75 ? 'fp-warn' : 'fp-ok') ?>"><?= $fleetAvgRam !== null ? e(number_format($fleetAvgRam, 1)) . '%' : 'N/A' ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">Storage usage</span>
          <strong class="<?= $fleetAvgDisk !== null && $fleetAvgDisk >= 90 ? 'fp-critical' : ($fleetAvgDisk !== null && $fleetAvgDisk >= 75 ? 'fp-warn' : 'fp-ok') ?>"><?= $fleetAvgDisk !== null ? e(number_format($fleetAvgDisk, 1)) . '%' : 'N/A' ?></strong>
        </article>
        <article class="fp-card">
          <span class="summary-label">Net Out</span>
          <strong><?= $fleetNetTxRate > 0 ? e(format_bytes($fleetNetTxRate)) . '/s' : 'N/A' ?></strong>
        </article>
      </div>
    </section>

    <?php if (count($mapLocations) > 0): ?>
    <section class="panel noc-map-panel">
      <div class="panel-head compact-head">
        <div>
          <h2>Network locations</h2>
          <p>Geographic distribution of monitored infrastructure across <?= e((string)count($mapLocations)) ?> location(s).</p>
        </div>
      </div>

      <div class="noc-map-wrap">
        <svg class="noc-map-svg" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <radialGradient id="pulse-up" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="var(--green)" stop-opacity="0.5"/>
              <stop offset="100%" stop-color="var(--green)" stop-opacity="0"/>
            </radialGradient>
            <radialGradient id="pulse-degraded" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="var(--yellow)" stop-opacity="0.5"/>
              <stop offset="100%" stop-color="var(--yellow)" stop-opacity="0"/>
            </radialGradient>
            <radialGradient id="pulse-down" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stop-color="var(--red)" stop-opacity="0.5"/>
              <stop offset="100%" stop-color="var(--red)" stop-opacity="0"/>
            </radialGradient>
          </defs>

          <!-- Grid lines -->
          <g class="noc-map-grid" stroke="var(--line)" stroke-width="0.5" opacity="0.3">
            <line x1="0" y1="125" x2="1000" y2="125"/>
            <line x1="0" y1="250" x2="1000" y2="250"/>
            <line x1="0" y1="375" x2="1000" y2="375"/>
            <line x1="250" y1="0" x2="250" y2="500"/>
            <line x1="500" y1="0" x2="500" y2="500"/>
            <line x1="750" y1="0" x2="750" y2="500"/>
          </g>

          <!-- World countries (equirectangular projection, generated from Natural Earth 110m) -->
          <g class="noc-map-land" fill="rgba(148,163,184,0.13)" stroke="rgba(148,163,184,0.30)" stroke-width="0.5" stroke-linejoin="round">
            <?= world_map_svg_paths() ?>
          </g>

          <!-- Connection lines between locations -->
          <?php if (count($mapLocations) > 1): ?>
            <g class="noc-map-connections">
              <?php for ($i = 0; $i < count($mapLocations); $i++): ?>
                <?php for ($j = $i + 1; $j < count($mapLocations); $j++): ?>
                  <line
                    x1="<?= e((string)($mapLocations[$i]['x'] * 10)) ?>"
                    y1="<?= e((string)($mapLocations[$i]['y'] * 10)) ?>"
                    x2="<?= e((string)($mapLocations[$j]['x'] * 10)) ?>"
                    y2="<?= e((string)($mapLocations[$j]['y'] * 10)) ?>"
                    stroke="var(--cyan)"
                    stroke-width="0.8"
                    stroke-dasharray="6 4"
                    opacity="0.15"
                  />
                <?php endfor; ?>
              <?php endfor; ?>
            </g>
          <?php endif; ?>

          <!-- Location points -->
          <?php foreach ($mapLocations as $loc): ?>
            <?php
            $px = $loc['x'] * 10;
            $py = $loc['y'] * 10;
            $statusColor = match ($loc['status']) {
              'up' => 'var(--green)',
              'degraded' => 'var(--yellow)',
              default => 'var(--red)',
            };
            $pulseId = 'pulse-' . $loc['status'];
            ?>
            <g class="noc-map-point" data-location="<?= e($loc['cc']) ?>" data-label="<?= e($loc['label']) ?>">
              <!-- Pulse ring -->
              <circle cx="<?= e((string)$px) ?>" cy="<?= e((string)$py) ?>" r="20" fill="url(#<?= e($pulseId) ?>)" class="noc-pulse-ring"/>
              <!-- Outer glow -->
              <circle cx="<?= e((string)$px) ?>" cy="<?= e((string)$py) ?>" r="8" fill="<?= $statusColor ?>" opacity="0.15"/>
              <!-- Core dot -->
              <circle cx="<?= e((string)$px) ?>" cy="<?= e((string)$py) ?>" r="4.5" fill="<?= $statusColor ?>" stroke="<?= $statusColor ?>" stroke-width="1.5" stroke-opacity="0.4"/>
              <!-- Inner bright dot -->
              <circle cx="<?= e((string)$px) ?>" cy="<?= e((string)$py) ?>" r="2" fill="#fff" opacity="0.9"/>
            </g>
          <?php endforeach; ?>
        </svg>

        <!-- Map tooltip -->
        <div class="noc-map-tooltip" id="mapTooltip" hidden>
          <span class="noc-map-tooltip-cc"></span>
          <span class="noc-map-tooltip-label"></span>
        </div>

        <!-- Location legend cards -->
        <div class="noc-map-legend">
          <?php foreach ($mapLocations as $loc): ?>
            <div class="noc-map-loc-card" data-location="<?= e($loc['cc']) ?>">
              <span class="noc-loc-dot noc-loc-<?= e($loc['status']) ?>"></span>
              <div class="noc-loc-info">
                <strong><?= e($loc['cc']) ?></strong>
                <span><?= e($loc['label']) ?></span>
              </div>
              <span class="noc-loc-count"><?= $loc['count'] > 0 ? e((string)$loc['up']) . '/' . e((string)$loc['count']) . ' <small>up</small>' : '<small>POP</small>' ?></span>
            </div>
          <?php endforeach; ?>
        </div>
      </div>
    </section>
    <?php endif; ?>

    <?php if (count($maintenanceTimeline) > 0): ?>
      <section class="panel maintenance-panel">
        <div class="panel-head compact-head">
          <div>
            <h2>Active & scheduled maintenances</h2>
            <p>Operational timeline for announced interventions.</p>
          </div>
        </div>
        <div class="maintenance-timeline">
          <?php foreach (array_slice($maintenanceTimeline, 0, 6) as $item): ?>
            <?php
            $targetNode = is_string($item['node_name'] ?? null) && trim((string)$item['node_name']) !== '' ? (string)$item['node_name'] : 'All nodes';
            $startText = !empty($item['starts_at']) ? date('Y-m-d H:i', (int)$item['starts_at']) : 'ASAP';
            $endText = !empty($item['ends_at']) ? date('Y-m-d H:i', (int)$item['ends_at']) : 'until resolved';
            $stateText = !empty($item['is_active_incident']) ? 'active now' : 'scheduled';
            ?>
            <article class="mt-item">
              <div class="mt-head">
                <strong><?= e((string)$item['title']) ?></strong>
                <span class="mt-state <?= !empty($item['is_active_incident']) ? 'mt-active' : 'mt-scheduled' ?>"><?= e($stateText) ?></span>
              </div>
              <p><?= e($targetNode) ?> • <?= e($startText) ?> -> <?= e($endText) ?></p>
            </article>
          <?php endforeach; ?>
        </div>
      </section>
    <?php endif; ?>

    <section class="panel fleet-panel" id="fleet">
      <div class="panel-head fleet-head">
        <div>
          <h2>Fleet nodes</h2>
          <p>Compact incident response table: status, uptime, and resource usage at a glance.</p>
        </div>
      </div>

      <form method="get" action="#fleet" class="fleet-filters">
        <label>
          <span>Search</span>
          <input type="text" name="q" value="<?= e($search) ?>" placeholder="Search by node name">
        </label>
        <label>
          <span>Status</span>
          <select name="status">
            <?php foreach ($allowedStatus as $status): ?>
              <option value="<?= e($status) ?>" <?= $status === $statusFilter ? 'selected' : '' ?>><?= e($status) ?></option>
            <?php endforeach; ?>
          </select>
        </label>
        <label>
          <span>Type</span>
          <select name="type">
            <?php foreach ($allowedType as $type): ?>
              <option value="<?= e($type) ?>" <?= $type === $typeFilter ? 'selected' : '' ?>><?= e($type) ?></option>
            <?php endforeach; ?>
          </select>
        </label>
        <label>
          <span>Sort</span>
          <select name="sort">
            <option value="uptime_desc" <?= $sort === 'uptime_desc' ? 'selected' : '' ?>>Uptime descending</option>
            <option value="uptime_asc" <?= $sort === 'uptime_asc' ? 'selected' : '' ?>>Uptime ascending</option>
            <option value="name_asc" <?= $sort === 'name_asc' ? 'selected' : '' ?>>Name A-Z</option>
            <option value="name_desc" <?= $sort === 'name_desc' ? 'selected' : '' ?>>Name Z-A</option>
            <option value="last_check_desc" <?= $sort === 'last_check_desc' ? 'selected' : '' ?>>Last check newest</option>
            <option value="last_check_asc" <?= $sort === 'last_check_asc' ? 'selected' : '' ?>>Last check oldest</option>
            <option value="status" <?= $sort === 'status' ? 'selected' : '' ?>>Status severity</option>
          </select>
        </label>
        <div class="fleet-filter-actions">
          <button class="btn-primary" type="submit">Apply</button>
          <a class="btn-secondary reset-link" href="/">Reset</a>
        </div>
      </form>

      <?php if (count($nodeRows) === 0): ?>
        <div class="admin-empty">No nodes match the selected filters.</div>
      <?php else: ?>
        <div class="fleet-cards-grid">
          <?php foreach ($nodeRows as $row): ?>
            <?php
            $node = $row['node'];
            $latest = $row['latest'];
            $liveStatus = (string)$row['live_status'];
            $nodeId = (int)$node['id'];
            $uptime = $row['uptime'];
            $uptimeText = $uptime !== null ? number_format((float)$uptime, 3) . '%' : 'N/A';
            $lastCheckText = $latest !== null ? date('Y-m-d H:i', (int)($latest['ts'] ?? 0)) : 'never';
            $hostFull = is_string($latest['hostname'] ?? null) && trim((string)$latest['hostname']) !== '' ? (string)$latest['hostname'] : '';
            $hostText = str_contains($hostFull, '.') ? strstr($hostFull, '.', true) : $hostFull;
            $cpuPct = is_numeric($latest['cpu_pct'] ?? null) ? (float)$latest['cpu_pct'] : null;
            $ramPct = is_numeric($latest['mem_used_pct'] ?? null) ? (float)$latest['mem_used_pct'] : null;
            $diskPct = is_numeric($latest['disk_used_pct'] ?? null) ? (float)$latest['disk_used_pct'] : null;
            $swapPct = is_numeric($latest['swap_used_pct'] ?? null) ? (float)$latest['swap_used_pct'] : null;
            $metricClass = static function (?float $value): string {
                if ($value === null) return 'usage-na';
                if ($value >= 90) return 'usage-critical';
                if ($value >= 75) return 'usage-warn';
                return 'usage-ok';
            };
            $statusText = match ($liveStatus) {
                'up' => 'ONLINE',
                'down' => 'OFFLINE',
                'degraded' => 'DEGRADED',
                'stale' => 'STALE',
                default => 'UNKNOWN',
            };
            $incidentLevel = is_string($row['incident_level'] ?? null) ? (string)$row['incident_level'] : '';
            $cardClass = $incidentLevel !== '' ? ' fc-' . $incidentLevel : '';
            $nodeCountry = strtoupper(trim((string)($node['country'] ?? '')));
            $nodeLocation = $nodeCountry !== '' ? ($locationsMap[$nodeCountry] ?? $nodeCountry) : '';
            $uptimeSeconds = is_numeric($latest['uptime_seconds'] ?? null) ? (int)$latest['uptime_seconds'] : null;
            $sysUptimeHuman = '';
            if ($uptimeSeconds !== null) {
                $ud = intdiv($uptimeSeconds, 86400);
                $uh = intdiv($uptimeSeconds % 86400, 3600);
                $um = intdiv($uptimeSeconds % 3600, 60);
                $sysUptimeHuman = ($ud > 0 ? $ud . 'd ' : '') . $uh . 'h ' . $um . 'm';
            }
            ?>
            <a id="node-row-<?= e((string)$nodeId) ?>" data-node-id="<?= e((string)$nodeId) ?>" class="fc-card<?= e($cardClass) ?>" href="/node?node_id=<?= e((string)$nodeId) ?>">
              <div class="fc-top">
                <div class="fc-identity">
                  <div class="fc-name"><?= e((string)$node['name']) ?></div>
                  <div class="fc-host"><?php
                    if ($hostText !== '') echo e($hostText);
                    if ($hostText !== '' && $nodeLocation !== '') echo ' &bull; ';
                    if ($nodeLocation !== '') {
                        echo '<span class="fc-loc-tag">' . e($nodeCountry) . '</span> ' . e($nodeLocation);
                    }
                  ?></div>
                </div>
                <div class="fc-status-area">
                  <span class="status-chip sc-<?= e($liveStatus) ?>"><?= e($statusText) ?></span>
                  <?php if ($incidentLevel !== ''): ?>
                    <span class="node-badge nb-<?= e($incidentLevel) ?>"><?= e($incidentLevel === 'critical' ? 'INCIDENT' : ($incidentLevel === 'maintenance' ? 'MAINT' : strtoupper($incidentLevel))) ?></span>
                  <?php endif; ?>
                </div>
              </div>

              <div class="fc-stats-row">
                <div class="fc-stat">
                  <span class="fc-stat-label">7d Uptime</span>
                  <span class="fc-stat-value fc-uptime"><?= e($uptimeText) ?></span>
                </div>
                <div class="fc-stat">
                  <span class="fc-stat-label">Type</span>
                  <span class="fc-stat-value"><?= e((string)$node['node_type']) ?></span>
                </div>
                <?php if ($sysUptimeHuman !== ''): ?>
                <div class="fc-stat">
                  <span class="fc-stat-label">Uptime</span>
                  <span class="fc-stat-value"><?= e($sysUptimeHuman) ?></span>
                </div>
                <?php endif; ?>
                <div class="fc-stat">
                  <span class="fc-stat-label">Checked</span>
                  <span class="fc-stat-value"><?= e($lastCheckText) ?></span>
                </div>
              </div>

              <div class="fc-resources">
                <?php
                $bars = [
                    ['CPU', $cpuPct],
                    ['RAM', $ramPct],
                    ['Disk', $diskPct],
                    ['Swap', $swapPct],
                ];
                foreach ($bars as [$label, $val]):
                    $cls = $metricClass($val);
                    $pct = $val !== null ? round($val) : 0;
                    $txt = $val !== null ? number_format($val, 0) . '%' : 'N/A';
                ?>
                <div class="fc-bar-row">
                  <span class="fc-bar-name"><?= e($label) ?></span>
                  <div class="fc-bar-track"><div class="fc-bar-fill <?= e($cls) ?>" style="width:<?= $val !== null ? e((string)$pct) : '0' ?>%"></div></div>
                  <span class="fc-bar-val"><?= e($txt) ?></span>
                </div>
                <?php endforeach; ?>
              </div>

              <div class="fc-history">
                <span class="fc-hist-label">7d history</span>
                <div class="uptime-strip fleet-strip fine-strip">
                  <?php foreach ($row['days'] as $day => $dayStatus): ?>
                    <span class="uptime-block ub-<?= e($dayStatus) ?>" title="<?= e($day . ' ' . $dayStatus) ?>"></span>
                  <?php endforeach; ?>
                </div>
              </div>
            </a>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>
    </section>

    <section id="announcements" class="bottom-grid single-col">
      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>Operational announcements</h2>
            <p>Scheduled maintenances, degradations, and critical incidents published by the NOC team.</p>
          </div>
          <?php
          $annFilterUrl = static function (string $val) use ($statusFilter, $typeFilter, $sort, $search): string {
            $params = ['ann' => $val];
            if ($statusFilter !== 'all') { $params['status'] = $statusFilter; }
            if ($typeFilter !== 'all') { $params['type'] = $typeFilter; }
            if ($sort !== 'uptime_desc') { $params['sort'] = $sort; }
            if ($search !== '') { $params['q'] = $search; }
            return '/?' . http_build_query($params) . '#announcements';
          };
          ?>
          <div class="announcement-filter-group">
            <a class="btn-secondary<?= $announcementFilter === 'active' ? ' is-active' : '' ?>" href="<?= e($annFilterUrl('active')) ?>">Active</a>
            <a class="btn-secondary<?= $announcementFilter === 'upcoming' ? ' is-active' : '' ?>" href="<?= e($annFilterUrl('upcoming')) ?>">Upcoming</a>
            <a class="btn-secondary<?= $announcementFilter === 'resolved' ? ' is-active' : '' ?>" href="<?= e($annFilterUrl('resolved')) ?>">Resolved</a>
            <a class="btn-secondary<?= $announcementFilter === 'all' ? ' is-active' : '' ?>" href="<?= e($annFilterUrl('all')) ?>">All</a>
          </div>
        </div>

        <div class="announce-list">
          <?php if (count($announcementRowsPaged) === 0): ?>
            <p class="empty-state">No announcements match the selected filter.</p>
          <?php endif; ?>

          <?php foreach ($announcementRowsPaged as $item): ?>
            <?php
            $level = is_string($item['level'] ?? null) ? (string)$item['level'] : 'info';
            $targetNode = is_string($item['node_name'] ?? null) && trim((string)$item['node_name']) !== '' ? (string)$item['node_name'] : 'All nodes';
            $targetNodeId = is_numeric($item['node_id'] ?? null) ? (int)$item['node_id'] : null;
            $window = null;
            if (!empty($item['starts_at']) || !empty($item['ends_at'])) {
                $startText = !empty($item['starts_at']) ? date('Y-m-d H:i', (int)$item['starts_at']) : 'ASAP';
                $endText = !empty($item['ends_at']) ? date('Y-m-d H:i', (int)$item['ends_at']) : 'until resolved';
                $window = $startText . ' -> ' . $endText;
            }
            ?>
            <article class="announcement-card an-card-<?= e($level) ?><?= !empty($item['is_active_incident']) && empty($item['resolved_at']) ? ' an-card-live' : '' ?><?= !empty($item['resolved_at']) ? ' an-card-resolved' : '' ?>">
              <div class="announcement-head">
                <div>
                  <h3><?= e((string)$item['title']) ?></h3>
                  <div class="announcement-tags">
                    <?php if (!empty($item['resolved_at'])): ?>
                      <span class="an-level an-resolved">RESOLVED</span>
                    <?php else: ?>
                      <span class="an-level an-<?= e($level) ?>"><?= e(strtoupper($level)) ?></span>
                    <?php endif; ?>
                    <?php if ($targetNodeId !== null && $targetNodeId > 0): ?>
                      <a class="an-target an-node-link" href="#node-row-<?= e((string)$targetNodeId) ?>" data-node-id="<?= e((string)$targetNodeId) ?>"><?= e($targetNode) ?></a>
                    <?php else: ?>
                      <span class="an-target"><?= e($targetNode) ?></span>
                    <?php endif; ?>
                    <?php if (!empty($item['pinned'])): ?>
                      <span class="pin-tag">Pinned</span>
                    <?php endif; ?>
                  </div>
                </div>
                <span><?= e(date('Y-m-d H:i', (int)$item['created_at'])) ?><?= !empty($item['resolved_at']) ? ' — Resolved ' . date('Y-m-d H:i', (int)$item['resolved_at']) : '' ?></span>
              </div>
              <?php if ($window !== null): ?>
                <p class="announcement-window">Window: <?= e($window) ?></p>
              <?php endif; ?>
              <p><?= nl2br(e((string)$item['message'])) ?></p>

              <?php
              $pubAnnId = (int)$item['id'];
              $pubUpdates = $allAnnouncementUpdates[$pubAnnId] ?? [];
              ?>
              <?php if (count($pubUpdates) > 0): ?>
                <div class="ann-updates-timeline">
                  <?php foreach ($pubUpdates as $upd): ?>
                    <div class="ann-update-entry">
                      <span class="ann-update-status ann-us-<?= e((string)$upd['status']) ?>"><?= e(strtoupper((string)$upd['status'])) ?></span>
                      <div class="ann-update-body">
                        <p><?= nl2br(e((string)$upd['message'])) ?></p>
                        <span class="ann-update-meta"><?= e(date('Y-m-d H:i', (int)$upd['created_at'])) ?></span>
                      </div>
                    </div>
                  <?php endforeach; ?>
                </div>
              <?php endif; ?>
            </article>
          <?php endforeach; ?>

          <?php if ($annTotalPg > 1):
            $annPgUrl = static function (int $pg) use ($announcementFilter, $statusFilter, $typeFilter, $sort, $search): string {
              $params = ['ann' => $announcementFilter, 'ann_pg' => $pg];
              if ($statusFilter !== 'all') { $params['status'] = $statusFilter; }
              if ($typeFilter !== 'all') { $params['type'] = $typeFilter; }
              if ($sort !== 'uptime_desc') { $params['sort'] = $sort; }
              if ($search !== '') { $params['q'] = $search; }
              return '/?' . http_build_query($params) . '#announcements';
            };
          ?>
            <nav class="nd-pagination">
              <?php if ($annPgNum > 1): ?>
                <a class="nd-page-link" href="<?= e($annPgUrl($annPgNum - 1)) ?>">← Prev</a>
              <?php endif; ?>
              <?php for ($p = 1; $p <= $annTotalPg; $p++): ?>
                <a class="nd-page-link<?= $p === $annPgNum ? ' nd-page-active' : '' ?>" href="<?= e($annPgUrl($p)) ?>"><?= $p ?></a>
              <?php endfor; ?>
              <?php if ($annPgNum < $annTotalPg): ?>
                <a class="nd-page-link" href="<?= e($annPgUrl($annPgNum + 1)) ?>">Next →</a>
              <?php endif; ?>
            </nav>
          <?php endif; ?>
        </div>
      </article>
    </section>
  </main>

  <footer class="site-footer">
    <div class="topbar-wrap footer-wrap">
      <div class="footer-left">
        <span class="footer-brand"><?= e($networkAsn) ?></span>
        <span class="footer-org"><?= e($networkOrg) ?></span>
      </div>
      <div class="footer-right">
        <span>Last refresh <?= e(date('H:i:s')) ?> UTC</span>
        <span class="footer-sep">&bull;</span>
        <span>Auto-refresh 1 min</span>
      </div>
    </div>
  </footer>

  <script>
    // ── Map point interaction: click to highlight country + show tooltip ──
    (function () {
      var mapWrap = document.querySelector('.noc-map-wrap');
      var tooltip = document.getElementById('mapTooltip');
      var svg = document.querySelector('.noc-map-svg');
      if (!mapWrap || !tooltip || !svg) return;

      var points = svg.querySelectorAll('.noc-map-point');
      var legendCards = document.querySelectorAll('.noc-map-loc-card');
      var activeCC = null;

      function clearHighlight() {
        svg.querySelectorAll('.noc-country-active').forEach(function (p) {
          p.classList.remove('noc-country-active');
        });
        tooltip.hidden = true;
        activeCC = null;
        legendCards.forEach(function (c) { c.classList.remove('noc-loc-active'); });
      }

      function highlightCC(cc, label, anchorX, anchorY) {
        clearHighlight();
        activeCC = cc;

        // Highlight matching country paths
        var paths = svg.querySelectorAll('.noc-map-land path[data-cc="' + cc + '"]');
        paths.forEach(function (p) { p.classList.add('noc-country-active'); });

        // Highlight legend card
        legendCards.forEach(function (c) {
          if (c.getAttribute('data-location') === cc) {
            c.classList.add('noc-loc-active');
          }
        });

        // Show tooltip
        if (label) {
          var ccSpan = tooltip.querySelector('.noc-map-tooltip-cc');
          var labelSpan = tooltip.querySelector('.noc-map-tooltip-label');
          ccSpan.textContent = cc;
          labelSpan.textContent = label;

          tooltip.hidden = false;

          // Position tooltip above the point
          var svgRect = svg.getBoundingClientRect();
          var svgVB = svg.viewBox.baseVal;
          var scaleX = svgRect.width / svgVB.width;
          var scaleY = svgRect.height / svgVB.height;
          var left = anchorX * scaleX;
          var top = anchorY * scaleY;

          tooltip.style.left = left + 'px';
          tooltip.style.top = top + 'px';
        }
      }

      points.forEach(function (point) {
        point.addEventListener('click', function (e) {
          e.stopPropagation();
          var cc = point.getAttribute('data-location');
          var label = point.getAttribute('data-label');
          var dot = point.querySelector('circle:nth-child(3)');
          var cx = parseFloat(dot.getAttribute('cx'));
          var cy = parseFloat(dot.getAttribute('cy'));
          if (activeCC === cc) {
            clearHighlight();
          } else {
            highlightCC(cc, label, cx, cy);
          }
        });
      });

      legendCards.forEach(function (card) {
        card.addEventListener('click', function (e) {
          var cc = card.getAttribute('data-location');
          var locPoint = svg.querySelector('.noc-map-point[data-location="' + cc + '"]');
          if (!locPoint) return;
          var label = locPoint.getAttribute('data-label');
          var dot = locPoint.querySelector('circle:nth-child(3)');
          var cx = parseFloat(dot.getAttribute('cx'));
          var cy = parseFloat(dot.getAttribute('cy'));
          if (activeCC === cc) {
            clearHighlight();
          } else {
            highlightCC(cc, label, cx, cy);
          }
        });
      });

      document.addEventListener('click', function (e) {
        if (!mapWrap.contains(e.target)) {
          clearHighlight();
        }
      });
    })();

    // Announcement node-link click → scroll & highlight
    const nodeLinks = document.querySelectorAll('.an-node-link');
    nodeLinks.forEach(function (link) {
      link.addEventListener('click', function (event) {
        event.preventDefault();
        const nodeId = link.getAttribute('data-node-id');
        if (!nodeId) {
          return;
        }

        const row = document.getElementById('node-row-' + nodeId);
        if (!row) {
          return;
        }

        row.scrollIntoView({ behavior: 'smooth', block: 'center' });
        row.classList.add('row-focus');
        setTimeout(function () {
          row.classList.remove('row-focus');
        }, 2200);
      });
    });

    // IPv4 / IPv6 prefix toggle
    const prefixToggles = document.querySelectorAll('.prefix-toggle');
    const prefixGridV4 = document.getElementById('prefixGridV4');
    const prefixGridV6 = document.getElementById('prefixGridV6');
    prefixToggles.forEach(function (btn) {
      btn.addEventListener('click', function () {
        prefixToggles.forEach(function (b) { b.classList.remove('is-active'); });
        btn.classList.add('is-active');
        var target = btn.getAttribute('data-prefix-target');
        if (target === 'v6') {
          if (prefixGridV4) { prefixGridV4.hidden = true; }
          if (prefixGridV6) { prefixGridV6.hidden = false; }
        } else {
          if (prefixGridV4) { prefixGridV4.hidden = false; }
          if (prefixGridV6) { prefixGridV6.hidden = true; }
        }
      });
    });

    // Website dropdown
    document.querySelectorAll('.nav-dropdown').forEach(function (dd) {
      var btn = dd.querySelector('.nav-dropdown-btn');
      if (!btn) return;
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var open = dd.classList.toggle('is-open');
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
      });
    });
    document.addEventListener('click', function () {
      document.querySelectorAll('.nav-dropdown.is-open').forEach(function (dd) {
        dd.classList.remove('is-open');
        var btn = dd.querySelector('.nav-dropdown-btn');
        if (btn) btn.setAttribute('aria-expanded', 'false');
      });
    });
  </script>

</body>
</html>
