<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

ensure_storage();
$force = isset($_GET['force']) && $_GET['force'] === '1';
$result = maybe_collect_sample(SAMPLE_INTERVAL_SECONDS, $force);

header('Content-Type: application/json; charset=utf-8');

echo json_encode([
    'ok' => true,
    'collected' => $result['collected'],
    'sample' => $result['sample'],
    'timestamp' => time(),
], JSON_UNESCAPED_SLASHES);
