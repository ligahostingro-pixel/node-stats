<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');
header('Cache-Control: no-store');

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

$checks = ['db' => false, 'disk' => false];
$ok = true;

// Database check
try {
    $stmt = db()->query('SELECT 1');
    $checks['db'] = $stmt !== false;
} catch (\Throwable $e) {
    $checks['db'] = false;
}

// Disk writable
$checks['disk'] = is_dir(DATA_DIR) && is_writable(DATA_DIR);

$ok = $checks['db'] && $checks['disk'];

http_response_code($ok ? 200 : 503);
echo json_encode([
    'status' => $ok ? 'healthy' : 'unhealthy',
    'checks' => $checks,
    'ts'     => time(),
], JSON_UNESCAPED_SLASHES);
