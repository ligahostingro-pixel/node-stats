<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

send_security_headers();

ensure_storage();
$force = isset($_GET['force']) && $_GET['force'] === '1';
if ($force) {
    $token = $_SERVER['HTTP_X_COLLECT_TOKEN'] ?? '';
    if ($token === '' || !defined('NODE_AGENT_TOKEN') || NODE_AGENT_TOKEN === '' || !hash_equals(NODE_AGENT_TOKEN, $token)) {
        $force = false;
    }
}
$result = maybe_collect_sample(SAMPLE_INTERVAL_SECONDS, $force);

header('Content-Type: application/json; charset=utf-8');

echo json_encode([
    'ok' => true,
    'collected' => $result['collected'],
    'nodes_collected' => $result['count'],
    'timestamp' => time(),
], JSON_UNESCAPED_SLASHES);
