<?php
// One-time script to add node. Access via browser then delete.
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/functions.php';
ensure_storage();

// Check if node already exists
$existing = db()->prepare('SELECT id FROM nodes WHERE ssh_host = :h LIMIT 1');
$existing->execute([':h' => '64.31.28.229']);
if ($existing->fetch()) {
    echo "Node already exists.\n";
    exit;
}

$ok = add_node(
    'US-LA-1',
    'remote',
    'http://64.31.28.229/node-agent.php',
    '',
    '64.31.28.229',
    22,
    'root',
    'Storm123@',
    'ens3',
    'US'
);
echo $ok ? "Node added OK\n" : "FAILED\n";
);
echo $ok ? "Node added OK\n" : "FAILED\n";
