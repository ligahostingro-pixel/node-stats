<?php

declare(strict_types=1);

date_default_timezone_set('Europe/Bucharest');

const APP_NAME = 'Node Status';
const DATA_DIR = __DIR__ . '/data';
const SAMPLES_DIR = DATA_DIR . '/samples';
const LOCK_FILE = DATA_DIR . '/collector.lock';
const SAMPLE_INTERVAL_SECONDS = 300;
const MAX_DAYS_TO_KEEP = 30;

/* ── MariaDB / MySQL connection ─────────────────────────────── */
define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_PORT', getenv('DB_PORT') ?: '3306');
define('DB_NAME', getenv('DB_NAME') ?: 'node_status');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASS', getenv('DB_PASS') ?: '');

define('ADMIN_DEFAULT_USER', getenv('STATUS_ADMIN_USER') ?: 'admin');
define('ADMIN_DEFAULT_PASS', getenv('STATUS_ADMIN_PASS') ?: 'admin123');
define('NODE_AGENT_TOKEN', getenv('NODE_AGENT_TOKEN') ?: '');
