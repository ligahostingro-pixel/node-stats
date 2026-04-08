<?php

declare(strict_types=1);

date_default_timezone_set('Europe/Bucharest');

const APP_NAME = 'Node Status';
const DATA_DIR = __DIR__ . '/data';
const SAMPLES_DIR = DATA_DIR . '/samples';
const SQLITE_PATH = DATA_DIR . '/status.sqlite';
const LOCK_FILE = DATA_DIR . '/collector.lock';
const SAMPLE_INTERVAL_SECONDS = 300;
const MAX_DAYS_TO_KEEP = 30;
define('ADMIN_USERNAME', getenv('STATUS_ADMIN_USER') ?: 'admin');
define('ADMIN_PASSWORD', getenv('STATUS_ADMIN_PASS') ?: 'admin123');
define('NODE_AGENT_TOKEN', getenv('NODE_AGENT_TOKEN') ?: '');
