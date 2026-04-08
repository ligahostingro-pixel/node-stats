<?php

declare(strict_types=1);

date_default_timezone_set('Europe/Bucharest');

const APP_NAME = 'Node Status';
const DATA_DIR = __DIR__ . '/data';
const SAMPLES_DIR = DATA_DIR . '/samples';
const ANNOUNCEMENTS_FILE = DATA_DIR . '/announcements.json';
const STATE_FILE = DATA_DIR . '/state.json';
const LOCK_FILE = DATA_DIR . '/collector.lock';
const SAMPLE_INTERVAL_SECONDS = 300;
const MAX_DAYS_TO_KEEP = 30;
