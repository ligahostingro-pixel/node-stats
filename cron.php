#!/usr/bin/env php
<?php
/**
 * Cron job — collect metrics from all active nodes.
 *
 * Add to crontab:
 *   * * * * * /usr/bin/php /var/www/node-stats/cron.php >> /var/log/node-stats-cron.log 2>&1
 *
 * Or without logging:
 *   * * * * * /usr/bin/php /var/www/node-stats/cron.php > /dev/null 2>&1
 */

declare(strict_types=1);

// Only allow CLI execution
if (php_sapi_name() !== 'cli') {
    http_response_code(403);
    echo 'Forbidden';
    exit(1);
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/functions.php';

ensure_storage();

$result = maybe_collect_sample(SAMPLE_INTERVAL_SECONDS, true);

$ts = date('Y-m-d H:i:s');
if ($result['collected']) {
    echo "[{$ts}] Collected {$result['count']} node(s)\n";
} else {
    echo "[{$ts}] Skipped (not due yet)\n";
}
