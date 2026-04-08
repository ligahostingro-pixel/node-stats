<?php

declare(strict_types=1);

/* ── Security bootstrap ──────────────────────────────────────────── */

function secure_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'httponly'  => true,
        'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'samesite' => 'Strict',
    ]);
    session_start();
}

function send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

/* ── Login rate limiting ─────────────────────────────────────────── */

function check_login_throttle(): bool
{
    $state = get_state_value('login_fails', '');
    if ($state === '') {
        return true; // no failures recorded
    }
    $data = json_decode($state, true);
    if (!is_array($data)) {
        return true;
    }
    $count  = (int)($data['count'] ?? 0);
    $lastTs = (int)($data['ts'] ?? 0);
    // lock for 60s after 5 failures
    if ($count >= 5 && (time() - $lastTs) < 60) {
        return false;
    }
    // reset after 60s
    if ((time() - $lastTs) >= 60) {
        set_state_value('login_fails', '');
    }
    return true;
}

function record_login_failure(): void
{
    $state = get_state_value('login_fails', '');
    $data  = is_string($state) && $state !== '' ? json_decode($state, true) : null;
    if (!is_array($data)) {
        $data = ['count' => 0, 'ts' => 0];
    }
    // reset counter if >60s since last failure
    if ((time() - (int)($data['ts'] ?? 0)) >= 60) {
        $data = ['count' => 0, 'ts' => 0];
    }
    $data['count'] = ((int)($data['count'] ?? 0)) + 1;
    $data['ts']    = time();
    set_state_value('login_fails', json_encode($data));
}

function clear_login_failures(): void
{
    set_state_value('login_fails', '');
}

function ensure_storage(): void
{
    if (!is_dir(DATA_DIR)) {
        mkdir(DATA_DIR, 0775, true);
    }

    if (!is_dir(SAMPLES_DIR)) {
        mkdir(SAMPLES_DIR, 0775, true);
    }

    db();
    seed_default_admin();
    ensure_audit_log_table();
}

/* ── Encryption helpers for SSH passwords ────────────────────── */

function encrypt_value(string $plaintext): string
{
    $key = APP_SECRET_KEY;
    if ($key === '' || strlen($key) < 64) {
        return $plaintext; // no key configured — store as-is (backward compat)
    }

    $keyBin = sodium_hex2bin($key);
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = sodium_crypto_secretbox($plaintext, $nonce, $keyBin);

    return 'enc:' . base64_encode($nonce . $cipher);
}

function decrypt_value(string $stored): string
{
    if (!str_starts_with($stored, 'enc:')) {
        return $stored; // plaintext (legacy or no key)
    }

    $key = APP_SECRET_KEY;
    if ($key === '' || strlen($key) < 64) {
        return ''; // can't decrypt without key
    }

    $keyBin = sodium_hex2bin($key);
    $raw = base64_decode(substr($stored, 4), true);
    if ($raw === false || strlen($raw) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES) {
        return '';
    }

    $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain = sodium_crypto_secretbox_open($cipher, $nonce, $keyBin);

    return $plain !== false ? $plain : '';
}

/* ── Input validation helpers ────────────────────────────────── */

function is_valid_net_interface(?string $name): bool
{
    if ($name === null || $name === '') {
        return true; // empty is ok
    }
    return (bool)preg_match('/^[a-zA-Z0-9._\-]{1,40}$/', $name);
}

/* ── Audit log ───────────────────────────────────────────────── */

function audit_log(string $action, ?string $detail = null): void
{
    try {
        $user = 'system';
        if (function_exists('is_admin') && is_admin()) {
            $user = admin_user();
        }
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;

        $stmt = db()->prepare(
            'INSERT INTO audit_log (ts, user, action, detail, ip)
             VALUES (:ts, :user, :action, :detail, :ip)'
        );
        $stmt->execute([
            ':ts'     => time(),
            ':user'   => substr($user, 0, 60),
            ':action' => substr($action, 0, 80),
            ':detail' => $detail !== null ? substr($detail, 0, 2000) : null,
            ':ip'     => $ip !== null ? substr($ip, 0, 45) : null,
        ]);
    } catch (\Throwable $e) {
        // never let audit failure break the app
    }
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = 'mysql:host=' . DB_HOST . ';port=' . DB_PORT . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);

    return $pdo;
}

function seed_default_local_node(): void
{
    $pdo = db();
    $stmt = $pdo->query('SELECT COUNT(*) AS c FROM nodes');
    $count = (int)($stmt->fetch()['c'] ?? 0);

    if ($count === 0) {
        $insert = $pdo->prepare(
                'INSERT INTO nodes (
                     name, node_type, ssh_host, ssh_port, ssh_user, ssh_password, net_interface,
                     endpoint_url, api_token, is_active, created_at
                 ) VALUES (
                     :name, :type, NULL, NULL, NULL, NULL, NULL,
                     NULL, NULL, 1, :created_at
                 )'
        );

        $insert->execute([
            ':name' => (gethostname() ?: 'local-node') . ' (local)',
            ':type' => 'local',
            ':created_at' => time(),
        ]);
    }
}

function seed_default_admin(): void
{
    $pdo = db();
    $stmt = $pdo->query('SELECT COUNT(*) AS c FROM admins');
    $count = (int)($stmt->fetch()['c'] ?? 0);

    if ($count === 0) {
        $insert = $pdo->prepare(
            'INSERT INTO admins (username, password, created_at)
             VALUES (:username, :password, :created_at)'
        );
        $insert->execute([
            ':username' => ADMIN_DEFAULT_USER,
            ':password' => password_hash(ADMIN_DEFAULT_PASS, PASSWORD_BCRYPT),
            ':created_at' => time(),
        ]);
    }
}

function ensure_audit_log_table(): void
{
    db()->exec(
        'CREATE TABLE IF NOT EXISTS `audit_log` (
            `id`     INT          NOT NULL AUTO_INCREMENT,
            `ts`     INT          NOT NULL,
            `user`   VARCHAR(60)  NOT NULL DEFAULT \'system\',
            `action` VARCHAR(80)  NOT NULL,
            `detail` TEXT         DEFAULT NULL,
            `ip`     VARCHAR(45)  DEFAULT NULL,
            PRIMARY KEY (`id`),
            INDEX `idx_audit_ts` (`ts` DESC)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'
    );
}

function get_state_value(string $key, string $default = ''): string
{
    $stmt = db()->prepare('SELECT state_value FROM app_state WHERE state_key = :key');
    $stmt->execute([':key' => $key]);
    $row = $stmt->fetch();

    return is_array($row) ? (string)$row['state_value'] : $default;
}

function set_state_value(string $key, string $value): void
{
    $stmt = db()->prepare(
        'INSERT INTO app_state (state_key, state_value)
         VALUES (:key, :value)
         ON DUPLICATE KEY UPDATE state_value = VALUES(state_value)'
    );

    $stmt->execute([
        ':key' => $key,
        ':value' => $value,
    ]);
}

function all_nodes(bool $activeOnly = true): array
{
    $sql = 'SELECT * FROM nodes';
    if ($activeOnly) {
        $sql .= ' WHERE is_active = 1';
    }
    $sql .= ' ORDER BY id ASC';

    return db()->query($sql)->fetchAll();
}

function add_node(
    string $name,
    string $type,
    ?string $endpointUrl,
    ?string $apiToken,
    ?string $sshHost = null,
    ?int $sshPort = null,
    ?string $sshUser = null,
    ?string $sshPassword = null,
    ?string $netInterface = null,
    ?string $country = null
): bool
{
    $name = trim($name);
    $type = trim($type);
    $endpointUrl = $endpointUrl !== null ? trim($endpointUrl) : null;
    $apiToken = $apiToken !== null ? trim($apiToken) : null;
    $sshHost = $sshHost !== null ? trim($sshHost) : null;
    $sshUser = $sshUser !== null ? trim($sshUser) : null;
    $sshPassword = $sshPassword !== null ? trim($sshPassword) : null;
    $netInterface = $netInterface !== null ? trim($netInterface) : null;
    $country = $country !== null ? trim($country) : null;

    if ($name === '') {
        return false;
    }

    if (!in_array($type, ['local', 'remote'], true)) {
        return false;
    }

    if (!is_valid_net_interface($netInterface)) {
        return false;
    }

    $encryptedPassword = ($type === 'remote' && $sshPassword !== null && $sshPassword !== '')
        ? encrypt_value(substr($sshPassword, 0, 255))
        : null;

    $stmt = db()->prepare(
        'INSERT INTO nodes (
            name, node_type, ssh_host, ssh_port, ssh_user, ssh_password, net_interface,
            endpoint_url, api_token, country, is_active, created_at
         ) VALUES (
            :name, :type, :ssh_host, :ssh_port, :ssh_user, :ssh_password, :net_interface,
            :url, :token, :country, 1, :created_at
         )'
    );

    $stmt->execute([
        ':name' => substr($name, 0, 120),
        ':type' => $type,
        ':ssh_host' => $type === 'remote' && $sshHost !== null && $sshHost !== '' ? substr($sshHost, 0, 255) : null,
        ':ssh_port' => $type === 'remote' && $sshPort !== null && $sshPort > 0 ? $sshPort : null,
        ':ssh_user' => $type === 'remote' && $sshUser !== null && $sshUser !== '' ? substr($sshUser, 0, 120) : null,
        ':ssh_password' => $encryptedPassword,
        ':net_interface' => $type === 'remote' && $netInterface !== null && $netInterface !== '' ? substr($netInterface, 0, 80) : null,
        ':url' => $type === 'remote' ? substr((string)$endpointUrl, 0, 400) : null,
        ':token' => $type === 'remote' ? substr((string)$apiToken, 0, 255) : null,
        ':country' => $country !== null && $country !== '' ? substr($country, 0, 10) : null,
        ':created_at' => time(),
    ]);

    audit_log('add_node', 'Added node: ' . $name . ' (' . $type . ')');
    return true;
}

function delete_node(int $id): void
{
    $pdo = db();
    // Clean up announcements linked to this node
    $stmt = $pdo->prepare('DELETE FROM announcements WHERE node_id = :id');
    $stmt->execute([':id' => $id]);
    // Delete node (samples cascade via FK)
    $stmt = $pdo->prepare('DELETE FROM nodes WHERE id = :id');
    $stmt->execute([':id' => $id]);
    audit_log('delete_node', 'Deleted node id=' . $id);
}

function clear_node_samples(int $nodeId): void
{
    $stmt = db()->prepare('DELETE FROM samples WHERE node_id = :nid');
    $stmt->execute([':nid' => $nodeId]);
    audit_log('clear_samples', 'Cleared samples for node_id=' . $nodeId);
}

function test_node_connection(array $node): array
{
    $start = microtime(true);
    $result = collect_node_metrics($node);
    $elapsed = round((microtime(true) - $start) * 1000);

    $ok = ($result['status'] ?? 'down') !== 'down';
    $details = [];
    $details['status'] = $result['status'] ?? 'down';
    $details['response_ms'] = $elapsed;
    $details['error'] = $result['error_text'] ?? null;
    $details['hostname'] = $result['hostname'] ?? null;
    $details['os_name'] = $result['os_name'] ?? null;
    $details['cpu_pct'] = $result['cpu_pct'] ?? null;
    $details['cpu_name'] = $result['cpu_name'] ?? null;
    $details['cpu_cores'] = $result['cpu_cores'] ?? null;
    $details['mem_used_pct'] = $result['mem_used_pct'] ?? null;
    $details['disk_used_pct'] = $result['disk_used_pct'] ?? null;
    $details['load1'] = $result['load1'] ?? null;

    $method = 'none';
    if (($node['node_type'] ?? 'remote') === 'local') {
        $method = 'local (/proc)';
    } elseif (trim((string)($node['endpoint_url'] ?? '')) !== '') {
        $method = 'HTTP agent (' . (string)$node['endpoint_url'] . ')';
    } elseif (trim((string)($node['ssh_host'] ?? '')) !== '') {
        $method = 'SSH (' . (string)$node['ssh_user'] . '@' . (string)$node['ssh_host'] . ':' . ((int)($node['ssh_port'] ?? 22)) . ')';
    }
    $details['method'] = $method;

    return ['ok' => $ok, 'details' => $details];
}

function load_announcements(): array
{
    $stmt = db()->query(
        'SELECT a.*, n.name AS node_name
         FROM announcements a
         LEFT JOIN nodes n ON n.id = a.node_id
         ORDER BY a.pinned DESC, a.created_at DESC'
    );
    return $stmt->fetchAll();
}

function add_announcement(
    string $title,
    string $message,
    bool $pinned,
    string $createdBy,
    string $level = 'info',
    ?int $nodeId = null,
    ?int $startsAt = null,
    ?int $endsAt = null
): bool
{
    $title = trim($title);
    $message = trim($message);
    $level = trim(strtolower($level));

    if (!in_array($level, ['info', 'maintenance', 'degraded', 'critical'], true)) {
        $level = 'info';
    }

    if ($title === '' || $message === '') {
        return false;
    }

    if ($startsAt !== null && $endsAt !== null && $startsAt > $endsAt) {
        return false;
    }

    if ($nodeId !== null && $nodeId > 0) {
        $check = db()->prepare('SELECT id FROM nodes WHERE id = :id LIMIT 1');
        $check->execute([':id' => $nodeId]);
        if ($check->fetch() === false) {
            $nodeId = null;
        }
    } else {
        $nodeId = null;
    }

    $stmt = db()->prepare(
        'INSERT INTO announcements (title, message, level, node_id, starts_at, ends_at, pinned, created_at, created_by)
         VALUES (:title, :message, :level, :node_id, :starts_at, :ends_at, :pinned, :created_at, :created_by)'
    );

    $stmt->execute([
        ':title' => substr($title, 0, 120),
        ':message' => substr($message, 0, 5000),
        ':level' => $level,
        ':node_id' => $nodeId,
        ':starts_at' => $startsAt,
        ':ends_at' => $endsAt,
        ':pinned' => $pinned ? 1 : 0,
        ':created_at' => time(),
        ':created_by' => substr($createdBy, 0, 60),
    ]);

    dispatch_discord_webhook($title, $message, $level, $nodeId, $startsAt, $endsAt);

    $nodeName = null;
    if ($nodeId !== null && $nodeId > 0) {
        $nStmt = db()->prepare('SELECT name FROM nodes WHERE id = :id LIMIT 1');
        $nStmt->execute([':id' => $nodeId]);
        $nRow = $nStmt->fetch();
        if (is_array($nRow)) { $nodeName = (string)$nRow['name']; }
    }
    notify_announcement($title, $message, $level, $nodeName);

    return true;
}

function send_discord_payload(string $webhookUrl, string $json): void
{
    if (function_exists('curl_init')) {
        $ch = curl_init($webhookUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $json,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($json),
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => true,
        ]);
        curl_exec($ch);
        curl_close($ch);
    } else {
        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nContent-Length: " . strlen($json) . "\r\n",
                'content' => $json,
                'timeout' => 10,
            ],
        ]);
        @file_get_contents($webhookUrl, false, $context);
    }
}

function dispatch_discord_webhook(
    string $title,
    string $message,
    string $level,
    ?int $nodeId,
    ?int $startsAt,
    ?int $endsAt
): void {
    $webhookUrl = trim(get_state_value('discord_webhook_url', ''));
    if ($webhookUrl === '' || !filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
        return;
    }

    $colorMap = [
        'info' => 0x32D4C8,
        'maintenance' => 0xF59E0B,
        'degraded' => 0xF59E0B,
        'critical' => 0xEF4444,
    ];

    $iconMap = [
        'info' => "\xE2\x84\xB9\xEF\xB8\x8F",
        'maintenance' => "\xF0\x9F\x94\xA7",
        'degraded' => "\xE2\x9A\xA0\xEF\xB8\x8F",
        'critical' => "\xF0\x9F\x9A\xA8",
    ];

    $color = $colorMap[$level] ?? 0x4EA8FF;
    $icon = $iconMap[$level] ?? '';

    $nodeName = 'All nodes';
    if ($nodeId !== null && $nodeId > 0) {
        $stmt = db()->prepare('SELECT name FROM nodes WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $nodeId]);
        $row = $stmt->fetch();
        if (is_array($row) && isset($row['name'])) {
            $nodeName = (string)$row['name'];
        }
    }

    $fields = [
        [
            'name' => 'Severity',
            'value' => '`' . strtoupper($level) . '`',
            'inline' => true,
        ],
        [
            'name' => 'Affected',
            'value' => $nodeName,
            'inline' => true,
        ],
    ];

    if ($startsAt !== null || $endsAt !== null) {
        $window = ($startsAt !== null ? date('Y-m-d H:i', $startsAt) : 'ASAP')
            . ' → '
            . ($endsAt !== null ? date('Y-m-d H:i', $endsAt) : 'Until resolved');
        $fields[] = [
            'name' => 'Maintenance window',
            'value' => $window,
            'inline' => false,
        ];
    }

    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => $icon . ' ' . $title,
                'description' => strlen($message) > 1024 ? substr($message, 0, 1021) . '...' : $message,
                'color' => $color,
                'fields' => $fields,
                'footer' => [
                    'text' => $networkAsn . ' • ' . $networkOrg . ' Status',
                ],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return;
    }

    send_discord_payload($webhookUrl, $json);
}

function delete_announcement(int $id): void
{
    $stmt = db()->prepare('DELETE FROM announcements WHERE id = :id');
    $stmt->execute([':id' => $id]);
    $stmt2 = db()->prepare('DELETE FROM announcement_updates WHERE announcement_id = :aid');
    $stmt2->execute([':aid' => $id]);
}

function load_announcement_updates(int $announcementId): array
{
    $stmt = db()->prepare(
        'SELECT * FROM announcement_updates WHERE announcement_id = :aid ORDER BY created_at ASC'
    );
    $stmt->execute([':aid' => $announcementId]);
    return $stmt->fetchAll();
}

function load_all_announcement_updates(): array
{
    $stmt = db()->query('SELECT * FROM announcement_updates ORDER BY created_at ASC');
    $rows = $stmt->fetchAll();
    $grouped = [];
    foreach ($rows as $row) {
        $grouped[(int)$row['announcement_id']][] = $row;
    }
    return $grouped;
}

function add_announcement_update(
    int $announcementId,
    string $message,
    string $status,
    string $createdBy
): bool {
    $message = trim($message);
    $status = trim(strtolower($status));

    $allowedStatuses = ['investigating', 'identified', 'monitoring', 'update', 'resolved'];
    if (!in_array($status, $allowedStatuses, true)) {
        $status = 'update';
    }

    if ($message === '') {
        return false;
    }

    $checkStmt = db()->prepare('SELECT id, title, level, node_id FROM announcements WHERE id = :id LIMIT 1');
    $checkStmt->execute([':id' => $announcementId]);
    $announcement = $checkStmt->fetch();
    if (!is_array($announcement)) {
        return false;
    }

    $stmt = db()->prepare(
        'INSERT INTO announcement_updates (announcement_id, message, status, created_at, created_by)
         VALUES (:aid, :message, :status, :created_at, :created_by)'
    );
    $stmt->execute([
        ':aid' => $announcementId,
        ':message' => substr($message, 0, 5000),
        ':status' => $status,
        ':created_at' => time(),
        ':created_by' => substr($createdBy, 0, 60),
    ]);

    // Auto-close the announcement when resolved
    if ($status === 'resolved') {
        $resolveStmt = db()->prepare('UPDATE announcements SET resolved_at = :ts WHERE id = :id AND resolved_at IS NULL');
        $resolveStmt->execute([':ts' => time(), ':id' => $announcementId]);
    }

    $annTitle = (string)$announcement['title'];
    $annLevel = (string)($announcement['level'] ?? 'info');
    $annNodeId = is_numeric($announcement['node_id'] ?? null) ? (int)$announcement['node_id'] : null;

    dispatch_discord_update_webhook($annTitle, $message, $status, $annLevel, $annNodeId);

    $nodeName = null;
    if ($annNodeId !== null && $annNodeId > 0) {
        $nStmt = db()->prepare('SELECT name FROM nodes WHERE id = :id LIMIT 1');
        $nStmt->execute([':id' => $annNodeId]);
        $nRow = $nStmt->fetch();
        if (is_array($nRow)) { $nodeName = (string)$nRow['name']; }
    }
    notify_announcement_update($annTitle, $message, $status, $annLevel, $nodeName);

    return true;
}

function dispatch_discord_update_webhook(
    string $announcementTitle,
    string $updateMessage,
    string $updateStatus,
    string $level,
    ?int $nodeId
): void {
    $webhookUrl = trim(get_state_value('discord_webhook_url', ''));
    if ($webhookUrl === '' || !filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
        return;
    }

    $colorMap = [
        'investigating' => 0xEF4444,
        'identified' => 0xF59E0B,
        'monitoring' => 0x4EA8FF,
        'update' => 0x4EA8FF,
        'resolved' => 0x22C55E,
    ];

    $iconMap = [
        'investigating' => "\xF0\x9F\x94\x8D",
        'identified' => "\xF0\x9F\x94\xA7",
        'monitoring' => "\xF0\x9F\x91\x80",
        'update' => "\xF0\x9F\x93\x8B",
        'resolved' => "\xE2\x9C\x85",
    ];

    $color = $colorMap[$updateStatus] ?? 0x4EA8FF;
    $icon = $iconMap[$updateStatus] ?? '';

    $nodeName = 'All nodes';
    if ($nodeId !== null && $nodeId > 0) {
        $stmt = db()->prepare('SELECT name FROM nodes WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $nodeId]);
        $row = $stmt->fetch();
        if (is_array($row) && isset($row['name'])) {
            $nodeName = (string)$row['name'];
        }
    }

    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => $icon . ' [UPDATE] ' . $announcementTitle,
                'description' => strlen($updateMessage) > 1024 ? substr($updateMessage, 0, 1021) . '...' : $updateMessage,
                'color' => $color,
                'fields' => [
                    [
                        'name' => 'Status',
                        'value' => '`' . strtoupper($updateStatus) . '`',
                        'inline' => true,
                    ],
                    [
                        'name' => 'Severity',
                        'value' => '`' . strtoupper($level) . '`',
                        'inline' => true,
                    ],
                    [
                        'name' => 'Affected',
                        'value' => $nodeName,
                        'inline' => true,
                    ],
                ],
                'footer' => [
                    'text' => $networkAsn . ' • ' . $networkOrg . ' Status',
                ],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        return;
    }

    send_discord_payload($webhookUrl, $json);
}

function notify_announcement_update(string $annTitle, string $updateMessage, string $updateStatus, string $level, ?string $nodeName): void
{
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $statusUpper = strtoupper($updateStatus);
    $affected = $nodeName ?? 'All nodes';

    $subject = '[' . $networkAsn . '] ' . $statusUpper . ' — ' . $annTitle;

    $colorMap = [
        'investigating' => '#EF4444',
        'identified' => '#F59E0B',
        'monitoring' => '#4EA8FF',
        'update' => '#4EA8FF',
        'resolved' => '#22C55E',
    ];
    $color = $colorMap[$updateStatus] ?? '#4EA8FF';

    $bodyHtml = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">'
        . '<div style="background:' . $color . ';color:#fff;padding:12px 20px;border-radius:8px 8px 0 0;font-weight:700;">' . htmlspecialchars($statusUpper, ENT_QUOTES, 'UTF-8') . '</div>'
        . '<div style="background:#111827;color:#e5eefb;padding:20px;border:1px solid #1e293b;border-radius:0 0 8px 8px;">'
        . '<h2 style="margin:0 0 8px;">' . htmlspecialchars($annTitle, ENT_QUOTES, 'UTF-8') . '</h2>'
        . '<p style="color:#93a4bd;margin:0 0 12px;">Affected: ' . htmlspecialchars($affected, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<div style="border-left:3px solid ' . $color . ';padding:8px 16px;margin:0 0 12px;background:rgba(0,0,0,0.2);border-radius:0 6px 6px 0;">'
        . '<p style="margin:0;font-weight:600;color:' . $color . ';">' . htmlspecialchars($statusUpper, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<p style="margin:4px 0 0;line-height:1.6;">' . nl2br(htmlspecialchars($updateMessage, ENT_QUOTES, 'UTF-8')) . '</p>'
        . '</div>'
        . '<p style="margin:0;font-size:12px;color:#64748b;">' . htmlspecialchars($networkAsn . ' • ' . $networkOrg, ENT_QUOTES, 'UTF-8') . '</p>'
        . '</div></div>';

    $bodyText = $statusUpper . " — " . $annTitle . "\nAffected: " . $affected . "\n\n" . $updateMessage . "\n\n" . $networkAsn . ' • ' . $networkOrg;

    notify_subscribers($subject, $bodyHtml, $bodyText);
}

function get_cpu_times(): ?array
{
    $content = @file('/proc/stat');
    if ($content === false || empty($content)) {
        return null;
    }

    $line = trim($content[0]);
    if (!str_starts_with($line, 'cpu ')) {
        return null;
    }

    $parts = preg_split('/\s+/', $line);
    if ($parts === false || count($parts) < 8) {
        return null;
    }

    $values = array_map('intval', array_slice($parts, 1));
    $idle = ($values[3] ?? 0) + ($values[4] ?? 0);
    $total = array_sum($values);

    return ['idle' => $idle, 'total' => $total];
}

function get_cpu_usage_percent(): ?float
{
    $start = get_cpu_times();
    if ($start === null) {
        return null;
    }

    usleep(120000);

    $end = get_cpu_times();
    if ($end === null) {
        return null;
    }

    $deltaTotal = $end['total'] - $start['total'];
    $deltaIdle = $end['idle'] - $start['idle'];

    if ($deltaTotal <= 0) {
        return null;
    }

    $usage = (1 - ($deltaIdle / $deltaTotal)) * 100;
    return round(max(0, min(100, $usage)), 2);
}

function get_cpu_details(): array
{
    $cpuinfo = @file('/proc/cpuinfo', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($cpuinfo === false) {
        return ['cpu_name' => null, 'cpu_cores' => null];
    }

    $cpuName = null;
    $coreCount = 0;

    foreach ($cpuinfo as $line) {
        $trimmed = trim($line);
        if ($cpuName === null && preg_match('/^model name\s*:\s*(.+)$/i', $trimmed, $matches) === 1) {
            $cpuName = trim((string)$matches[1]);
        }

        if (preg_match('/^processor\s*:\s*\d+$/i', $trimmed) === 1) {
            $coreCount++;
        }
    }

    return [
        'cpu_name' => $cpuName !== null && $cpuName !== '' ? $cpuName : null,
        'cpu_cores' => $coreCount > 0 ? $coreCount : null,
    ];
}

function get_memory_stats(): array
{
    $meminfo = @file('/proc/meminfo');
    $totalKb = 0;
    $availableKb = 0;

    if ($meminfo !== false) {
        foreach ($meminfo as $line) {
            if (preg_match('/^MemTotal:\s+(\d+)\s+kB$/', trim($line), $matches) === 1) {
                $totalKb = (int)$matches[1];
            }

            if (preg_match('/^MemAvailable:\s+(\d+)\s+kB$/', trim($line), $matches) === 1) {
                $availableKb = (int)$matches[1];
            }
        }
    }

    $usedKb = max(0, $totalKb - $availableKb);
    $usedPct = $totalKb > 0 ? ($usedKb / $totalKb) * 100 : 0;

    return [
        'total_mb' => round($totalKb / 1024, 2),
        'used_mb' => round($usedKb / 1024, 2),
        'used_pct' => round($usedPct, 2),
    ];
}

function get_network_totals(): array
{
    $lines = @file('/proc/net/dev');
    if ($lines === false) {
        return ['rx_bytes' => 0, 'tx_bytes' => 0];
    }

    $rx = 0;
    $tx = 0;

    foreach ($lines as $line) {
        if (!str_contains($line, ':')) {
            continue;
        }

        $clean = preg_replace('/\s+/', ' ', trim(str_replace(':', ' ', $line)));
        if ($clean === null) {
            continue;
        }

        $parts = explode(' ', $clean);
        if (count($parts) < 10) {
            continue;
        }

        $iface = $parts[0];
        if ($iface === 'lo') {
            continue;
        }

        $rx += (int)$parts[1];
        $tx += (int)$parts[9];
    }

    return ['rx_bytes' => $rx, 'tx_bytes' => $tx];
}

function get_swap_stats(): array
{
    $meminfo = @file('/proc/meminfo');
    $swapTotalKb = 0;
    $swapFreeKb = 0;

    if ($meminfo !== false) {
        foreach ($meminfo as $line) {
            if (preg_match('/^SwapTotal:\s+(\d+)\s+kB$/', trim($line), $matches) === 1) {
                $swapTotalKb = (int)$matches[1];
            }

            if (preg_match('/^SwapFree:\s+(\d+)\s+kB$/', trim($line), $matches) === 1) {
                $swapFreeKb = (int)$matches[1];
            }
        }
    }

    $swapUsedKb = max(0, $swapTotalKb - $swapFreeKb);
    $swapUsedPct = $swapTotalKb > 0 ? ($swapUsedKb / $swapTotalKb) * 100 : 0;

    return [
        'total_mb' => round($swapTotalKb / 1024, 2),
        'used_mb' => round($swapUsedKb / 1024, 2),
        'used_pct' => round($swapUsedPct, 2),
    ];
}

function get_disk_stats(string $path = '/'): array
{
    $total = @disk_total_space($path);
    $free = @disk_free_space($path);

    if (!is_numeric($total) || !is_numeric($free) || (float)$total <= 0) {
        return [
            'total_gb' => null,
            'used_gb' => null,
            'used_pct' => null,
        ];
    }

    $totalF = (float)$total;
    $freeF = (float)$free;
    $usedF = max(0.0, $totalF - $freeF);

    return [
        'total_gb' => round($totalF / 1073741824, 2),
        'used_gb' => round($usedF / 1073741824, 2),
        'used_pct' => round(($usedF / $totalF) * 100, 2),
    ];
}

function get_system_uptime(): ?int
{
    $raw = @file_get_contents('/proc/uptime');
    if (!is_string($raw) || $raw === '') {
        return null;
    }
    $parts = explode(' ', trim($raw));
    return is_numeric($parts[0] ?? null) ? (int)((float)$parts[0]) : null;
}

function collect_local_metrics(): array
{
    $mem = get_memory_stats();
    $swap = get_swap_stats();
    $disk = get_disk_stats('/');
    $net = get_network_totals();
    $load = sys_getloadavg();
    $cpuDetails = get_cpu_details();

    return [
        'status' => 'up',
        'cpu_pct' => get_cpu_usage_percent(),
        'cpu_name' => $cpuDetails['cpu_name'],
        'cpu_cores' => $cpuDetails['cpu_cores'],
        'hostname' => gethostname() ?: 'unknown',
        'os_name' => php_uname('s') . ' ' . php_uname('r'),
        'mem_total_mb' => $mem['total_mb'],
        'mem_used_mb' => $mem['used_mb'],
        'mem_used_pct' => $mem['used_pct'],
        'swap_total_mb' => $swap['total_mb'],
        'swap_used_mb' => $swap['used_mb'],
        'swap_used_pct' => $swap['used_pct'],
        'disk_total_gb' => $disk['total_gb'],
        'disk_used_gb' => $disk['used_gb'],
        'disk_used_pct' => $disk['used_pct'],
        'net_rx_bytes' => $net['rx_bytes'],
        'net_tx_bytes' => $net['tx_bytes'],
        'load1' => $load[0] ?? null,
        'load5' => $load[1] ?? null,
        'load15' => $load[2] ?? null,
        'uptime_seconds' => get_system_uptime(),
        'error_text' => null,
    ];
}

function build_remote_url(string $base, ?string $token): string
{
    if ($token === null || $token === '') {
        return $base;
    }

    $separator = str_contains($base, '?') ? '&' : '?';
    return $base . $separator . 'token=' . rawurlencode($token);
}

function http_get_json(string $url, int $timeoutSeconds = 4): ?array
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeoutSeconds,
            CURLOPT_CONNECTTIMEOUT => $timeoutSeconds,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);

        $raw = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if (!is_string($raw) || $code < 200 || $code >= 300) {
            return null;
        }

        $decoded = json_decode($raw, true);
        return is_array($decoded) ? $decoded : null;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => $timeoutSeconds,
            'header' => "Accept: application/json\r\n",
        ],
    ]);

    $raw = @file_get_contents($url, false, $context);
    if (!is_string($raw) || $raw === '') {
        return null;
    }

    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : null;
}

function normalize_remote_metrics(?array $payload): array
{
    if ($payload === null) {
        return [
            'status' => 'down',
            'cpu_pct' => null,
            'cpu_name' => null,
            'cpu_cores' => null,
            'hostname' => null,
            'os_name' => null,
            'mem_total_mb' => null,
            'mem_used_mb' => null,
            'mem_used_pct' => null,
            'swap_total_mb' => null,
            'swap_used_mb' => null,
            'swap_used_pct' => null,
            'disk_total_gb' => null,
            'disk_used_gb' => null,
            'disk_used_pct' => null,
            'net_rx_bytes' => null,
            'net_tx_bytes' => null,
            'load1' => null,
            'load5' => null,
            'load15' => null,
            'uptime_seconds' => null,
            'error_text' => 'Node not reachable or invalid JSON',
        ];
    }

    $cpu = is_numeric($payload['cpu_pct'] ?? null) ? (float)$payload['cpu_pct'] : null;
    $memPct = is_numeric($payload['mem_used_pct'] ?? null) ? (float)$payload['mem_used_pct'] : null;

    $status = 'up';
    if (($payload['ok'] ?? true) === false) {
        $status = 'down';
    } elseif (($cpu !== null && $cpu >= 92) || ($memPct !== null && $memPct >= 95)) {
        $status = 'degraded';
    }

    return [
        'status' => $status,
        'cpu_pct' => $cpu,
        'cpu_name' => is_string($payload['cpu_name'] ?? null) ? substr(trim((string)$payload['cpu_name']), 0, 255) : null,
        'cpu_cores' => is_numeric($payload['cpu_cores'] ?? null) ? (int)$payload['cpu_cores'] : null,
        'hostname' => is_string($payload['hostname'] ?? null) ? substr(trim((string)$payload['hostname']), 0, 120) : null,
        'os_name' => is_string($payload['os_name'] ?? null) ? substr(trim((string)$payload['os_name']), 0, 180) : null,
        'mem_total_mb' => is_numeric($payload['mem_total_mb'] ?? null) ? (float)$payload['mem_total_mb'] : null,
        'mem_used_mb' => is_numeric($payload['mem_used_mb'] ?? null) ? (float)$payload['mem_used_mb'] : null,
        'mem_used_pct' => $memPct,
        'swap_total_mb' => is_numeric($payload['swap_total_mb'] ?? null) ? (float)$payload['swap_total_mb'] : null,
        'swap_used_mb' => is_numeric($payload['swap_used_mb'] ?? null) ? (float)$payload['swap_used_mb'] : null,
        'swap_used_pct' => is_numeric($payload['swap_used_pct'] ?? null) ? (float)$payload['swap_used_pct'] : null,
        'disk_total_gb' => is_numeric($payload['disk_total_gb'] ?? null) ? (float)$payload['disk_total_gb'] : null,
        'disk_used_gb' => is_numeric($payload['disk_used_gb'] ?? null) ? (float)$payload['disk_used_gb'] : null,
        'disk_used_pct' => is_numeric($payload['disk_used_pct'] ?? null) ? (float)$payload['disk_used_pct'] : null,
        'net_rx_bytes' => is_numeric($payload['net_rx_bytes'] ?? null) ? (int)$payload['net_rx_bytes'] : null,
        'net_tx_bytes' => is_numeric($payload['net_tx_bytes'] ?? null) ? (int)$payload['net_tx_bytes'] : null,
        'load1' => is_numeric($payload['load1'] ?? null) ? (float)$payload['load1'] : null,
        'load5' => is_numeric($payload['load5'] ?? null) ? (float)$payload['load5'] : null,
        'load15' => is_numeric($payload['load15'] ?? null) ? (float)$payload['load15'] : null,
        'uptime_seconds' => is_numeric($payload['uptime_seconds'] ?? null) ? (int)$payload['uptime_seconds'] : null,
        'error_text' => is_string($payload['error'] ?? null) ? substr($payload['error'], 0, 300) : null,
    ];
}

function collect_via_ssh(string $host, int $port, string $user, string $password, string $netInterface = ''): array
{
    $emptyResult = static function (string $error): array {
        return [
            'status' => 'down',
            'cpu_pct' => null, 'cpu_name' => null, 'cpu_cores' => null,
            'hostname' => null, 'os_name' => null,
            'mem_total_mb' => null, 'mem_used_mb' => null, 'mem_used_pct' => null,
            'swap_total_mb' => null, 'swap_used_mb' => null, 'swap_used_pct' => null,
            'disk_total_gb' => null, 'disk_used_gb' => null, 'disk_used_pct' => null,
            'net_rx_bytes' => null, 'net_tx_bytes' => null,
            'load1' => null, 'load5' => null, 'load15' => null,
            'uptime_seconds' => null, 'error_text' => $error,
        ];
    };

    if (!function_exists('ssh2_connect')) {
        return $emptyResult('PHP ssh2 extension not installed');
    }

    $conn = @ssh2_connect($host, $port);
    if ($conn === false) {
        return $emptyResult('SSH connection failed to ' . $host . ':' . $port);
    }

    if (!@ssh2_auth_password($conn, $user, $password)) {
        return $emptyResult('SSH auth failed for ' . $user . '@' . $host);
    }

    // Build a one-liner that outputs JSON with all metrics
    $netIfaceFilter = $netInterface !== '' ? escapeshellarg($netInterface) : '';
    $script = <<<'BASH'
echo "{"
# hostname
printf '"hostname":"%s",' "$(hostname)"
printf '"os_name":"%s %s",' "$(uname -s)" "$(uname -r)"

# uptime
UT=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
printf '"uptime_seconds":%s,' "${UT:-null}"

# load
read L1 L5 L15 _ < /proc/loadavg 2>/dev/null
printf '"load1":%s,"load5":%s,"load15":%s,' "${L1:-null}" "${L5:-null}" "${L15:-null}"

# cpu info
CPUNAME=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//' | sed 's/"/\\"/g')
CORES=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null)
printf '"cpu_name":"%s","cpu_cores":%s,' "$CPUNAME" "${CORES:-null}"

# cpu usage (2 samples, 200ms apart)
read -r _ U1 N1 S1 I1 W1 Q1 X1 ST1 _REST < /proc/stat 2>/dev/null
sleep 0.2
read -r _ U2 N2 S2 I2 W2 Q2 X2 ST2 _REST < /proc/stat 2>/dev/null
T1=$((U1+N1+S1+I1+W1+Q1+X1+${ST1:-0})); T2=$((U2+N2+S2+I2+W2+Q2+X2+${ST2:-0}))
DT=$((T2-T1)); DI=$((I2-I1+W2-W1))
if [ "$DT" -gt 0 ] 2>/dev/null; then
  CPU=$(awk "BEGIN{printf \"%.2f\", (1-${DI}/${DT})*100}")
else
  CPU="null"
fi
printf '"cpu_pct":%s,' "$CPU"

# memory
MT=$(awk '/^MemTotal/{print $2}' /proc/meminfo)
MA=$(awk '/^MemAvailable/{print $2}' /proc/meminfo)
MU=$((MT-MA))
MTMB=$(awk "BEGIN{printf \"%.2f\", ${MT:-0}/1024}")
MUMB=$(awk "BEGIN{printf \"%.2f\", ${MU:-0}/1024}")
MUPCT=$(awk "BEGIN{if(${MT:-0}>0) printf \"%.2f\", ${MU}/${MT}*100; else print 0}")
printf '"mem_total_mb":%s,"mem_used_mb":%s,"mem_used_pct":%s,' "$MTMB" "$MUMB" "$MUPCT"

# swap
ST=$(awk '/^SwapTotal/{print $2}' /proc/meminfo)
SF=$(awk '/^SwapFree/{print $2}' /proc/meminfo)
SU=$((${ST:-0}-${SF:-0}))
STMB=$(awk "BEGIN{printf \"%.2f\", ${ST:-0}/1024}")
SUMB=$(awk "BEGIN{printf \"%.2f\", ${SU:-0}/1024}")
SUPCT=$(awk "BEGIN{if(${ST:-0}>0) printf \"%.2f\", ${SU}/${ST}*100; else print 0}")
printf '"swap_total_mb":%s,"swap_used_mb":%s,"swap_used_pct":%s,' "$STMB" "$SUMB" "$SUPCT"

# disk
DINFO=$(df -B1 / 2>/dev/null | awk 'NR==2{print $2,$3}')
DTOTAL=$(echo "$DINFO" | awk '{print $1}')
DUSED=$(echo "$DINFO" | awk '{print $2}')
DTGB=$(awk "BEGIN{printf \"%.2f\", ${DTOTAL:-0}/1073741824}")
DUGB=$(awk "BEGIN{printf \"%.2f\", ${DUSED:-0}/1073741824}")
DUPCT=$(awk "BEGIN{if(${DTOTAL:-0}>0) printf \"%.2f\", ${DUSED}/${DTOTAL}*100; else print 0}")
printf '"disk_total_gb":%s,"disk_used_gb":%s,"disk_used_pct":%s,' "$DTGB" "$DUGB" "$DUPCT"

# network
BASH;

    if ($netIfaceFilter !== '') {
        $script .= <<<BASH

NETIFACE={$netIfaceFilter}
RX=\$(awk -v iface="\$NETIFACE:" '\$1==iface{gsub(/[^0-9]/,"",\$2); print \$2}' /proc/net/dev 2>/dev/null)
TX=\$(awk -v iface="\$NETIFACE:" '\$1==iface{print \$10}' /proc/net/dev 2>/dev/null)
BASH;
    } else {
        $script .= <<<'BASH'

RX=$(awk 'NR>2 && $1!="lo:"{gsub(/:/,"",$1); rx+=$2; tx+=$10} END{print rx+0}' /proc/net/dev 2>/dev/null)
TX=$(awk 'NR>2 && $1!="lo:"{gsub(/:/,"",$1); tx+=$10} END{print tx+0}' /proc/net/dev 2>/dev/null)
BASH;
    }

    $script .= <<<'BASH'

printf '"net_rx_bytes":%s,"net_tx_bytes":%s' "${RX:-0}" "${TX:-0}"
echo "}"
BASH;

    $stream = @ssh2_exec($conn, $script);
    if ($stream === false) {
        return $emptyResult('SSH command execution failed');
    }

    stream_set_blocking($stream, true);
    stream_set_timeout($stream, 10);
    $output = stream_get_contents($stream);
    fclose($stream);

    if (!is_string($output) || $output === '') {
        return $emptyResult('SSH returned empty output');
    }

    $data = json_decode($output, true);
    if (!is_array($data)) {
        return $emptyResult('SSH returned invalid JSON: ' . substr($output, 0, 200));
    }

    // Determine status
    $cpu = is_numeric($data['cpu_pct'] ?? null) ? (float)$data['cpu_pct'] : null;
    $memPct = is_numeric($data['mem_used_pct'] ?? null) ? (float)$data['mem_used_pct'] : null;
    $status = 'up';
    if (($cpu !== null && $cpu >= 92) || ($memPct !== null && $memPct >= 95)) {
        $status = 'degraded';
    }

    return [
        'status' => $status,
        'cpu_pct' => $cpu,
        'cpu_name' => is_string($data['cpu_name'] ?? null) ? substr(trim($data['cpu_name']), 0, 255) : null,
        'cpu_cores' => is_numeric($data['cpu_cores'] ?? null) ? (int)$data['cpu_cores'] : null,
        'hostname' => is_string($data['hostname'] ?? null) ? substr(trim($data['hostname']), 0, 120) : null,
        'os_name' => is_string($data['os_name'] ?? null) ? substr(trim($data['os_name']), 0, 180) : null,
        'mem_total_mb' => is_numeric($data['mem_total_mb'] ?? null) ? (float)$data['mem_total_mb'] : null,
        'mem_used_mb' => is_numeric($data['mem_used_mb'] ?? null) ? (float)$data['mem_used_mb'] : null,
        'mem_used_pct' => $memPct,
        'swap_total_mb' => is_numeric($data['swap_total_mb'] ?? null) ? (float)$data['swap_total_mb'] : null,
        'swap_used_mb' => is_numeric($data['swap_used_mb'] ?? null) ? (float)$data['swap_used_mb'] : null,
        'swap_used_pct' => is_numeric($data['swap_used_pct'] ?? null) ? (float)$data['swap_used_pct'] : null,
        'disk_total_gb' => is_numeric($data['disk_total_gb'] ?? null) ? (float)$data['disk_total_gb'] : null,
        'disk_used_gb' => is_numeric($data['disk_used_gb'] ?? null) ? (float)$data['disk_used_gb'] : null,
        'disk_used_pct' => is_numeric($data['disk_used_pct'] ?? null) ? (float)$data['disk_used_pct'] : null,
        'net_rx_bytes' => is_numeric($data['net_rx_bytes'] ?? null) ? (int)$data['net_rx_bytes'] : null,
        'net_tx_bytes' => is_numeric($data['net_tx_bytes'] ?? null) ? (int)$data['net_tx_bytes'] : null,
        'load1' => is_numeric($data['load1'] ?? null) ? (float)$data['load1'] : null,
        'load5' => is_numeric($data['load5'] ?? null) ? (float)$data['load5'] : null,
        'load15' => is_numeric($data['load15'] ?? null) ? (float)$data['load15'] : null,
        'uptime_seconds' => is_numeric($data['uptime_seconds'] ?? null) ? (int)$data['uptime_seconds'] : null,
        'error_text' => null,
    ];
}

function collect_node_metrics(array $node): array
{
    if (($node['node_type'] ?? 'remote') === 'local') {
        $data = collect_local_metrics();
        if (($data['cpu_pct'] === null && $data['mem_used_pct'] === null)) {
            $data['status'] = 'down';
            $data['error_text'] = 'Local metrics unavailable';
        } elseif (($data['cpu_pct'] ?? 0) >= 92 || ($data['mem_used_pct'] ?? 0) >= 95) {
            $data['status'] = 'degraded';
        }

        return $data;
    }

    // Try HTTP agent first
    if (trim((string)($node['endpoint_url'] ?? '')) !== '') {
        $url = build_remote_url((string)($node['endpoint_url'] ?? ''), (string)($node['api_token'] ?? ''));
        return normalize_remote_metrics(http_get_json($url));
    }

    // Try SSH
    if (trim((string)($node['ssh_host'] ?? '')) !== '') {
        $sshPass = (string)($node['ssh_password'] ?? '');
        if ($sshPass !== '') {
            $sshPass = decrypt_value($sshPass);
        }
        return collect_via_ssh(
            (string)$node['ssh_host'],
            ((int)($node['ssh_port'] ?? 0)) > 0 ? (int)$node['ssh_port'] : 22,
            (string)($node['ssh_user'] ?? 'root'),
            $sshPass,
            (string)($node['net_interface'] ?? '')
        );
    }

    return [
        'status' => 'down',
        'cpu_pct' => null, 'cpu_name' => null, 'cpu_cores' => null,
        'hostname' => null, 'os_name' => null,
        'mem_total_mb' => null, 'mem_used_mb' => null, 'mem_used_pct' => null,
        'swap_total_mb' => null, 'swap_used_mb' => null, 'swap_used_pct' => null,
        'disk_total_gb' => null, 'disk_used_gb' => null, 'disk_used_pct' => null,
        'net_rx_bytes' => null, 'net_tx_bytes' => null,
        'load1' => null, 'load5' => null, 'load15' => null,
        'uptime_seconds' => null,
        'error_text' => 'No endpoint URL or SSH credentials configured',
    ];
}

function insert_sample(int $nodeId, int $timestamp, array $data): void
{
    $stmt = db()->prepare(
        'INSERT INTO samples (
            node_id, ts, status, cpu_pct, cpu_name, cpu_cores, hostname, os_name, mem_total_mb, mem_used_mb, mem_used_pct,
            swap_total_mb, swap_used_mb, swap_used_pct, disk_total_gb, disk_used_gb, disk_used_pct,
            net_rx_bytes, net_tx_bytes, load1, load5, load15, uptime_seconds, error_text
        ) VALUES (
            :node_id, :ts, :status, :cpu_pct, :cpu_name, :cpu_cores, :hostname, :os_name, :mem_total_mb, :mem_used_mb, :mem_used_pct,
            :swap_total_mb, :swap_used_mb, :swap_used_pct, :disk_total_gb, :disk_used_gb, :disk_used_pct,
            :net_rx_bytes, :net_tx_bytes, :load1, :load5, :load15, :uptime_seconds, :error_text
        )'
    );

    $stmt->execute([
        ':node_id' => $nodeId,
        ':ts' => $timestamp,
        ':status' => (string)($data['status'] ?? 'down'),
        ':cpu_pct' => $data['cpu_pct'],
        ':cpu_name' => isset($data['cpu_name']) && is_string($data['cpu_name']) ? substr(trim((string)$data['cpu_name']), 0, 255) : null,
        ':cpu_cores' => is_numeric($data['cpu_cores'] ?? null) ? (int)$data['cpu_cores'] : null,
        ':hostname' => isset($data['hostname']) && is_string($data['hostname']) ? substr(trim((string)$data['hostname']), 0, 120) : null,
        ':os_name' => isset($data['os_name']) && is_string($data['os_name']) ? substr(trim((string)$data['os_name']), 0, 180) : null,
        ':mem_total_mb' => is_numeric($data['mem_total_mb'] ?? null) ? (float)$data['mem_total_mb'] : null,
        ':mem_used_mb' => $data['mem_used_mb'],
        ':mem_used_pct' => $data['mem_used_pct'],
        ':swap_total_mb' => is_numeric($data['swap_total_mb'] ?? null) ? (float)$data['swap_total_mb'] : null,
        ':swap_used_mb' => is_numeric($data['swap_used_mb'] ?? null) ? (float)$data['swap_used_mb'] : null,
        ':swap_used_pct' => is_numeric($data['swap_used_pct'] ?? null) ? (float)$data['swap_used_pct'] : null,
        ':disk_total_gb' => is_numeric($data['disk_total_gb'] ?? null) ? (float)$data['disk_total_gb'] : null,
        ':disk_used_gb' => is_numeric($data['disk_used_gb'] ?? null) ? (float)$data['disk_used_gb'] : null,
        ':disk_used_pct' => is_numeric($data['disk_used_pct'] ?? null) ? (float)$data['disk_used_pct'] : null,
        ':net_rx_bytes' => $data['net_rx_bytes'],
        ':net_tx_bytes' => $data['net_tx_bytes'],
        ':load1' => $data['load1'],
        ':load5' => $data['load5'],
        ':load15' => $data['load15'],
        ':uptime_seconds' => is_numeric($data['uptime_seconds'] ?? null) ? (int)$data['uptime_seconds'] : null,
        ':error_text' => $data['error_text'],
    ]);
}

function maybe_collect_sample(int $intervalSeconds = SAMPLE_INTERVAL_SECONDS, bool $force = false): array
{
    $lock = fopen(LOCK_FILE, 'c');
    if ($lock === false) {
        return ['collected' => false, 'count' => 0];
    }

    if (!flock($lock, LOCK_EX)) {
        fclose($lock);
        return ['collected' => false, 'count' => 0];
    }

    $lastCollected = (int)get_state_value('last_collected', '0');
    $now = time();
    $due = ($now - $lastCollected) >= $intervalSeconds;

    if (!$force && !$due) {
        flock($lock, LOCK_UN);
        fclose($lock);
        return ['collected' => false, 'count' => 0];
    }

    $nodes = all_nodes(true);
    $count = 0;

    foreach ($nodes as $node) {
        $prevSample = latest_sample_for_node((int)$node['id']);
        $prevStatus = $prevSample !== null ? (string)($prevSample['status'] ?? 'unknown') : 'unknown';

        $sample = collect_node_metrics($node);
        insert_sample((int)$node['id'], $now, $sample);
        $count++;

        $newStatus = (string)($sample['status'] ?? 'unknown');
        if ($newStatus === 'down' && $prevStatus !== 'down') {
            notify_node_down((string)$node['name']);
            dispatch_discord_node_down((string)$node['name'], (int)$node['id']);
            auto_create_downtime_announcement((string)$node['name'], (int)$node['id']);
        }
        if ($newStatus !== 'down' && $prevStatus === 'down') {
            dispatch_discord_node_recovered((string)$node['name'], (int)$node['id']);
            auto_resolve_downtime_announcement((int)$node['id']);
        }
    }

    set_state_value('last_collected', (string)$now);
    prune_old_samples(MAX_DAYS_TO_KEEP);

    flock($lock, LOCK_UN);
    fclose($lock);

    return ['collected' => true, 'count' => $count];
}

function latest_sample_for_node(int $nodeId): ?array
{
    $stmt = db()->prepare('SELECT * FROM samples WHERE node_id = :node_id ORDER BY ts DESC LIMIT 1');
    $stmt->execute([':node_id' => $nodeId]);
    $row = $stmt->fetch();

    return is_array($row) ? $row : null;
}

/** Bulk-fetch the latest sample per node in a single query. */
function all_latest_samples(): array
{
    $stmt = db()->query(
        'SELECT s.* FROM samples s
         INNER JOIN (
             SELECT node_id, MAX(ts) AS max_ts
             FROM samples
             GROUP BY node_id
         ) latest ON s.node_id = latest.node_id AND s.ts = latest.max_ts'
    );
    $rows = $stmt->fetchAll();
    $map = [];
    foreach ($rows as $row) {
        $map[(int)$row['node_id']] = $row;
    }
    return $map;
}

/** Return current network rate [rx_bps, tx_bps] by comparing the two most recent samples. */
function node_net_rate(int $nodeId): array
{
    $stmt = db()->prepare('SELECT ts, net_rx_bytes, net_tx_bytes FROM samples WHERE node_id = :nid ORDER BY ts DESC LIMIT 2');
    $stmt->execute([':nid' => $nodeId]);
    $rows = $stmt->fetchAll();
    if (count($rows) < 2) {
        return [0, 0];
    }
    $dt = max(1, abs((int)$rows[0]['ts'] - (int)$rows[1]['ts']));
    $rxDiff = (int)($rows[0]['net_rx_bytes'] ?? 0) - (int)($rows[1]['net_rx_bytes'] ?? 0);
    $txDiff = (int)($rows[0]['net_tx_bytes'] ?? 0) - (int)($rows[1]['net_tx_bytes'] ?? 0);
    // Counter may have reset (reboot); clamp to 0
    if ($rxDiff < 0) { $rxDiff = 0; }
    if ($txDiff < 0) { $txDiff = 0; }
    return [(int)round($rxDiff / $dt), (int)round($txDiff / $dt)];
}

function node_live_status(?array $latest, int $staleThreshold = 900): string
{
    if ($latest === null) {
        return 'unknown';
    }

    if ((time() - (int)($latest['ts'] ?? 0)) > $staleThreshold) {
        return 'stale';
    }

    return (string)($latest['status'] ?? 'unknown');
}

function read_daily_samples(int $nodeId, string $date): array
{
    $start = strtotime($date . ' 00:00:00');
    $end = strtotime($date . ' 23:59:59');

    if ($start === false || $end === false) {
        return [];
    }

    $stmt = db()->prepare(
        'SELECT * FROM samples
         WHERE node_id = :node_id AND ts BETWEEN :start_ts AND :end_ts
         ORDER BY ts ASC'
    );

    $stmt->execute([
        ':node_id' => $nodeId,
        ':start_ts' => $start,
        ':end_ts' => $end,
    ]);

    return $stmt->fetchAll();
}

function summarize_samples(array $samples): array
{
    if (count($samples) === 0) {
        return [
            'samples' => 0,
            'cpu_avg' => null,
            'cpu_min' => null,
            'cpu_max' => null,
            'ram_avg_mb' => null,
            'ram_max_mb' => null,
            'rx_total' => 0,
            'tx_total' => 0,
            'up_pct' => null,
        ];
    }

    $cpuValues = [];
    $ramValues = [];
    $upCount = 0;

    foreach ($samples as $sample) {
        if (is_numeric($sample['cpu_pct'] ?? null)) {
            $cpuValues[] = (float)$sample['cpu_pct'];
        }

        if (is_numeric($sample['mem_used_mb'] ?? null)) {
            $ramValues[] = (float)$sample['mem_used_mb'];
        }

        if (($sample['status'] ?? '') === 'up') {
            $upCount++;
        }
    }

    $rxTotal = 0;
    $txTotal = 0;

    for ($i = 1; $i < count($samples); $i++) {
        $prevRx = (int)($samples[$i - 1]['net_rx_bytes'] ?? 0);
        $currRx = (int)($samples[$i]['net_rx_bytes'] ?? 0);
        $prevTx = (int)($samples[$i - 1]['net_tx_bytes'] ?? 0);
        $currTx = (int)($samples[$i]['net_tx_bytes'] ?? 0);

        $rxTotal += $currRx >= $prevRx ? ($currRx - $prevRx) : max(0, $currRx);
        $txTotal += $currTx >= $prevTx ? ($currTx - $prevTx) : max(0, $currTx);
    }

    return [
        'samples' => count($samples),
        'cpu_avg' => count($cpuValues) > 0 ? round(array_sum($cpuValues) / count($cpuValues), 2) : null,
        'cpu_min' => count($cpuValues) > 0 ? round(min($cpuValues), 2) : null,
        'cpu_max' => count($cpuValues) > 0 ? round(max($cpuValues), 2) : null,
        'ram_avg_mb' => count($ramValues) > 0 ? round(array_sum($ramValues) / count($ramValues), 2) : null,
        'ram_max_mb' => count($ramValues) > 0 ? round(max($ramValues), 2) : null,
        'rx_total' => $rxTotal,
        'tx_total' => $txTotal,
        'up_pct' => round(($upCount / count($samples)) * 100, 4),
    ];
}

function last_days(int $count = 7): array
{
    $days = [];
    for ($i = $count - 1; $i >= 0; $i--) {
        $days[] = date('Y-m-d', strtotime('-' . $i . ' day'));
    }

    return $days;
}

function node_day_status(int $nodeId, string $date): string
{
    $samples = read_daily_samples($nodeId, $date);
    if (count($samples) === 0) {
        return 'unknown';
    }

    $down = 0;
    $degraded = 0;
    foreach ($samples as $sample) {
        $status = (string)($sample['status'] ?? 'unknown');
        if ($status === 'down') {
            $down++;
        } elseif ($status === 'degraded') {
            $degraded++;
        }
    }

    if ($down > 0) {
        return 'down';
    }

    if ($degraded > 0) {
        return 'degraded';
    }

    return 'up';
}

function node_uptime_percent(int $nodeId, int $days = 30): ?float
{
    $start = strtotime('-' . max(1, $days) . ' day');
    if ($start === false) {
        return null;
    }

    $stmt = db()->prepare(
        "SELECT
            COUNT(*) AS total_count,
            SUM(CASE WHEN status = 'up' THEN 1 ELSE 0 END) AS up_count
         FROM samples
         WHERE node_id = :node_id AND ts >= :start_ts"
    );

    $stmt->execute([
        ':node_id' => $nodeId,
        ':start_ts' => $start,
    ]);

    $row = $stmt->fetch();
    $total = (int)($row['total_count'] ?? 0);
    $up = (int)($row['up_count'] ?? 0);

    if ($total === 0) {
        return null;
    }

    return round(($up / $total) * 100, 4);
}

function list_available_days(int $limit = 30): array
{
    $stmt = db()->prepare(
        'SELECT DISTINCT DATE(FROM_UNIXTIME(ts)) AS day
         FROM samples
         ORDER BY day DESC
         LIMIT :lim'
    );
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();

    $rows = $stmt->fetchAll();
    return array_map(static fn(array $r): string => (string)$r['day'], $rows);
}

function prune_old_samples(int $daysToKeep): void
{
    $cutoff = strtotime('-' . max(1, $daysToKeep) . ' day');
    if ($cutoff === false) {
        return;
    }

    $stmt = db()->prepare('DELETE FROM samples WHERE ts < :cutoff');
    $stmt->execute([':cutoff' => $cutoff]);
}

function format_bytes(float|int|null $bytes): string
{
    if ($bytes === null) {
        return 'N/A';
    }

    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $value = (float)$bytes;
    $index = 0;

    while ($value >= 1024 && $index < count($units) - 1) {
        $value /= 1024;
        $index++;
    }

    return number_format($value, 2) . ' ' . $units[$index];
}

function csrf_token(): string
{
    if (!isset($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }

    return $_SESSION['csrf_token'];
}

function csrf_valid(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals((string)$_SESSION['csrf_token'], $token);
}

function login_admin(string $username, string $password): bool
{
    if (!check_login_throttle()) {
        return false;
    }

    $username = trim($username);
    if ($username === '' || $password === '') {
        record_login_failure();
        return false;
    }

    $stmt = db()->prepare('SELECT id, username, password FROM admins WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $username]);
    $admin = $stmt->fetch();

    if (!is_array($admin) || !password_verify($password, (string)$admin['password'])) {
        record_login_failure();
        return false;
    }

    // Rehash if cost/algo changed
    if (password_needs_rehash((string)$admin['password'], PASSWORD_BCRYPT)) {
        $upd = db()->prepare('UPDATE admins SET password = :p WHERE id = :id');
        $upd->execute([':p' => password_hash($password, PASSWORD_BCRYPT), ':id' => $admin['id']]);
    }

    clear_login_failures();
    session_regenerate_id(true);
    $_SESSION['is_admin'] = true;
    $_SESSION['admin_user'] = (string)$admin['username'];
    $_SESSION['admin_id'] = (int)$admin['id'];
    audit_log('login', 'Admin login: ' . (string)$admin['username']);
    return true;
}

function logout_admin(): void
{
    unset($_SESSION['is_admin'], $_SESSION['admin_user'], $_SESSION['admin_id']);
}

function is_admin(): bool
{
    return (bool)($_SESSION['is_admin'] ?? false);
}

function admin_user(): string
{
    return (string)($_SESSION['admin_user'] ?? 'admin');
}

function change_admin_password(string $currentPassword, string $newPassword): bool
{
    $adminId = (int)($_SESSION['admin_id'] ?? 0);
    if ($adminId <= 0) {
        return false;
    }

    $stmt = db()->prepare('SELECT password FROM admins WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => $adminId]);
    $row = $stmt->fetch();
    if (!is_array($row) || !password_verify($currentPassword, (string)$row['password'])) {
        return false;
    }

    $upd = db()->prepare('UPDATE admins SET password = :p WHERE id = :id');
    $upd->execute([':p' => password_hash($newPassword, PASSWORD_BCRYPT), ':id' => $adminId]);
    audit_log('change_password', 'Admin id=' . $adminId . ' changed password');
    return true;
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function get_locations_map(): array
{
    $raw = get_state_value('locations_map', '');
    if ($raw === '') {
        return [
            'RO' => 'Tulcea, Romania',
            'NL' => 'Amsterdam, Netherlands',
            'DE' => 'Frankfurt, Germany',
            'US' => 'Los Angeles, USA',
        ];
    }
    $map = [];
    foreach (preg_split('/\r\n|\r|\n/', $raw) ?: [] as $line) {
        $line = trim($line);
        if ($line === '' || !str_contains($line, '=')) {
            continue;
        }
        [$code, $label] = explode('=', $line, 2);
        $code = strtoupper(trim($code));
        $label = trim($label);
        if ($code !== '' && $label !== '') {
            $map[$code] = $label;
        }
    }
    return $map;
}

function subscribe_email(string $email): array
{
    $email = strtolower(trim($email));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['ok' => false, 'error' => 'Invalid email address.'];
    }

    $stmt = db()->prepare('SELECT id, confirmed FROM subscribers WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => $email]);
    $existing = $stmt->fetch();
    if (is_array($existing)) {
        if ((int)($existing['confirmed'] ?? 0) === 1) {
            return ['ok' => false, 'error' => 'This email is already subscribed.'];
        }
        return ['ok' => true, 'message' => 'Confirmation email already sent. Please check your inbox.', 'resend' => true, 'id' => (int)$existing['id']];
    }

    $token = bin2hex(random_bytes(24));
    $stmt = db()->prepare(
        'INSERT INTO subscribers (email, token, confirmed, created_at)
         VALUES (:email, :token, 0, :created_at)'
    );
    $stmt->execute([
        ':email' => substr($email, 0, 255),
        ':token' => $token,
        ':created_at' => time(),
    ]);

    return ['ok' => true, 'message' => 'Subscribed! You will receive email notifications.', 'token' => $token, 'id' => (int)db()->lastInsertId()];
}

function confirm_subscriber(string $token): bool
{
    $stmt = db()->prepare('UPDATE subscribers SET confirmed = 1 WHERE token = :token AND confirmed = 0');
    $stmt->execute([':token' => $token]);
    return $stmt->rowCount() > 0;
}

function unsubscribe_by_token(string $token): bool
{
    $stmt = db()->prepare('DELETE FROM subscribers WHERE token = :token');
    $stmt->execute([':token' => $token]);
    return $stmt->rowCount() > 0;
}

function unsubscribe_by_email(string $email): bool
{
    $email = strtolower(trim($email));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    $stmt = db()->prepare('DELETE FROM subscribers WHERE email = :email');
    $stmt->execute([':email' => $email]);
    return $stmt->rowCount() > 0;
}

function all_subscribers(bool $confirmedOnly = true): array
{
    $sql = 'SELECT * FROM subscribers';
    if ($confirmedOnly) {
        $sql .= ' WHERE confirmed = 1';
    }
    $sql .= ' ORDER BY created_at DESC';
    return db()->query($sql)->fetchAll();
}

function delete_subscriber(int $id): void
{
    $stmt = db()->prepare('DELETE FROM subscribers WHERE id = :id');
    $stmt->execute([':id' => $id]);
}

function smtp_send_email(string $to, string $subject, string $bodyHtml, string $fromName, string $fromEmail, array $extraHeaders = []): bool
{
    $smtpHost = trim(get_state_value('smtp_host', ''));
    $smtpPort = (int)get_state_value('smtp_port', '587');
    $smtpUser = trim(get_state_value('smtp_user', ''));
    $smtpPass = trim(get_state_value('smtp_pass', ''));
    $smtpEncryption = trim(get_state_value('smtp_encryption', 'none'));

    if ($smtpHost === '' || $smtpPort <= 0) {
        $headers = [
            'From: ' . $fromName . ' <' . $fromEmail . '>',
            'Reply-To: ' . $fromEmail,
            'MIME-Version: 1.0',
            'Content-Type: text/html; charset=UTF-8',
        ];
        foreach ($extraHeaders as $h) {
            $headers[] = $h;
        }
        return @mail($to, $subject, $bodyHtml, implode("\r\n", $headers));
    }

    $prefix = $smtpEncryption === 'ssl' ? 'ssl://' : '';
    $timeout = 10;
    $errno = 0;
    $errstr = '';

    $socket = @stream_socket_client(
        $prefix . $smtpHost . ':' . $smtpPort,
        $errno,
        $errstr,
        $timeout
    );

    if ($socket === false) {
        return false;
    }

    stream_set_timeout($socket, $timeout);

    $read = static function () use ($socket): string {
        $response = '';
        while ($line = fgets($socket, 512)) {
            $response .= $line;
            if (isset($line[3]) && $line[3] === ' ') {
                break;
            }
        }
        return $response;
    };

    $send = static function (string $cmd) use ($socket, $read): string {
        fwrite($socket, $cmd . "\r\n");
        return $read();
    };

    $ok = static function (string $response, string $code = '2'): bool {
        return str_starts_with(trim($response), $code);
    };

    $greeting = $read();
    if (!$ok($greeting)) {
        fclose($socket);
        return false;
    }

    $ehloHost = gethostname() ?: 'localhost';
    $ehloResp = $send('EHLO ' . $ehloHost);
    if (!$ok($ehloResp)) {
        $send('HELO ' . $ehloHost);
    }

    if ($smtpEncryption === 'tls') {
        $tlsResp = $send('STARTTLS');
        if (!$ok($tlsResp)) {
            fclose($socket);
            return false;
        }
        $crypto = stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
        if ($crypto !== true) {
            fclose($socket);
            return false;
        }
        $send('EHLO ' . $ehloHost);
    }

    if ($smtpUser !== '' && $smtpPass !== '') {
        $authResp = $send('AUTH LOGIN');
        if (!$ok($authResp, '3')) {
            fclose($socket);
            return false;
        }
        $userResp = $send(base64_encode($smtpUser));
        if (!$ok($userResp, '3')) {
            fclose($socket);
            return false;
        }
        $passResp = $send(base64_encode($smtpPass));
        if (!$ok($passResp)) {
            fclose($socket);
            return false;
        }
    }

    $fromResp = $send('MAIL FROM:<' . preg_replace('/[\r\n]/', '', $fromEmail) . '>');
    if (!$ok($fromResp)) {
        fclose($socket);
        return false;
    }

    $rcptResp = $send('RCPT TO:<' . preg_replace('/[\r\n]/', '', $to) . '>');
    if (!$ok($rcptResp)) {
        fclose($socket);
        return false;
    }

    $dataResp = $send('DATA');
    if (!$ok($dataResp, '3')) {
        fclose($socket);
        return false;
    }

    $headers = 'From: ' . $fromName . ' <' . $fromEmail . ">\r\n"
        . 'To: ' . $to . "\r\n"
        . 'Subject: ' . $subject . "\r\n"
        . 'MIME-Version: 1.0' . "\r\n"
        . 'Content-Type: text/html; charset=UTF-8' . "\r\n"
        . 'Reply-To: ' . $fromEmail . "\r\n";

    foreach ($extraHeaders as $h) {
        $headers .= $h . "\r\n";
    }

    $body = str_replace("\r\n.", "\r\n..", $bodyHtml);
    $endResp = $send($headers . "\r\n" . $body . "\r\n.");

    $send('QUIT');
    fclose($socket);

    return $ok($endResp);
}

function notify_subscribers(string $subject, string $bodyHtml, string $bodyText): void
{
    $subscribers = all_subscribers(true);
    if (count($subscribers) === 0) {
        return;
    }

    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $fromName = $networkOrg . ' NOC';
    $fromEmail = trim(get_state_value('notify_from_email', ''));
    if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        return;
    }

    foreach ($subscribers as $sub) {
        $email = (string)$sub['email'];
        $token = (string)$sub['token'];
        $unsubLink = rtrim(get_state_value('site_base_url', ''), '/') . '/subscribe?action=unsubscribe&token=' . rawurlencode($token);

        $personalHtml = $bodyHtml . '<p style="margin-top:24px;font-size:12px;color:#888;"><a href="' . htmlspecialchars($unsubLink, ENT_QUOTES, 'UTF-8') . '">Unsubscribe</a></p>';

        smtp_send_email(
            $email,
            $subject,
            $personalHtml,
            $fromName,
            $fromEmail,
            ['List-Unsubscribe: <' . $unsubLink . '>']
        );
    }
}

function notify_announcement(string $title, string $message, string $level, ?string $nodeName): void
{
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $levelUpper = strtoupper($level);
    $affected = $nodeName ?? 'All nodes';

    $subject = '[' . $networkAsn . '] ' . $levelUpper . ' — ' . $title;

    $colorMap = [
        'info' => '#32D4C8',
        'maintenance' => '#F59E0B',
        'degraded' => '#F59E0B',
        'critical' => '#EF4444',
    ];
    $color = $colorMap[$level] ?? '#4EA8FF';

    $bodyHtml = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">'
        . '<div style="background:' . $color . ';color:#fff;padding:12px 20px;border-radius:8px 8px 0 0;font-weight:700;">' . htmlspecialchars($levelUpper, ENT_QUOTES, 'UTF-8') . '</div>'
        . '<div style="background:#111827;color:#e5eefb;padding:20px;border:1px solid #1e293b;border-radius:0 0 8px 8px;">'
        . '<h2 style="margin:0 0 12px;">' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '</h2>'
        . '<p style="color:#93a4bd;margin:0 0 8px;">Affected: ' . htmlspecialchars($affected, ENT_QUOTES, 'UTF-8') . '</p>'
        . '<p style="margin:0;line-height:1.6;">' . nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8')) . '</p>'
        . '<p style="margin:16px 0 0;font-size:12px;color:#64748b;">' . htmlspecialchars($networkAsn . ' • ' . $networkOrg, ENT_QUOTES, 'UTF-8') . '</p>'
        . '</div></div>';

    $bodyText = $levelUpper . " — " . $title . "\nAffected: " . $affected . "\n\n" . $message . "\n\n" . $networkAsn . ' • ' . $networkOrg;

    notify_subscribers($subject, $bodyHtml, $bodyText);
}

function notify_node_down(string $nodeName): void
{
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $subject = '[' . $networkAsn . '] NODE DOWN — ' . $nodeName;

    $bodyHtml = '<div style="font-family:sans-serif;max-width:600px;margin:0 auto;">'
        . '<div style="background:#EF4444;color:#fff;padding:12px 20px;border-radius:8px 8px 0 0;font-weight:700;">NODE DOWN</div>'
        . '<div style="background:#111827;color:#e5eefb;padding:20px;border:1px solid #1e293b;border-radius:0 0 8px 8px;">'
        . '<h2 style="margin:0 0 12px;">' . htmlspecialchars($nodeName, ENT_QUOTES, 'UTF-8') . ' is unreachable</h2>'
        . '<p style="margin:0;line-height:1.6;">The monitoring system detected that <strong>' . htmlspecialchars($nodeName, ENT_QUOTES, 'UTF-8') . '</strong> is not responding. The NOC team has been alerted.</p>'
        . '</div></div>';

    $bodyText = "NODE DOWN — " . $nodeName . "\n\nThe node is not responding. The NOC team has been alerted.";

    notify_subscribers($subject, $bodyHtml, $bodyText);
}

function dispatch_discord_node_down(string $nodeName, int $nodeId): void
{
    $webhookUrl = trim(get_state_value('discord_webhook_url', ''));
    if ($webhookUrl === '' || !filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
        return;
    }

    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => "\xF0\x9F\x9A\xA8 NODE DOWN — " . $nodeName,
                'description' => "**" . $nodeName . "** is not responding.\nAutomatic incident created. The NOC team has been alerted.",
                'color' => 0xEF4444,
                'fields' => [
                    ['name' => 'Status', 'value' => '`CRITICAL`', 'inline' => true],
                    ['name' => 'Affected', 'value' => $nodeName, 'inline' => true],
                    ['name' => 'Detected', 'value' => '<t:' . time() . ':R>', 'inline' => true],
                ],
                'footer' => ['text' => $networkAsn . ' • ' . $networkOrg . ' Status'],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json !== false) {
        send_discord_payload($webhookUrl, $json);
    }
}

function dispatch_discord_node_recovered(string $nodeName, int $nodeId): void
{
    $webhookUrl = trim(get_state_value('discord_webhook_url', ''));
    if ($webhookUrl === '' || !filter_var($webhookUrl, FILTER_VALIDATE_URL)) {
        return;
    }

    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => "\xE2\x9C\x85 NODE RECOVERED — " . $nodeName,
                'description' => "**" . $nodeName . "** is back online.\nAutomatic incident resolved.",
                'color' => 0x22C55E,
                'fields' => [
                    ['name' => 'Status', 'value' => '`RESOLVED`', 'inline' => true],
                    ['name' => 'Affected', 'value' => $nodeName, 'inline' => true],
                    ['name' => 'Recovered', 'value' => '<t:' . time() . ':R>', 'inline' => true],
                ],
                'footer' => ['text' => $networkAsn . ' • ' . $networkOrg . ' Status'],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    $json = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json !== false) {
        send_discord_payload($webhookUrl, $json);
    }
}

function auto_create_downtime_announcement(string $nodeName, int $nodeId): void
{
    // Check if there's already an unresolved auto-announcement for this node
    $stmt = db()->prepare(
        "SELECT id FROM announcements
         WHERE node_id = :nid AND level = 'critical' AND resolved_at IS NULL
         AND title LIKE '[AUTO]%'
         LIMIT 1"
    );
    $stmt->execute([':nid' => $nodeId]);
    if ($stmt->fetch()) {
        return; // already exists
    }

    $now = time();
    $insert = db()->prepare(
        'INSERT INTO announcements (title, message, level, node_id, starts_at, ends_at, pinned, resolved_at, created_at, created_by)
         VALUES (:title, :message, :level, :node_id, :starts_at, NULL, 1, NULL, :created_at, :created_by)'
    );
    $insert->execute([
        ':title' => '[AUTO] ' . $nodeName . ' — Node Down',
        ':message' => 'Automatic alert: ' . $nodeName . ' is not responding. Our monitoring system detected this outage and created this incident automatically. The team is investigating.',
        ':level' => 'critical',
        ':node_id' => $nodeId,
        ':starts_at' => $now,
        ':created_at' => $now,
        ':created_by' => 'system',
    ]);

    $annId = (int)db()->lastInsertId();
    if ($annId > 0) {
        $upd = db()->prepare(
            'INSERT INTO announcement_updates (announcement_id, message, status, created_at, created_by)
             VALUES (:aid, :message, :status, :created_at, :created_by)'
        );
        $upd->execute([
            ':aid' => $annId,
            ':message' => 'Node detected as unreachable. Automatic incident opened.',
            ':status' => 'investigating',
            ':created_at' => $now,
            ':created_by' => 'system',
        ]);
    }
}

function auto_resolve_downtime_announcement(int $nodeId): void
{
    $stmt = db()->prepare(
        "SELECT id FROM announcements
         WHERE node_id = :nid AND level = 'critical' AND resolved_at IS NULL
         AND title LIKE '[AUTO]%'"
    );
    $stmt->execute([':nid' => $nodeId]);
    $rows = $stmt->fetchAll();

    $now = time();
    foreach ($rows as $row) {
        $annId = (int)$row['id'];

        $res = db()->prepare('UPDATE announcements SET resolved_at = :ts WHERE id = :id');
        $res->execute([':ts' => $now, ':id' => $annId]);

        $upd = db()->prepare(
            'INSERT INTO announcement_updates (announcement_id, message, status, created_at, created_by)
             VALUES (:aid, :message, :status, :created_at, :created_by)'
        );
        $upd->execute([
            ':aid' => $annId,
            ':message' => 'Node is back online. Incident resolved automatically.',
            ':status' => 'resolved',
            ':created_at' => $now,
            ':created_by' => 'system',
        ]);
    }
}
