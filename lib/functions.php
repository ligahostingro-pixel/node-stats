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

/* ── Login rate limiting (per-IP) ─────────────────────────────── */

function _login_state_key(): string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return 'login_fails_' . md5($ip);
}

function check_login_throttle(): bool
{
    $state = get_state_value(_login_state_key(), '');
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
        set_state_value(_login_state_key(), '');
    }
    return true;
}

function record_login_failure(): void
{
    $key = _login_state_key();
    $state = get_state_value($key, '');
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
    set_state_value($key, json_encode($data));
}

function clear_login_failures(): void
{
    set_state_value(_login_state_key(), '');
}

function ensure_storage(): void
{
    static $done = false;
    if ($done) {
        return;
    }
    $done = true;

    if (!is_dir(DATA_DIR)) {
        mkdir(DATA_DIR, 0775, true);
    }

    if (!is_dir(SAMPLES_DIR)) {
        mkdir(SAMPLES_DIR, 0775, true);
    }

    db();

    // Only seed admin and audit table if needed (check app_state flag)
    $initialized = get_state_value('schema_initialized', '');
    if ($initialized !== '1') {
        seed_default_admin();
        ensure_audit_log_table();
        set_state_value('schema_initialized', '1');
    }
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

function update_node(
    int $id,
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

    if ($name === '' || $id <= 0) {
        return false;
    }

    if (!in_array($type, ['local', 'remote'], true)) {
        return false;
    }

    if (!is_valid_net_interface($netInterface)) {
        return false;
    }

    // If password field is blank, keep the existing password
    $passwordSql = '';
    $params = [
        ':id' => $id,
        ':name' => substr($name, 0, 120),
        ':type' => $type,
        ':ssh_host' => $type === 'remote' && $sshHost !== null && $sshHost !== '' ? substr($sshHost, 0, 255) : null,
        ':ssh_port' => $type === 'remote' && $sshPort !== null && $sshPort > 0 ? $sshPort : null,
        ':ssh_user' => $type === 'remote' && $sshUser !== null && $sshUser !== '' ? substr($sshUser, 0, 120) : null,
        ':net_interface' => $type === 'remote' && $netInterface !== null && $netInterface !== '' ? substr($netInterface, 0, 80) : null,
        ':url' => $type === 'remote' ? substr((string)$endpointUrl, 0, 400) : null,
        ':token' => $type === 'remote' ? substr((string)$apiToken, 0, 255) : null,
        ':country' => $country !== null && $country !== '' ? substr($country, 0, 10) : null,
    ];

    if ($sshPassword !== null && $sshPassword !== '') {
        $passwordSql = ', ssh_password = :ssh_password';
        $params[':ssh_password'] = ($type === 'remote') ? encrypt_value(substr($sshPassword, 0, 255)) : null;
    }

    $stmt = db()->prepare(
        'UPDATE nodes SET
            name = :name, node_type = :type, ssh_host = :ssh_host, ssh_port = :ssh_port,
            ssh_user = :ssh_user, net_interface = :net_interface,
            endpoint_url = :url, api_token = :token, country = :country' . $passwordSql . '
         WHERE id = :id'
    );

    $stmt->execute($params);
    audit_log('update_node', 'Updated node id=' . $id . ': ' . $name . ' (' . $type . ')');
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
        'info' => 0x4EA8FF,
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
    $icon = $iconMap[$level] ?? "\xE2\x84\xB9\xEF\xB8\x8F";

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
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

    $desc = (strlen($message) > 800 ? substr($message, 0, 797) . '...' : $message)
        . "\n"
        . "\n\xF0\x9F\x94\xB9 **Severity:** `" . strtoupper($level) . "`"
        . "\n\xF0\x9F\x96\xA5\xEF\xB8\x8F **Affected:** " . $nodeName;

    if ($startsAt !== null || $endsAt !== null) {
        $windowStart = $startsAt !== null ? '<t:' . $startsAt . ':f>' : 'ASAP';
        $windowEnd = $endsAt !== null ? '<t:' . $endsAt . ':f>' : 'Until resolved';
        $desc .= "\n\xF0\x9F\x93\x85 **Window:** " . $windowStart . ' → ' . $windowEnd;
    }

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => $icon . ' ' . $title,
                'description' => $desc,
                'color' => $color,
                'footer' => ['text' => $networkAsn . ' • ' . $networkOrg],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    if ($baseUrl !== '') {
        $payload['embeds'][0]['fields'] = [
            ['name' => "\xF0\x9F\x94\x97 Links", 'value' => "\xF0\x9F\x93\x8A [Status Page](" . $baseUrl . ")  \xE2\x80\xA2  \xF0\x9F\x94\x94 [Subscribe](" . $baseUrl . "/subscribe)", 'inline' => false],
        ];
        $payload['embeds'][0]['url'] = $baseUrl;
    }

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
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');
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

    $iconMap = [
        'investigating' => "\xF0\x9F\x94\x8D",
        'identified' => "\xF0\x9F\x94\xA7",
        'monitoring' => "\xF0\x9F\x91\x80",
        'update' => "\xE2\x84\xB9\xEF\xB8\x8F",
        'resolved' => "\xE2\x9C\x85",
    ];
    $icon = $iconMap[$updateStatus] ?? "\xE2\x84\xB9\xEF\xB8\x8F";

    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">' . $esc($annTitle) . '</h2>'
        . '<table cellpadding="0" cellspacing="0" border="0" style="margin:12px 0 16px;">'
        . '<tr>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Status</span><br>'
        . '<span style="color:' . $color . ';font-weight:700;font-size:13px;">' . $esc($statusUpper) . '</span>'
        . '</td>'
        . '<td style="width:12px;"></td>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Affected</span><br>'
        . '<span style="color:#e5eefb;font-weight:600;font-size:13px;">' . $esc($affected) . '</span>'
        . '</td>'
        . '</tr></table>'
        . '<div style="border-left:3px solid ' . $color . ';padding:10px 16px;background:rgba(0,0,0,0.2);border-radius:0 6px 6px 0;">'
        . '<p style="margin:0;line-height:1.7;color:#cbd5e1;font-size:14px;">' . nl2br($esc($updateMessage)) . '</p>'
        . '</div>';

    $bodyHtml = build_email_layout($color, $icon, $statusUpper, $inner, $networkAsn, $networkOrg, $baseUrl);
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
        $nodeId = (int)$node['id'];
        $prevSamples = latest_samples_for_node($nodeId, 2);
        $prevStatus  = isset($prevSamples[0]) ? (string)($prevSamples[0]['status'] ?? 'unknown') : 'unknown';
        $prevPrevStatus = isset($prevSamples[1]) ? (string)($prevSamples[1]['status'] ?? 'unknown') : 'unknown';

        $sample = collect_node_metrics($node);
        $newStatus = (string)($sample['status'] ?? 'unknown');

        // Instant retry: if check failed, retry once — if retry succeeds, use success
        if ($newStatus === 'down') {
            error_log('[NOC] Node ' . $nodeId . ' (' . $node['name'] . ') down, retrying once...');
            usleep(500000); // 0.5s pause before retry
            $retry = collect_node_metrics($node);
            $retryStatus = (string)($retry['status'] ?? 'unknown');
            if ($retryStatus !== 'down') {
                error_log('[NOC] Node ' . $nodeId . ' (' . $node['name'] . ') retry succeeded → ' . $retryStatus);
                $sample = $retry;
                $newStatus = $retryStatus;
            } else {
                error_log('[NOC] Node ' . $nodeId . ' (' . $node['name'] . ') retry also failed → down');
            }
        }

        insert_sample($nodeId, $now, $sample);
        $count++;

        $downAlerted = get_state_value('node_' . $nodeId . '_down_alerted', '0') === '1';

        // Alert only after 3 consecutive "down" checks to avoid false alarms
        if ($newStatus === 'down' && $prevStatus === 'down' && $prevPrevStatus === 'down' && !$downAlerted) {
            set_state_value('node_' . $nodeId . '_down_alerted', '1');
            error_log('[NOC] DOWN alert fired for node ' . $nodeId . ' (' . $node['name'] . ')');
            notify_node_down((string)$node['name']);
            dispatch_discord_node_down((string)$node['name'], $nodeId);
            auto_create_downtime_announcement((string)$node['name'], $nodeId);
        }
        // Recover only after 3 consecutive "not down" checks AND a down alert was actually sent
        if ($newStatus !== 'down' && $prevStatus !== 'down' && $prevPrevStatus !== 'down' && $downAlerted) {
            set_state_value('node_' . $nodeId . '_down_alerted', '0');
            error_log('[NOC] RECOVERY alert fired for node ' . $nodeId . ' (' . $node['name'] . ')');
            notify_node_recovered((string)$node['name']);
            dispatch_discord_node_recovered((string)$node['name'], $nodeId);
            auto_resolve_downtime_announcement($nodeId);
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

function latest_samples_for_node(int $nodeId, int $limit = 2): array
{
    $stmt = db()->prepare('SELECT * FROM samples WHERE node_id = :node_id ORDER BY ts DESC LIMIT ' . max(1, $limit));
    $stmt->execute([':node_id' => $nodeId]);
    return $stmt->fetchAll();
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

/**
 * Bulk-fetch network rates for all nodes using a single query.
 * Returns [ nodeId => [rx_bps, tx_bps], ... ]
 */
function bulk_node_net_rates(): array
{
    // Get the 2 most recent samples per node using a window function
    $rows = db()->query(
        'SELECT node_id, ts, net_rx_bytes, net_tx_bytes
         FROM (
             SELECT node_id, ts, net_rx_bytes, net_tx_bytes,
                    ROW_NUMBER() OVER (PARTITION BY node_id ORDER BY ts DESC) AS rn
             FROM samples
         ) ranked
         WHERE rn <= 2
         ORDER BY node_id, ts DESC'
    )->fetchAll();

    $grouped = [];
    foreach ($rows as $row) {
        $nid = (int)$row['node_id'];
        $grouped[$nid][] = $row;
    }

    $map = [];
    foreach ($grouped as $nid => $samples) {
        if (count($samples) < 2) {
            $map[$nid] = [0, 0];
            continue;
        }
        $dt = max(1, abs((int)$samples[0]['ts'] - (int)$samples[1]['ts']));
        $rxDiff = (int)($samples[0]['net_rx_bytes'] ?? 0) - (int)($samples[1]['net_rx_bytes'] ?? 0);
        $txDiff = (int)($samples[0]['net_tx_bytes'] ?? 0) - (int)($samples[1]['net_tx_bytes'] ?? 0);
        if ($rxDiff < 0) { $rxDiff = 0; }
        if ($txDiff < 0) { $txDiff = 0; }
        $map[$nid] = [(int)round($rxDiff / $dt), (int)round($txDiff / $dt)];
    }
    return $map;
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
    $consecutiveDown = 0;
    $realDown = 0;
    foreach ($samples as $sample) {
        $status = (string)($sample['status'] ?? 'unknown');
        if ($status === 'down') {
            $consecutiveDown++;
            $down++;
        } else {
            if ($consecutiveDown >= 3) {
                $realDown += $consecutiveDown;
            }
            $consecutiveDown = 0;
            if ($status === 'degraded') {
                $degraded++;
            }
        }
    }
    if ($consecutiveDown >= 3) {
        $realDown += $consecutiveDown;
    }

    if ($realDown > 0) {
        return 'down';
    }

    if ($degraded > 0) {
        return 'degraded';
    }

    return 'up';
}

/**
 * Bulk-fetch day statuses for all nodes across a list of dates in a single query.
 * Returns [ nodeId => [ 'Y-m-d' => 'up'|'down'|'degraded'|'unknown', ... ], ... ]
 */
function bulk_node_day_statuses(array $dates): array
{
    if (count($dates) === 0) {
        return [];
    }

    $startTs = strtotime(min($dates) . ' 00:00:00');
    $endTs   = strtotime(max($dates) . ' 23:59:59');
    if ($startTs === false || $endTs === false) {
        return [];
    }

    // Fetch individual samples ordered by node and time to detect consecutive runs
    $stmt = db()->prepare(
        "SELECT node_id, DATE(FROM_UNIXTIME(ts)) AS day, status
         FROM samples
         WHERE ts BETWEEN :start_ts AND :end_ts
         ORDER BY node_id, ts ASC"
    );
    $stmt->execute([':start_ts' => $startTs, ':end_ts' => $endTs]);
    $rows = $stmt->fetchAll();

    // Group samples by node_id + day
    $grouped = [];
    foreach ($rows as $row) {
        $key = (int)$row['node_id'] . '|' . (string)$row['day'];
        $grouped[$key][] = (string)($row['status'] ?? 'unknown');
    }

    $map = [];
    foreach ($grouped as $key => $statuses) {
        [$nid, $day] = explode('|', $key, 2);
        $nid = (int)$nid;

        $consecutiveDown = 0;
        $realDown = 0;
        $degraded = 0;

        foreach ($statuses as $s) {
            if ($s === 'down') {
                $consecutiveDown++;
            } else {
                if ($consecutiveDown >= 3) {
                    $realDown += $consecutiveDown;
                }
                $consecutiveDown = 0;
                if ($s === 'degraded') {
                    $degraded++;
                }
            }
        }
        if ($consecutiveDown >= 3) {
            $realDown += $consecutiveDown;
        }

        if ($realDown > 0) {
            $status = 'down';
        } elseif ($degraded > 0) {
            $status = 'degraded';
        } else {
            $status = 'up';
        }

        if (!isset($map[$nid])) {
            $map[$nid] = [];
        }
        $map[$nid][$day] = $status;
    }

    return $map;
}

function node_uptime_percent(int $nodeId, int $days = 30): ?float
{
    $start = strtotime('-' . max(1, $days) . ' day');
    if ($start === false) {
        return null;
    }

    $stmt = db()->prepare(
        "SELECT status FROM samples
         WHERE node_id = :node_id AND ts >= :start_ts
         ORDER BY ts ASC"
    );
    $stmt->execute([
        ':node_id' => $nodeId,
        ':start_ts' => $start,
    ]);
    $rows = $stmt->fetchAll();

    $total = count($rows);
    if ($total === 0) {
        return null;
    }

    // Count only 3+ consecutive downs as real downtime
    $consecutiveDown = 0;
    $realDown = 0;
    foreach ($rows as $row) {
        if (($row['status'] ?? 'unknown') === 'down') {
            $consecutiveDown++;
        } else {
            if ($consecutiveDown >= 3) {
                $realDown += $consecutiveDown;
            }
            $consecutiveDown = 0;
        }
    }
    if ($consecutiveDown >= 3) {
        $realDown += $consecutiveDown;
    }

    $up = $total - $realDown;
    return round(($up / $total) * 100, 4);
}

/**
 * Bulk-fetch uptime percentages for all nodes in a single query.
 * Returns [ nodeId => float|null, ... ]
 */
function bulk_node_uptime_percent(int $days = 30): array
{
    $start = strtotime('-' . max(1, $days) . ' day');
    if ($start === false) {
        return [];
    }

    $stmt = db()->prepare(
        "SELECT node_id, status FROM samples
         WHERE ts >= :start_ts
         ORDER BY node_id, ts ASC"
    );
    $stmt->execute([':start_ts' => $start]);
    $rows = $stmt->fetchAll();

    // Group by node
    $byNode = [];
    foreach ($rows as $row) {
        $byNode[(int)$row['node_id']][] = (string)($row['status'] ?? 'unknown');
    }

    $map = [];
    foreach ($byNode as $nid => $statuses) {
        $total = count($statuses);
        $consecutiveDown = 0;
        $realDown = 0;
        foreach ($statuses as $s) {
            if ($s === 'down') {
                $consecutiveDown++;
            } else {
                if ($consecutiveDown >= 3) {
                    $realDown += $consecutiveDown;
                }
                $consecutiveDown = 0;
            }
        }
        if ($consecutiveDown >= 3) {
            $realDown += $consecutiveDown;
        }
        $up = $total - $realDown;
        $map[$nid] = $total > 0 ? round(($up / $total) * 100, 4) : null;
    }
    return $map;
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
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    }
    session_destroy();
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

    $stmt = db()->prepare('SELECT id, confirmed, token FROM subscribers WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => $email]);
    $existing = $stmt->fetch();
    if (is_array($existing)) {
        if ((int)($existing['confirmed'] ?? 0) === 1) {
            return ['ok' => false, 'error' => 'This email is already subscribed.'];
        }
        // Resend confirmation email
        try {
            $sendResult = send_confirmation_email($email, (string)$existing['token']);
        } catch (\Throwable $e) {
            error_log('[NOC] send_confirmation_email exception: ' . $e->getMessage());
            $sendResult = 'Exception: ' . $e->getMessage();
        }
        if ($sendResult !== 'ok') {
            return ['ok' => false, 'error' => 'Could not send confirmation email: ' . $sendResult];
        }
        return ['ok' => true, 'message' => 'Confirmation email sent. Please check your inbox (and spam folder).', 'resend' => true, 'id' => (int)$existing['id']];
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

    try {
        $sendResult = send_confirmation_email($email, $token);
    } catch (\Throwable $e) {
        error_log('[NOC] send_confirmation_email exception: ' . $e->getMessage());
        $sendResult = 'Exception: ' . $e->getMessage();
    }
    if ($sendResult !== 'ok') {
        return ['ok' => false, 'error' => 'Subscribed, but email failed: ' . $sendResult];
    }

    return ['ok' => true, 'message' => 'Confirmation email sent! Please check your inbox (and spam folder) to confirm your subscription.', 'token' => $token, 'id' => (int)db()->lastInsertId()];
}

function send_confirmation_email(string $email, string $token): string
{
    error_log('[NOC] send_confirmation_email() called for: ' . $email);
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $fromName = $networkOrg . ' NOC';
    $fromEmail = trim(get_state_value('notify_from_email', ''));
    if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        error_log('[NOC] send_confirmation_email: invalid notify_from_email: "' . $fromEmail . '"');
        return 'Sender email not configured (notify_from_email="' . $fromEmail . '")';
    }

    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');
    if ($baseUrl === '') {
        error_log('[NOC] send_confirmation_email: site_base_url is empty');
        return 'Site base URL not configured';
    }

    $confirmLink = $baseUrl . '/subscribe?action=confirm&token=' . rawurlencode($token);
    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $subject = '[' . $networkAsn . '] Confirm your subscription';

    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">Confirm your email</h2>'
        . '<p style="margin:8px 0 20px;line-height:1.7;color:#cbd5e1;font-size:14px;">'
        . 'You requested to receive status notifications from <strong style="color:#fff;">' . $esc($networkOrg) . '</strong>.'
        . '<br>Click the button below to activate your subscription.'
        . '</p>'
        . '<table cellpadding="0" cellspacing="0" border="0"><tr><td style="border-radius:8px;background:#4EA8FF;text-align:center;">'
        . '<a href="' . $esc($confirmLink) . '" style="display:inline-block;padding:14px 32px;color:#fff;font-weight:700;font-size:14px;text-decoration:none;letter-spacing:0.3px;">Confirm subscription</a>'
        . '</td></tr></table>'
        . '<p style="margin:20px 0 0;font-size:12px;color:#64748b;line-height:1.5;">If you did not request this, you can safely ignore this email.</p>';

    $bodyHtml = build_email_layout('#4EA8FF', "\xF0\x9F\x94\x94", 'CONFIRM SUBSCRIPTION', $inner, $networkAsn, $networkOrg, $baseUrl);
    $bodyHtml = str_replace('{{UNSUB_FOOTER}}', '', $bodyHtml);

    $sent = smtp_send_email($email, $subject, $bodyHtml, $fromName, $fromEmail);
    error_log('[NOC] send_confirmation_email result for ' . $email . ': ' . ($sent ? 'OK' : 'FAILED'));
    return $sent ? 'ok' : 'SMTP send failed (check error log for [SMTP] details)';
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

function send_unsubscribe_email(string $email): bool
{
    error_log('[NOC] send_unsubscribe_email() called for: ' . $email);
    $email = strtolower(trim($email));
    if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        error_log('[NOC] send_unsubscribe_email: invalid email');
        return false;
    }

    $stmt = db()->prepare('SELECT token FROM subscribers WHERE email = :email LIMIT 1');
    $stmt->execute([':email' => $email]);
    $row = $stmt->fetch();
    if (!is_array($row)) {
        error_log('[NOC] send_unsubscribe_email: email not found in subscribers: ' . $email);
        return false;
    }

    $token = (string)$row['token'];
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $fromName = $networkOrg . ' NOC';
    $fromEmail = trim(get_state_value('notify_from_email', ''));
    if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        error_log('[NOC] send_unsubscribe_email: invalid notify_from_email: "' . $fromEmail . '"');
        return false;
    }

    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');
    if ($baseUrl === '') {
        error_log('[NOC] send_unsubscribe_email: site_base_url is empty');
        return false;
    }

    $unsubLink = $baseUrl . '/subscribe?action=unsubscribe&token=' . rawurlencode($token);
    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $subject = '[' . $networkAsn . '] Confirm unsubscribe';

    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">Confirm unsubscribe</h2>'
        . '<p style="margin:8px 0 20px;line-height:1.7;color:#cbd5e1;font-size:14px;">'
        . 'You requested to unsubscribe from status notifications for <strong style="color:#fff;">' . $esc($networkOrg) . '</strong>.'
        . '<br>Click the button below to confirm. If you did not request this, ignore this email.'
        . '</p>'
        . '<table cellpadding="0" cellspacing="0" border="0"><tr><td style="border-radius:8px;background:#EF4444;text-align:center;">'
        . '<a href="' . $esc($unsubLink) . '" style="display:inline-block;padding:14px 32px;color:#fff;font-weight:700;font-size:14px;text-decoration:none;letter-spacing:0.3px;">Confirm unsubscribe</a>'
        . '</td></tr></table>'
        . '<p style="margin:20px 0 0;font-size:12px;color:#64748b;line-height:1.5;">If you did not request this, no action is needed — your subscription remains active.</p>';

    $bodyHtml = build_email_layout('#EF4444', "\xF0\x9F\x94\x95", 'UNSUBSCRIBE', $inner, $networkAsn, $networkOrg, $baseUrl);
    $bodyHtml = str_replace('{{UNSUB_FOOTER}}', '', $bodyHtml);

    $sent = smtp_send_email($email, $subject, $bodyHtml, $fromName, $fromEmail);
    error_log('[NOC] send_unsubscribe_email result for ' . $email . ': ' . ($sent ? 'OK' : 'FAILED'));
    return $sent;
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
    // Auto-upgrade to STARTTLS on port 587 when encryption is not explicitly set
    $useStartTls = $smtpEncryption === 'tls' || ($smtpEncryption === 'none' && $smtpPort === 587);
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
        error_log('[SMTP] Connection failed to ' . $smtpHost . ':' . $smtpPort . ' — ' . $errstr . ' (errno=' . $errno . ')');
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
        error_log('[SMTP] Bad greeting from ' . $smtpHost . ': ' . trim($greeting));
        fclose($socket);
        return false;
    }

    $ehloHost = gethostname() ?: 'localhost';
    $ehloResp = $send('EHLO ' . $ehloHost);
    if (!$ok($ehloResp)) {
        $send('HELO ' . $ehloHost);
    }

    if ($useStartTls) {
        $tlsResp = $send('STARTTLS');
        if (!$ok($tlsResp)) {
            error_log('[SMTP] STARTTLS rejected by ' . $smtpHost . ': ' . trim($tlsResp));
            fclose($socket);
            return false;
        }
        $crypto = stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
        if ($crypto !== true) {
            error_log('[SMTP] TLS handshake failed with ' . $smtpHost);
            fclose($socket);
            return false;
        }
        $send('EHLO ' . $ehloHost);
    }

    if ($smtpUser !== '' && $smtpPass !== '') {
        $authResp = $send('AUTH LOGIN');
        if (!$ok($authResp, '3')) {
            error_log('[SMTP] AUTH LOGIN rejected by ' . $smtpHost . ': ' . trim($authResp));
            fclose($socket);
            return false;
        }
        $userResp = $send(base64_encode($smtpUser));
        if (!$ok($userResp, '3')) {
            error_log('[SMTP] AUTH user rejected by ' . $smtpHost . ': ' . trim($userResp));
            fclose($socket);
            return false;
        }
        $passResp = $send(base64_encode($smtpPass));
        if (!$ok($passResp)) {
            error_log('[SMTP] AUTH password rejected by ' . $smtpHost . ': ' . trim($passResp));
            fclose($socket);
            return false;
        }
    }

    $fromResp = $send('MAIL FROM:<' . preg_replace('/[\r\n]/', '', $fromEmail) . '>');
    if (!$ok($fromResp)) {
        error_log('[SMTP] MAIL FROM rejected: ' . trim($fromResp));
        fclose($socket);
        return false;
    }

    $rcptResp = $send('RCPT TO:<' . preg_replace('/[\r\n]/', '', $to) . '>');
    if (!$ok($rcptResp)) {
        error_log('[SMTP] RCPT TO <' . $to . '> rejected: ' . trim($rcptResp));
        fclose($socket);
        return false;
    }

    $dataResp = $send('DATA');
    if (!$ok($dataResp, '3')) {
        error_log('[SMTP] DATA rejected: ' . trim($dataResp));
        fclose($socket);
        return false;
    }

    $headers = 'From: ' . $fromName . ' <' . $fromEmail . ">\r\n"
        . 'To: ' . $to . "\r\n"
        . 'Subject: ' . $subject . "\r\n"
        . 'MIME-Version: 1.0' . "\r\n"
        . 'Content-Type: text/html; charset=UTF-8' . "\r\n"
        . 'Content-Transfer-Encoding: base64' . "\r\n"
        . 'Reply-To: ' . $fromEmail . "\r\n";

    foreach ($extraHeaders as $h) {
        $headers .= $h . "\r\n";
    }

    $body = rtrim(chunk_split(base64_encode($bodyHtml), 76, "\r\n"));
    $endResp = $send($headers . "\r\n" . $body . "\r\n.");

    $send('QUIT');
    fclose($socket);

    return $ok($endResp);
}

function notify_subscribers(string $subject, string $bodyHtml, string $bodyText): void
{
    $subscribers = all_subscribers(true);
    if (count($subscribers) === 0) {
        error_log('[NOC] notify_subscribers: no confirmed subscribers, skipping email for: ' . $subject);
        return;
    }

    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $fromName = $networkOrg . ' NOC';
    $fromEmail = trim(get_state_value('notify_from_email', ''));
    if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
        error_log('[NOC] notify_subscribers: invalid or empty notify_from_email, skipping: ' . $subject);
        return;
    }

    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

    foreach ($subscribers as $sub) {
        $email = (string)$sub['email'];
        $token = (string)$sub['token'];
        $unsubLink = $baseUrl !== '' ? $baseUrl . '/subscribe?action=unsubscribe&token=' . rawurlencode($token) : '';

        $footer = '<tr><td style="padding:24px 32px;text-align:center;border-top:1px solid #1e293b;">';
        if ($unsubLink !== '') {
            $footer .= '<a href="' . htmlspecialchars($unsubLink, ENT_QUOTES, 'UTF-8') . '" style="color:#64748b;font-size:12px;text-decoration:underline;">Unsubscribe from notifications</a>';
        }
        $footer .= '</td></tr>';

        $personalHtml = str_replace('{{UNSUB_FOOTER}}', $footer, $bodyHtml);

        $headers = [];
        if ($unsubLink !== '') {
            $headers[] = 'List-Unsubscribe: <' . $unsubLink . '>';
        }

        error_log('[NOC] Sending email to ' . $email . ' — Subject: ' . $subject);
        $sent = smtp_send_email(
            $email,
            $subject,
            $personalHtml,
            $fromName,
            $fromEmail,
            $headers
        );
        if (!$sent) {
            error_log('[NOC] Email FAILED for ' . $email . ' — Subject: ' . $subject);
        }
    }
}

/**
 * Build a consistent HTML email layout.
 *
 * @param string $bannerColor  Hex color for the top banner
 * @param string $bannerIcon   Emoji/symbol for the banner
 * @param string $bannerLabel  Label text on the banner
 * @param string $innerHtml    Main content HTML (goes inside the body cell)
 * @param string $networkAsn   e.g. "AS201131"
 * @param string $networkOrg   e.g. "LIGA HOSTING LTD"
 * @param string $statusPageUrl e.g. "https://as201131.net"
 */
function build_email_layout(string $bannerColor, string $bannerIcon, string $bannerLabel, string $innerHtml, string $networkAsn, string $networkOrg, string $statusPageUrl): string
{
    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $statusLink = '';
    if ($statusPageUrl !== '') {
        $statusLink = '<a href="' . $esc($statusPageUrl) . '" style="color:#4EA8FF;text-decoration:none;">View status page &rarr;</a>';
    }

    return '<!DOCTYPE html><html><head><meta charset="utf-8"></head><body style="margin:0;padding:0;background:#0a0f1a;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Roboto,sans-serif;">'
        . '<table cellpadding="0" cellspacing="0" border="0" width="100%" style="background:#0a0f1a;padding:32px 16px;">'
        . '<tr><td align="center">'
        . '<table cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;width:100%;border-radius:12px;overflow:hidden;border:1px solid #1e293b;">'
        // Banner
        . '<tr><td style="background:' . $bannerColor . ';padding:16px 32px;text-align:center;">'
        . '<span style="font-size:20px;vertical-align:middle;">' . $bannerIcon . '</span>'
        . ' <span style="color:#fff;font-size:16px;font-weight:700;letter-spacing:0.5px;vertical-align:middle;">' . $esc($bannerLabel) . '</span>'
        . '</td></tr>'
        // Body
        . '<tr><td style="background:#111827;padding:28px 32px;color:#e5eefb;">'
        . $innerHtml
        . '</td></tr>'
        // Status page link
        . '<tr><td style="background:#111827;padding:0 32px 20px;text-align:center;">'
        . $statusLink
        . '</td></tr>'
        // Footer: ASN + org
        . '<tr><td style="background:#0d1117;padding:16px 32px;text-align:center;">'
        . '<span style="color:#475569;font-size:12px;">' . $esc($networkAsn) . ' &bull; ' . $esc($networkOrg) . '</span>'
        . '</td></tr>'
        // Unsubscribe (replaced per-subscriber)
        . '{{UNSUB_FOOTER}}'
        . '</table>'
        . '</td></tr></table>'
        . '</body></html>';
}

function notify_announcement(string $title, string $message, string $level, ?string $nodeName): void
{
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');
    $affected = $nodeName ?? 'All nodes';
    $levelUpper = strtoupper($level);

    $subject = '[' . $networkAsn . '] ' . $levelUpper . ' — ' . $title;

    $colorMap = [
        'info' => '#4EA8FF',
        'maintenance' => '#F59E0B',
        'degraded' => '#F59E0B',
        'critical' => '#EF4444',
    ];
    $color = $colorMap[$level] ?? '#4EA8FF';

    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $iconMap = [
        'info' => "\xE2\x84\xB9\xEF\xB8\x8F",
        'maintenance' => "\xF0\x9F\x94\xA7",
        'degraded' => "\xE2\x9A\xA0\xEF\xB8\x8F",
        'critical' => "\xF0\x9F\x9A\xA8",
    ];
    $icon = $iconMap[$level] ?? "\xE2\x84\xB9\xEF\xB8\x8F";

    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">' . $esc($title) . '</h2>'
        . '<table cellpadding="0" cellspacing="0" border="0" style="margin:12px 0 16px;">'
        . '<tr>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;margin-right:8px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Severity</span><br>'
        . '<span style="color:' . $color . ';font-weight:700;font-size:13px;">' . $esc($levelUpper) . '</span>'
        . '</td>'
        . '<td style="width:12px;"></td>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Affected</span><br>'
        . '<span style="color:#e5eefb;font-weight:600;font-size:13px;">' . $esc($affected) . '</span>'
        . '</td>'
        . '</tr></table>'
        . '<p style="margin:0;line-height:1.7;color:#cbd5e1;font-size:14px;">' . nl2br($esc($message)) . '</p>';

    $bodyHtml = build_email_layout($color, $icon, $levelUpper, $inner, $networkAsn, $networkOrg, $baseUrl);
    $bodyText = $levelUpper . " — " . $title . "\nAffected: " . $affected . "\n\n" . $message . "\n\n" . $networkAsn . ' • ' . $networkOrg;

    notify_subscribers($subject, $bodyHtml, $bodyText);
}

function notify_node_down(string $nodeName): void
{
    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

    $subject = '[' . $networkAsn . '] NODE DOWN — ' . $nodeName;

    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">' . $esc($nodeName) . ' is unreachable</h2>'
        . '<p style="margin:8px 0 0;line-height:1.7;color:#cbd5e1;font-size:14px;">'
        . 'The monitoring system detected that <strong style="color:#fff;">' . $esc($nodeName) . '</strong> is not responding.'
        . '<br>An automatic incident has been created and the NOC team has been alerted.'
        . '</p>'
        . '<table cellpadding="0" cellspacing="0" border="0" style="margin:16px 0 0;">'
        . '<tr>'
        . '<td style="padding:6px 12px;background:rgba(239,68,68,0.1);border-radius:6px;border:1px solid rgba(239,68,68,0.2);">'
        . '<span style="color:#EF4444;font-weight:700;font-size:13px;">&#9679; CRITICAL</span>'
        . '</td>'
        . '<td style="width:12px;"></td>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Node</span><br>'
        . '<span style="color:#e5eefb;font-weight:600;font-size:13px;">' . $esc($nodeName) . '</span>'
        . '</td>'
        . '<td style="width:12px;"></td>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Detected</span><br>'
        . '<span style="color:#e5eefb;font-weight:600;font-size:13px;">' . $esc(gmdate('Y-m-d H:i')) . ' UTC</span>'
        . '</td>'
        . '</tr></table>';

    $bodyHtml = build_email_layout('#EF4444', "\xF0\x9F\x9A\xA8", 'NODE DOWN', $inner, $networkAsn, $networkOrg, $baseUrl);
    $bodyText = "NODE DOWN — " . $nodeName . "\n\nThe node is not responding. The NOC team has been alerted.";

    notify_subscribers($subject, $bodyHtml, $bodyText);
}

function notify_node_recovered(string $nodeName): void
{
    error_log('[NOC] notify_node_recovered() called for: ' . $nodeName);

    $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
    $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

    $subject = '[' . $networkAsn . '] NODE RECOVERED — ' . $nodeName;

    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">' . $esc($nodeName) . ' is back online</h2>'
        . '<p style="margin:8px 0 0;line-height:1.7;color:#cbd5e1;font-size:14px;">'
        . '<strong style="color:#fff;">' . $esc($nodeName) . '</strong> has recovered and is responding normally.'
        . '<br>The automatic incident has been resolved.'
        . '</p>'
        . '<table cellpadding="0" cellspacing="0" border="0" style="margin:16px 0 0;">'
        . '<tr>'
        . '<td style="padding:6px 12px;background:rgba(34,197,94,0.1);border-radius:6px;border:1px solid rgba(34,197,94,0.2);">'
        . '<span style="color:#22C55E;font-weight:700;font-size:13px;">&#10003; RESOLVED</span>'
        . '</td>'
        . '<td style="width:12px;"></td>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Node</span><br>'
        . '<span style="color:#e5eefb;font-weight:600;font-size:13px;">' . $esc($nodeName) . '</span>'
        . '</td>'
        . '<td style="width:12px;"></td>'
        . '<td style="padding:6px 12px;background:rgba(255,255,255,0.05);border-radius:6px;">'
        . '<span style="color:#94a3b8;font-size:12px;">Recovered</span><br>'
        . '<span style="color:#e5eefb;font-weight:600;font-size:13px;">' . $esc(gmdate('Y-m-d H:i')) . ' UTC</span>'
        . '</td>'
        . '</tr></table>';

    $bodyHtml = build_email_layout('#22C55E', "\xE2\x9C\x85", 'NODE RECOVERED', $inner, $networkAsn, $networkOrg, $baseUrl);
    $bodyText = "NODE RECOVERED — " . $nodeName . "\n\nThe node is back online and responding normally.";

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
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

    $desc = "\xE2\x9D\x8C **" . $nodeName . "** is not responding to health checks.\n"
        . "An automatic incident has been created.\n"
        . "\n"
        . "\xF0\x9F\x94\xB9 **Severity:** `CRITICAL`\n"
        . "\xF0\x9F\x96\xA5\xEF\xB8\x8F **Node:** " . $nodeName . "\n"
        . "\xF0\x9F\x95\x90 **Detected:** <t:" . time() . ":f> (<t:" . time() . ":R>)";

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => "\xF0\x9F\x9A\xA8 Node Outage — " . $nodeName,
                'description' => $desc,
                'color' => 0xEF4444,
                'footer' => ['text' => $networkAsn . ' • ' . $networkOrg],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    if ($baseUrl !== '') {
        $payload['embeds'][0]['fields'] = [
            ['name' => "\xF0\x9F\x94\x97 Links", 'value' => "\xF0\x9F\x93\x8A [Status Page](" . $baseUrl . ")  \xE2\x80\xA2  \xF0\x9F\x94\x94 [Subscribe](" . $baseUrl . "/subscribe)", 'inline' => false],
        ];
        $payload['embeds'][0]['url'] = $baseUrl;
    }

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
    $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

    $desc = "\xE2\x9C\x85 **" . $nodeName . "** is back online and responding normally.\n"
        . "The automatic incident has been resolved.\n"
        . "\n"
        . "\xF0\x9F\x94\xB9 **Status:** `RESOLVED`\n"
        . "\xF0\x9F\x96\xA5\xEF\xB8\x8F **Node:** " . $nodeName . "\n"
        . "\xF0\x9F\x95\x90 **Recovered:** <t:" . time() . ":f> (<t:" . time() . ":R>)";

    $payload = [
        'username' => $networkOrg . ' NOC',
        'embeds' => [
            [
                'title' => "\xE2\x9C\x85 Node Recovered — " . $nodeName,
                'description' => $desc,
                'color' => 0x22C55E,
                'footer' => ['text' => $networkAsn . ' • ' . $networkOrg],
                'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            ],
        ],
    ];

    if ($baseUrl !== '') {
        $payload['embeds'][0]['fields'] = [
            ['name' => "\xF0\x9F\x94\x97 Links", 'value' => "\xF0\x9F\x93\x8A [Status Page](" . $baseUrl . ")  \xE2\x80\xA2  \xF0\x9F\x94\x94 [Subscribe](" . $baseUrl . "/subscribe)", 'inline' => false],
        ];
        $payload['embeds'][0]['url'] = $baseUrl;
    }

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
