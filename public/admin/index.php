<?php

declare(strict_types=1);

require_once dirname(__DIR__, 2) . '/config.php';
require_once dirname(__DIR__, 2) . '/lib/functions.php';

secure_session_start();
send_security_headers();

ensure_storage();

$parseDateTime = static function (?string $value): ?int {
  if (!is_string($value)) {
    return null;
  }

  $value = trim($value);
  if ($value === '') {
    return null;
  }

  $ts = strtotime($value);
  return $ts !== false ? $ts : null;
};

$loginFailed = false;
$passwordChanged = false;
$passwordError = '';
$testResult = null;
$testNodeId = 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $token = (string)($_POST['csrf_token'] ?? '');
    $action = (string)($_POST['action'] ?? '');

    if (csrf_valid($token)) {
        if ($action === 'login_admin') {
            $loginFailed = !login_admin((string)($_POST['username'] ?? ''), (string)($_POST['password'] ?? ''));
        }

        if ($action === 'logout_admin') {
            logout_admin();
            header('Location: /admin/');
            exit;
        }

        if (is_admin() && $action === 'add_node') {
            add_node(
                (string)($_POST['name'] ?? ''),
                (string)($_POST['node_type'] ?? 'remote'),
                isset($_POST['endpoint_url']) ? (string)$_POST['endpoint_url'] : null,
                isset($_POST['api_token']) ? (string)$_POST['api_token'] : null,
                isset($_POST['ssh_host']) ? (string)$_POST['ssh_host'] : null,
                isset($_POST['ssh_port']) && $_POST['ssh_port'] !== '' ? (int)$_POST['ssh_port'] : null,
                isset($_POST['ssh_user']) ? (string)$_POST['ssh_user'] : null,
                isset($_POST['ssh_password']) ? (string)$_POST['ssh_password'] : null,
                isset($_POST['net_interface']) ? (string)$_POST['net_interface'] : null,
                isset($_POST['country']) ? (string)$_POST['country'] : null
            );

            header('Location: /admin/#nodes');
            exit;
        }

        if (is_admin() && $action === 'edit_node') {
            $id = (int)($_POST['id'] ?? 0);
            if ($id > 0) {
                update_node(
                    $id,
                    (string)($_POST['name'] ?? ''),
                    (string)($_POST['node_type'] ?? 'remote'),
                    isset($_POST['endpoint_url']) ? (string)$_POST['endpoint_url'] : null,
                    isset($_POST['api_token']) ? (string)$_POST['api_token'] : null,
                    isset($_POST['ssh_host']) ? (string)$_POST['ssh_host'] : null,
                    isset($_POST['ssh_port']) && $_POST['ssh_port'] !== '' ? (int)$_POST['ssh_port'] : null,
                    isset($_POST['ssh_user']) ? (string)$_POST['ssh_user'] : null,
                    isset($_POST['ssh_password']) ? (string)$_POST['ssh_password'] : null,
                    isset($_POST['net_interface']) ? (string)$_POST['net_interface'] : null,
                    isset($_POST['country']) ? (string)$_POST['country'] : null
                );
            }
            header('Location: /admin/#nodes');
            exit;
        }

        if (is_admin() && $action === 'delete_node') {
            $id = (int)($_POST['id'] ?? 0);
            if ($id > 0) {
                delete_node($id);
            }

            header('Location: /admin/');
            exit;
        }

        if (is_admin() && $action === 'clear_samples') {
            $id = (int)($_POST['id'] ?? 0);
            if ($id > 0) {
                clear_node_samples($id);
            }
            header('Location: /admin/#nodes');
            exit;
        }

        if (is_admin() && $action === 'test_node') {
            $id = (int)($_POST['id'] ?? 0);
            if ($id > 0) {
                $testNodeId = $id;
                $allNodesForTest = all_nodes(false);
                foreach ($allNodesForTest as $n) {
                    if ((int)$n['id'] === $id) {
                        $testResult = test_node_connection($n);
                        break;
                    }
                }
            }
        }

        if (is_admin() && $action === 'add_announcement') {
            add_announcement(
                (string)($_POST['title'] ?? ''),
                (string)($_POST['message'] ?? ''),
                isset($_POST['pinned']) && $_POST['pinned'] === '1',
            admin_user(),
            (string)($_POST['level'] ?? 'info'),
            isset($_POST['node_id']) && $_POST['node_id'] !== '' ? (int)$_POST['node_id'] : null,
            $parseDateTime(isset($_POST['starts_at']) ? (string)$_POST['starts_at'] : null),
            $parseDateTime(isset($_POST['ends_at']) ? (string)$_POST['ends_at'] : null)
            );

            header('Location: /admin/#announcements');
            exit;
        }

        if (is_admin() && $action === 'delete_announcement') {
            $id = (int)($_POST['id'] ?? 0);
            $annRedirectPage = max(1, (int)($_POST['ann_page'] ?? 1));
            if ($id > 0) {
                delete_announcement($id);
            }

            header('Location: /admin/?ann_page=' . $annRedirectPage . '#announcements');
            exit;
        }

        if (is_admin() && $action === 'add_announcement_update') {
            $announcementId = (int)($_POST['announcement_id'] ?? 0);
            $annRedirectPage = max(1, (int)($_POST['ann_page'] ?? 1));
            if ($announcementId > 0) {
                add_announcement_update(
                    $announcementId,
                    (string)($_POST['update_message'] ?? ''),
                    (string)($_POST['update_status'] ?? 'update'),
                    admin_user()
                );
            }

            header('Location: /admin/?ann_page=' . $annRedirectPage . '#announcements');
            exit;
        }

        if (is_admin() && $action === 'save_network_profile') {
          set_state_value('network_asn', trim((string)($_POST['network_asn'] ?? 'AS201131')));
          set_state_value('network_org', trim((string)($_POST['network_org'] ?? 'LIGA HOSTING LTD')));
          set_state_value('network_prefixes', trim((string)($_POST['network_prefixes'] ?? '')));
          set_state_value('network_countries', trim((string)($_POST['network_countries'] ?? '')));
          set_state_value('network_power_label', trim((string)($_POST['network_power_label'] ?? '')));
          set_state_value('network_prefixes_v6', trim((string)($_POST['network_prefixes_v6'] ?? '')));
          set_state_value('locations_map', trim((string)($_POST['locations_map'] ?? '')));
          set_state_value('site_base_url', trim((string)($_POST['site_base_url'] ?? '')));

          header('Location: /admin/#panel-settings');
          exit;
        }

        if (is_admin() && $action === 'save_integrations') {
          set_state_value('discord_webhook_url', trim((string)($_POST['discord_webhook_url'] ?? '')));

          header('Location: /admin/#panel-settings');
          exit;
        }

        if (is_admin() && $action === 'save_smtp') {
          set_state_value('notify_from_email', trim((string)($_POST['notify_from_email'] ?? '')));
          set_state_value('smtp_host', trim((string)($_POST['smtp_host'] ?? '')));
          set_state_value('smtp_port', trim((string)($_POST['smtp_port'] ?? '')));
          set_state_value('smtp_user', trim((string)($_POST['smtp_user'] ?? '')));
          $smtpPass = trim((string)($_POST['smtp_pass'] ?? ''));
          if ($smtpPass !== '') {
              set_state_value('smtp_pass', $smtpPass);
          }
          set_state_value('smtp_encryption', trim((string)($_POST['smtp_encryption'] ?? 'none')));

          header('Location: /admin/#panel-settings');
          exit;
        }

        if (is_admin() && $action === 'test_smtp') {
            $testTo = trim((string)($_POST['test_email'] ?? ''));
            if ($testTo !== '' && filter_var($testTo, FILTER_VALIDATE_EMAIL)) {
                $networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));
                $networkAsn = trim(get_state_value('network_asn', 'AS201131'));
                $fromEmail = trim(get_state_value('notify_from_email', ''));
                $baseUrl = rtrim(get_state_value('site_base_url', ''), '/');

                $configErrors = [];
                if ($fromEmail === '' || !filter_var($fromEmail, FILTER_VALIDATE_EMAIL)) {
                    $configErrors[] = 'Sender email (notify_from_email) is empty or invalid';
                }
                if ($baseUrl === '') {
                    $configErrors[] = 'Site base URL is empty';
                }

                if (count($configErrors) > 0) {
                    $_SESSION['smtp_test_result'] = 'config_error';
                    $_SESSION['smtp_test_to'] = implode('; ', $configErrors);
                } else {
                    $inner = '<h2 style="margin:0 0 6px;font-size:20px;color:#fff;">SMTP Test</h2>'
                        . '<p style="margin:8px 0 0;line-height:1.7;color:#cbd5e1;font-size:14px;">'
                        . 'If you can read this, your SMTP settings are working correctly.'
                        . '</p>';
                    $bodyHtml = build_email_layout('#4EA8FF', "\xE2\x9C\x89\xEF\xB8\x8F", 'TEST EMAIL', $inner, $networkAsn, $networkOrg, $baseUrl);
                    $bodyHtml = str_replace('{{UNSUB_FOOTER}}', '', $bodyHtml);
                    $sent = smtp_send_email($testTo, '[' . $networkAsn . '] SMTP Test', $bodyHtml, $networkOrg . ' NOC', $fromEmail);
                    $_SESSION['smtp_test_result'] = $sent ? 'ok' : 'fail';
                    $_SESSION['smtp_test_to'] = $testTo;
                }
            }
            header('Location: /admin/#panel-settings');
            exit;
        }

        if (is_admin() && $action === 'delete_subscriber') {
            $id = (int)($_POST['id'] ?? 0);
            if ($id > 0) {
                delete_subscriber($id);
            }
            $subPg = (int)($_POST['sub_page'] ?? 1);
            header('Location: /admin/?sub_page=' . $subPg . '#panel-subscribers');
            exit;
        }

        if (is_admin() && $action === 'change_password') {
            $currentPass = (string)($_POST['current_password'] ?? '');
            $newPass = (string)($_POST['new_password'] ?? '');
            $confirmPass = (string)($_POST['confirm_password'] ?? '');

            if ($newPass !== '' && $newPass === $confirmPass && strlen($newPass) >= 6) {
                $passwordChanged = change_admin_password($currentPass, $newPass);
                $passwordError = $passwordChanged ? '' : 'Current password is incorrect.';
            } else {
                $passwordChanged = false;
                $passwordError = $newPass !== $confirmPass
                    ? 'New passwords do not match.'
                    : 'Password must be at least 6 characters.';
            }
        }
    }
}

$nodes = all_nodes(false);
$announcements = load_announcements();
$allUpdates = load_all_announcement_updates();
$annPage = max(1, (int)($_GET['ann_page'] ?? 1));
$annPerPage = 10;
$annTotal = count($announcements);
$annTotalPages = max(1, (int)ceil($annTotal / $annPerPage));
if ($annPage > $annTotalPages) { $annPage = $annTotalPages; }
$annOffset = ($annPage - 1) * $annPerPage;
$annPaged = array_slice($announcements, $annOffset, $annPerPage);
$networkAsn = get_state_value('network_asn', 'AS201131');
$networkOrg = get_state_value('network_org', 'LIGA HOSTING LTD');
$networkPrefixes = get_state_value('network_prefixes', "2.27.119.0/24\n5.180.33.0/24\n87.76.205.0/24\n163.5.26.0/24");
$networkCountries = get_state_value('network_countries', 'RO, NL, DE, US');
$networkPowerLabel = get_state_value('network_power_label', 'Anycast-ready edge, transit, anti-DDoS and low-latency backbone.');
$networkPrefixesV6 = get_state_value('network_prefixes_v6', '');
$discordWebhookUrl = get_state_value('discord_webhook_url', '');
$locationsMapRaw = get_state_value('locations_map', '');
$siteBaseUrl = get_state_value('site_base_url', '');
$notifyFromEmail = get_state_value('notify_from_email', '');
$smtpHost = get_state_value('smtp_host', '');
$smtpPort = get_state_value('smtp_port', '587');
$smtpUser = get_state_value('smtp_user', '');
$smtpPass = get_state_value('smtp_pass', '');
$smtpEncryption = get_state_value('smtp_encryption', 'none');
$subscribers = all_subscribers(false);
$subPage = max(1, (int)($_GET['sub_page'] ?? 1));
$subPerPage = 20;
$subTotal = count($subscribers);
$subTotalPages = max(1, (int)ceil($subTotal / $subPerPage));
if ($subPage > $subTotalPages) { $subPage = $subTotalPages; }
$subPaged = array_slice($subscribers, ($subPage - 1) * $subPerPage, $subPerPage);
$remoteCount = 0;
foreach ($nodes as $node) {
    if ((string)($node['node_type'] ?? '') === 'remote') {
        $remoteCount++;
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title><?= e(APP_NAME) ?> - Admin</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-wrap">
      <a class="brand" href="/admin/">
        <span class="brand-as"><?= e($networkAsn !== '' ? $networkAsn : 'AS201131') ?></span>
        <span class="brand-name">Control Panel</span>
      </a>

      <nav class="topbar-nav">
        <?php if (is_admin()): ?>
          <a class="nav-link" href="/">
            <svg viewBox="0 0 24 24" aria-hidden="true" style="width:14px;height:14px;fill:currentColor"><path d="M19 19H5V5h7V3H5a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z"/></svg>
            View Status Page
          </a>
          <form method="post" style="display:inline">
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="logout_admin">
            <button class="nav-link logout-nav-btn" type="submit">
              <svg viewBox="0 0 24 24" aria-hidden="true" style="width:14px;height:14px;fill:currentColor"><path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/></svg>
              Logout
            </button>
          </form>
        <?php else: ?>
          <a class="nav-link" href="/">Status page</a>
        <?php endif; ?>
      </nav>
    </div>
  </header>

  <main class="wrap admin-shell">
    <?php if (!is_admin()): ?>
      <section class="login-shell">
        <div class="login-brand">
          <span class="private-badge">Private area /admin/</span>
        </div>

        <article class="panel login-panel">
          <div class="panel-head">
            <div>
              <svg class="login-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM15.1 8H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z"/></svg>
              <h2>Admin login</h2>
              <p>Authenticate to manage nodes, announcements, and subscriber notifications.</p>
            </div>
          </div>

          <?php if (!check_login_throttle()): ?>
            <div class="sub-alert sub-error">Too many failed attempts. Please wait 60 seconds.</div>
          <?php elseif ($loginFailed): ?>
            <div class="sub-alert sub-error">Invalid username or password.</div>
          <?php endif; ?>

          <form method="post" class="form-grid">
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="login_admin">

            <label>
              <span>Username</span>
              <input type="text" name="username" autocomplete="username" required placeholder="admin">
            </label>

            <label>
              <span>Password</span>
              <input type="password" name="password" autocomplete="current-password" required placeholder="••••••••">
            </label>

            <div>
              <button class="btn-primary" type="submit" style="width:100%">Login</button>
            </div>
          </form>

          <a class="login-back-link" href="/">
            <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15.41 7.41 14 6l-6 6 6 6 1.41-1.41L10.83 12z"/></svg>
            Back to status page
          </a>
        </article>
      </section>

    <?php else: ?>

    <section class="admin-topbar-strip">
      <div class="admin-welcome">
        <div>
          <h1 class="admin-welcome-title">Welcome back, <?= e(admin_user()) ?></h1>
          <p class="admin-welcome-sub"><?= e($networkAsn . ' • ' . $networkOrg) ?> — <?= e((string)count($nodes)) ?> node(s), <?= e((string)count($announcements)) ?> announcement(s), <?= e((string)count($subscribers)) ?> subscriber(s)</p>
        </div>
        <span class="private-badge">Admin</span>
      </div>

      <nav class="admin-tabs">
        <button class="admin-tab is-active" type="button" data-panel="nodes">
          <svg viewBox="0 0 24 24"><path d="M20 13H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM20 3H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>
          Nodes
        </button>
        <button class="admin-tab" type="button" data-panel="announcements">
          <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-7 9h-2V5h2v6zm0 4h-2v-2h2v2z"/></svg>
          Announcements
        </button>
        <button class="admin-tab" type="button" data-panel="settings">
          <svg viewBox="0 0 24 24"><path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 00.12-.61l-1.92-3.32a.49.49 0 00-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 00-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.07.62-.07.94s.02.64.07.94l-2.03 1.58a.49.49 0 00-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6A3.6 3.6 0 1112 8.4a3.6 3.6 0 010 7.2z"/></svg>
          Settings
        </button>
        <button class="admin-tab" type="button" data-panel="subscribers">
          <svg viewBox="0 0 24 24"><path d="M20 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm0 4l-8 5-8-5V6l8 5 8-5v2z"/></svg>
          Subscribers
        </button>
        <button class="admin-tab" type="button" data-panel="security">
          <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
          Security
        </button>
      </nav>
    </section>

    <!-- === NODES PANEL === -->
    <section class="admin-panel-page is-visible" id="panel-nodes">
      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>Add node</h2>
            <p>Store host, SSH and network interface details for monitoring.</p>
          </div>
        </div>

        <form method="post" class="form-grid">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="add_node">

          <div class="field-grid">
            <label>
              <span>Node name</span>
              <input type="text" name="name" placeholder="prod-ro-1" required>
            </label>

            <label>
              <span>Type</span>
              <select name="node_type" id="nodeTypeSelect">
                <option value="remote">remote</option>
                <option value="local">local</option>
              </select>
            </label>

            <label>
              <span>Host / IP</span>
              <input type="text" name="ssh_host" placeholder="185.XXX.XXX.XXX or hostname">
            </label>

            <label>
              <span>SSH port</span>
              <input type="text" name="ssh_port" placeholder="22">
            </label>

            <label>
              <span>SSH user</span>
              <input type="text" name="ssh_user" placeholder="root">
            </label>

            <label>
              <span>SSH password</span>
              <input type="password" name="ssh_password" placeholder="stored private">
            </label>

            <label>
              <span>Network interface</span>
              <input type="text" name="net_interface" placeholder="eth0, ens18, vmbr0">
            </label>

            <label>
              <span>Country code</span>
              <input type="text" name="country" placeholder="RO, NL, DE, US" maxlength="10">
            </label>

            <label>
              <span>Agent endpoint URL</span>
              <input type="text" name="endpoint_url" placeholder="https://node.example.com/node-agent.php">
            </label>

            <label>
              <span>Agent API token</span>
              <input type="text" name="api_token" placeholder="optional token for node-agent.php">
            </label>
          </div>

          <div>
            <button class="btn-primary" type="submit">Save node</button>
          </div>
        </form>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>Node inventory</h2>
            <p><?= e((string)count($nodes)) ?> node(s) registered — <?= e((string)$remoteCount) ?> remote</p>
          </div>
        </div>

        <?php if (count($nodes) === 0): ?>
          <div class="admin-empty">No nodes saved yet. Add one above.</div>
        <?php else: ?>
          <div class="admin-node-list">
            <?php foreach ($nodes as $node): ?>
              <?php
              $sshBits = [];
              if (trim((string)($node['ssh_user'] ?? '')) !== '') {
                $sshBits[] = (string)$node['ssh_user'];
              }
              if (!empty($node['ssh_port'])) {
                $sshBits[] = ':' . (string)$node['ssh_port'];
              }
              $nType = (string)($node['node_type'] ?? 'remote');
              $nCountry = (string)($node['country'] ?? '');
              ?>
              <div class="admin-node-card">
                <div class="anc-head">
                  <div class="anc-identity">
                    <strong class="anc-name"><?= e((string)$node['name']) ?></strong>
                    <div class="anc-tags">
                      <span class="anc-type-tag anc-type-<?= e($nType) ?>"><?= e(strtoupper($nType)) ?></span>
                      <?php if ($nCountry !== ''): ?>
                        <span class="anc-country-tag"><?= e($nCountry) ?></span>
                      <?php endif; ?>
                    </div>
                  </div>
                  <div class="anc-actions">
                    <button class="btn-secondary btn-sm" type="button" onclick="this.closest('.admin-node-card').querySelector('.anc-edit-form').classList.toggle('is-visible')">Edit</button>
                    <form method="post" style="display:inline">
                      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                      <input type="hidden" name="action" value="test_node">
                      <input type="hidden" name="id" value="<?= e((string)$node['id']) ?>">
                      <button class="btn-secondary btn-sm" type="submit">Test</button>
                    </form>
                    <form method="post" style="display:inline" onsubmit="return confirm('Clear all samples for this node?')">
                      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                      <input type="hidden" name="action" value="clear_samples">
                      <input type="hidden" name="id" value="<?= e((string)$node['id']) ?>">
                      <button class="btn-warning btn-sm" type="submit">Clear samples</button>
                    </form>
                    <form method="post" style="display:inline" onsubmit="return confirm('Delete this node permanently?')">
                      <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                      <input type="hidden" name="action" value="delete_node">
                      <input type="hidden" name="id" value="<?= e((string)$node['id']) ?>">
                      <button class="btn-danger btn-sm" type="submit">Delete</button>
                    </form>
                  </div>
                </div>
                <div class="anc-details">
                  <?php if (trim((string)($node['ssh_host'] ?? '')) !== ''): ?>
                    <div class="anc-detail">
                      <span>Host</span>
                      <strong><?= e((string)$node['ssh_host']) ?></strong>
                    </div>
                  <?php endif; ?>
                  <?php if (count($sshBits) > 0): ?>
                    <div class="anc-detail">
                      <span>SSH</span>
                      <strong><?= e(implode('', $sshBits)) ?><?php if (trim((string)($node['ssh_password'] ?? '')) !== ''): ?> <span class="masked-secret">••••</span><?php endif; ?></strong>
                    </div>
                  <?php endif; ?>
                  <?php if (trim((string)($node['net_interface'] ?? '')) !== ''): ?>
                    <div class="anc-detail">
                      <span>Interface</span>
                      <strong><?= e((string)$node['net_interface']) ?></strong>
                    </div>
                  <?php endif; ?>
                  <?php if (trim((string)($node['endpoint_url'] ?? '')) !== ''): ?>
                    <div class="anc-detail anc-detail-wide">
                      <span>Endpoint</span>
                      <strong class="anc-endpoint"><?= e((string)$node['endpoint_url']) ?></strong>
                    </div>
                  <?php endif; ?>
                </div>
                <?php if ($testResult !== null && $testNodeId === (int)$node['id']): ?>
                  <div class="anc-test-result <?= $testResult['ok'] ? 'anc-test-ok' : 'anc-test-fail' ?>">
                    <div class="anc-test-header">
                      <strong><?= $testResult['ok'] ? '✅ Connection OK' : '❌ Connection Failed' ?></strong>
                      <span><?= e((string)$testResult['details']['response_ms']) ?>ms</span>
                    </div>
                    <div class="anc-test-details">
                      <span><b>Method:</b> <?= e((string)$testResult['details']['method']) ?></span>
                      <span><b>Status:</b> <?= e((string)$testResult['details']['status']) ?></span>
                      <?php if ($testResult['details']['hostname'] !== null): ?>
                        <span><b>Hostname:</b> <?= e((string)$testResult['details']['hostname']) ?></span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['os_name'] !== null): ?>
                        <span><b>OS:</b> <?= e((string)$testResult['details']['os_name']) ?></span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['cpu_pct'] !== null): ?>
                        <span><b>CPU:</b> <?= e(number_format((float)$testResult['details']['cpu_pct'], 1)) ?>%</span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['cpu_name'] !== null): ?>
                        <span><b>Processor:</b> <?= e((string)$testResult['details']['cpu_name']) ?></span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['cpu_cores'] !== null): ?>
                        <span><b>Cores:</b> <?= e((string)$testResult['details']['cpu_cores']) ?></span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['mem_used_pct'] !== null): ?>
                        <span><b>RAM:</b> <?= e(number_format((float)$testResult['details']['mem_used_pct'], 1)) ?>%</span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['disk_used_pct'] !== null): ?>
                        <span><b>Disk:</b> <?= e(number_format((float)$testResult['details']['disk_used_pct'], 1)) ?>%</span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['load1'] !== null): ?>
                        <span><b>Load:</b> <?= e(number_format((float)$testResult['details']['load1'], 2)) ?></span>
                      <?php endif; ?>
                      <?php if ($testResult['details']['error'] !== null): ?>
                        <span class="anc-test-error"><b>Error:</b> <?= e((string)$testResult['details']['error']) ?></span>
                      <?php endif; ?>
                    </div>
                  </div>
                <?php endif; ?>
                <div class="anc-edit-form">
                  <form method="post" class="form-grid">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="edit_node">
                    <input type="hidden" name="id" value="<?= e((string)$node['id']) ?>">
                    <div class="field-grid">
                      <label><span>Node name</span><input type="text" name="name" value="<?= e((string)$node['name']) ?>" required></label>
                      <label><span>Type</span>
                        <select name="node_type">
                          <option value="remote"<?= $nType === 'remote' ? ' selected' : '' ?>>remote</option>
                          <option value="local"<?= $nType === 'local' ? ' selected' : '' ?>>local</option>
                        </select>
                      </label>
                      <label><span>Host / IP</span><input type="text" name="ssh_host" value="<?= e((string)($node['ssh_host'] ?? '')) ?>"></label>
                      <label><span>SSH port</span><input type="text" name="ssh_port" value="<?= e((string)($node['ssh_port'] ?? '')) ?>"></label>
                      <label><span>SSH user</span><input type="text" name="ssh_user" value="<?= e((string)($node['ssh_user'] ?? '')) ?>"></label>
                      <label><span>SSH password</span><input type="password" name="ssh_password" placeholder="leave blank to keep current"></label>
                      <label><span>Network interface</span><input type="text" name="net_interface" value="<?= e((string)($node['net_interface'] ?? '')) ?>"></label>
                      <label><span>Country code</span><input type="text" name="country" value="<?= e((string)($node['country'] ?? '')) ?>" maxlength="10"></label>
                      <label><span>Agent endpoint URL</span><input type="text" name="endpoint_url" value="<?= e((string)($node['endpoint_url'] ?? '')) ?>"></label>
                      <label><span>Agent API token</span><input type="text" name="api_token" value="<?= e((string)($node['api_token'] ?? '')) ?>"></label>
                    </div>
                    <div><button class="btn-primary btn-sm" type="submit">Save changes</button></div>
                  </form>
                </div>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>
      </article>
    </section>

    <!-- === ANNOUNCEMENTS PANEL === -->
    <section class="admin-panel-page" id="panel-announcements">
      <div class="admin-two-col">
        <article class="panel">
          <div class="panel-head">
            <div>
              <h2>Publish announcement</h2>
              <p>Set severity, affected node, and maintenance window.</p>
            </div>
          </div>

          <form method="post" class="form-grid">
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="add_announcement">

            <label>
              <span>Title</span>
              <input type="text" name="title" maxlength="120" required>
            </label>

            <label>
              <span>Message</span>
              <textarea name="message" rows="4" maxlength="5000" required></textarea>
            </label>

            <div class="field-grid">
              <label>
                <span>Severity</span>
                <select name="level">
                  <option value="info">Info</option>
                  <option value="maintenance">Maintenance</option>
                  <option value="degraded">Degraded</option>
                  <option value="critical">Critical</option>
                </select>
              </label>

              <label>
                <span>Node affected</span>
                <select name="node_id">
                  <option value="">All nodes</option>
                  <?php foreach ($nodes as $node): ?>
                    <option value="<?= e((string)$node['id']) ?>"><?= e((string)$node['name']) ?></option>
                  <?php endforeach; ?>
                </select>
              </label>

              <label>
                <span>Maintenance start</span>
                <input type="datetime-local" name="starts_at">
              </label>

              <label>
                <span>Maintenance end</span>
                <input type="datetime-local" name="ends_at">
              </label>
            </div>

            <label class="check-row">
              <input type="checkbox" name="pinned" value="1">
              <span>Pin at top</span>
            </label>

            <div>
              <button class="btn-primary" type="submit">Publish</button>
            </div>
          </form>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div>
              <h2>Existing announcements</h2>
              <p class="table-meta"><?= e((string)$annTotal) ?> announcement(s)<?= $annTotalPages > 1 ? ' — page ' . e((string)$annPage) . ' of ' . e((string)$annTotalPages) : '' ?></p>
            </div>
          </div>

          <div class="announce-list">
            <?php if ($annTotal === 0): ?>
              <div class="admin-empty">No announcements yet.</div>
            <?php endif; ?>

            <?php foreach ($annPaged as $item): ?>
              <?php
              $level = is_string($item['level'] ?? null) ? (string)$item['level'] : 'info';
              $targetNode = is_string($item['node_name'] ?? null) && trim((string)$item['node_name']) !== '' ? (string)$item['node_name'] : 'All nodes';
              $window = null;
              if (!empty($item['starts_at']) || !empty($item['ends_at'])) {
                  $startText = !empty($item['starts_at']) ? date('Y-m-d H:i', (int)$item['starts_at']) : 'ASAP';
                  $endText = !empty($item['ends_at']) ? date('Y-m-d H:i', (int)$item['ends_at']) : 'until resolved';
                  $window = $startText . ' → ' . $endText;
              }
              ?>
              <article class="announcement-card">
                <div class="announcement-head">
                  <div>
                    <h3><?= e((string)$item['title']) ?></h3>
                    <div class="announcement-tags">
                      <span class="an-level an-<?= e($level) ?>"><?= e(strtoupper($level)) ?></span>
                      <span class="an-target"><?= e($targetNode) ?></span>
                      <?php if (!empty($item['pinned'])): ?>
                        <span class="pin-tag">Pinned</span>
                      <?php endif; ?>
                    </div>
                  </div>
                  <span><?= e(date('Y-m-d H:i', (int)$item['created_at'])) ?></span>
                </div>
                <?php if ($window !== null): ?>
                  <p class="announcement-window">Window: <?= e($window) ?></p>
                <?php endif; ?>
                <p><?= nl2br(e((string)$item['message'])) ?></p>

                <?php
                $annId = (int)$item['id'];
                $updates = $allUpdates[$annId] ?? [];
                ?>
                <?php if (count($updates) > 0): ?>
                  <div class="ann-updates-timeline">
                    <?php foreach ($updates as $upd): ?>
                      <div class="ann-update-entry">
                        <span class="ann-update-status ann-us-<?= e((string)$upd['status']) ?>"><?= e(strtoupper((string)$upd['status'])) ?></span>
                        <div class="ann-update-body">
                          <p><?= nl2br(e((string)$upd['message'])) ?></p>
                          <span class="ann-update-meta"><?= e((string)$upd['created_by']) ?> — <?= e(date('Y-m-d H:i', (int)$upd['created_at'])) ?></span>
                        </div>
                      </div>
                    <?php endforeach; ?>
                  </div>
                <?php endif; ?>

                <div class="ann-actions-row">
                  <form method="post" class="ann-update-form">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="add_announcement_update">
                    <input type="hidden" name="announcement_id" value="<?= e((string)$annId) ?>">
                    <input type="hidden" name="ann_page" value="<?= $annPage ?>">
                    <select name="update_status">
                      <option value="investigating">Investigating</option>
                      <option value="identified">Identified</option>
                      <option value="monitoring">Monitoring</option>
                      <option value="update">Update</option>
                      <option value="resolved">Resolved</option>
                    </select>
                    <input type="text" name="update_message" placeholder="Post a status update..." required maxlength="5000">
                    <button class="btn-primary btn-sm" type="submit">Post</button>
                  </form>
                  <form method="post">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="hidden" name="action" value="delete_announcement">
                    <input type="hidden" name="id" value="<?= e((string)$item['id']) ?>">
                    <input type="hidden" name="ann_page" value="<?= $annPage ?>">
                    <button class="btn-danger btn-sm" type="submit">Delete</button>
                  </form>
                </div>
              </article>
            <?php endforeach; ?>
          </div>

          <?php if ($annTotalPages > 1): ?>
            <nav class="nd-pagination">
              <?php if ($annPage > 1): ?>
                <a class="nd-page-link" href="?ann_page=<?= $annPage - 1 ?>#panel-announcements">← Prev</a>
              <?php endif; ?>
              <?php for ($p = 1; $p <= $annTotalPages; $p++): ?>
                <a class="nd-page-link<?= $p === $annPage ? ' nd-page-active' : '' ?>" href="?ann_page=<?= $p ?>#panel-announcements"><?= $p ?></a>
              <?php endfor; ?>
              <?php if ($annPage < $annTotalPages): ?>
                <a class="nd-page-link" href="?ann_page=<?= $annPage + 1 ?>#panel-announcements">Next →</a>
              <?php endif; ?>
            </nav>
          <?php endif; ?>
        </article>
      </div>
    </section>

    <!-- === SETTINGS PANEL === -->
    <section class="admin-panel-page" id="panel-settings">
      <div class="admin-two-col">
        <article class="panel">
          <div class="panel-head">
            <div>
              <h2>ASN profile</h2>
              <p>Public-facing network information shown on the status page.</p>
            </div>
          </div>

          <form method="post" class="form-grid">
            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
            <input type="hidden" name="action" value="save_network_profile">

            <div class="field-grid">
              <label>
                <span>ASN label</span>
                <input type="text" name="network_asn" value="<?= e($networkAsn) ?>" maxlength="40">
              </label>

              <label>
                <span>Organization</span>
                <input type="text" name="network_org" value="<?= e($networkOrg) ?>" maxlength="80">
              </label>
            </div>

            <label>
              <span>Announced prefixes (one per line)</span>
              <textarea name="network_prefixes" rows="4" maxlength="2000"><?= e($networkPrefixes) ?></textarea>
            </label>

            <label>
              <span>IPv6 prefixes (one per line)</span>
              <textarea name="network_prefixes_v6" rows="3" maxlength="2000"><?= e($networkPrefixesV6) ?></textarea>
            </label>

            <div class="field-grid">
              <label>
                <span>Countries (comma separated)</span>
                <input type="text" name="network_countries" value="<?= e($networkCountries) ?>" maxlength="500" placeholder="RO, DE, NL, FR">
              </label>

              <label>
                <span>Site base URL</span>
                <input type="text" name="site_base_url" value="<?= e($siteBaseUrl) ?>" maxlength="255" placeholder="https://status.example.com">
              </label>
            </div>

            <label>
              <span>Network power label</span>
              <textarea name="network_power_label" rows="2" maxlength="800"><?= e($networkPowerLabel) ?></textarea>
            </label>

            <label>
              <span>Locations map (CODE=Label, one per line)</span>
              <textarea name="locations_map" rows="4" maxlength="2000" placeholder="RO=Tulcea, Romania&#10;NL=Amsterdam, Netherlands&#10;DE=Frankfurt, Germany"><?= e($locationsMapRaw) ?></textarea>
              <span class="field-hint">Maps country codes to display names on cards.</span>
            </label>

            <div>
              <button class="btn-primary" type="submit">Save profile</button>
            </div>
          </form>
        </article>

        <div class="admin-stack">
          <article class="panel">
            <div class="panel-head">
              <div>
                <h2>Integrations</h2>
                <p>Discord and webhook configuration.</p>
              </div>
            </div>

            <form method="post" class="form-grid">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="save_integrations">

              <label>
                <span>Discord Webhook URL</span>
                <input type="text" name="discord_webhook_url" value="<?= e($discordWebhookUrl) ?>" maxlength="500" placeholder="https://discord.com/api/webhooks/...">
                <span class="field-hint">Announcements will be posted as rich embeds automatically.</span>
              </label>

              <div>
                <button class="btn-primary" type="submit">Save integrations</button>
              </div>
            </form>
          </article>

          <article class="panel">
            <div class="panel-head">
              <div>
                <h2>SMTP / Email</h2>
                <p>Configure outbound email for subscriber notifications.</p>
              </div>
            </div>

            <form method="post" class="form-grid">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="save_smtp">

              <label>
                <span>Sender email</span>
                <input type="email" name="notify_from_email" value="<?= e($notifyFromEmail) ?>" maxlength="255" placeholder="noc@example.com">
              </label>

              <div class="field-grid">
                <label>
                  <span>SMTP host</span>
                  <input type="text" name="smtp_host" value="<?= e($smtpHost) ?>" maxlength="255" placeholder="smtp.example.com">
                </label>

                <label>
                  <span>SMTP port</span>
                  <input type="text" name="smtp_port" value="<?= e($smtpPort) ?>" maxlength="5" placeholder="587">
                </label>

                <label>
                  <span>SMTP user</span>
                  <input type="text" name="smtp_user" value="<?= e($smtpUser) ?>" maxlength="255" placeholder="noc@example.com">
                </label>

                <label>
                  <span>SMTP password</span>
                  <input type="password" name="smtp_pass" maxlength="255" placeholder="<?= $smtpPass !== '' ? '••••••••' : '' ?>">
                </label>

                <label>
                  <span>Encryption</span>
                  <select name="smtp_encryption">
                    <option value="none"<?= $smtpEncryption === 'none' ? ' selected' : '' ?>>None</option>
                    <option value="tls"<?= $smtpEncryption === 'tls' ? ' selected' : '' ?>>STARTTLS</option>
                    <option value="ssl"<?= $smtpEncryption === 'ssl' ? ' selected' : '' ?>>SSL/TLS</option>
                  </select>
                </label>
              </div>

              <div>
                <button class="btn-primary" type="submit">Save SMTP</button>
              </div>
            </form>

            <?php
              $smtpTestResult = $_SESSION['smtp_test_result'] ?? null;
              $smtpTestTo = $_SESSION['smtp_test_to'] ?? '';
              unset($_SESSION['smtp_test_result'], $_SESSION['smtp_test_to']);
            ?>
            <?php if ($smtpTestResult !== null): ?>
              <div class="sub-alert sub-<?= $smtpTestResult === 'ok' ? 'success' : 'error' ?>" style="margin:12px 0 0;">
                <?php if ($smtpTestResult === 'ok'): ?>
                  ✅ Test email sent to <?= e($smtpTestTo) ?>. Check your inbox.
                <?php elseif ($smtpTestResult === 'config_error'): ?>
                  ⚠️ Configuration missing: <?= e($smtpTestTo) ?>
                <?php else: ?>
                  ❌ Failed to send test email to <?= e($smtpTestTo) ?>. Check error logs.
                <?php endif; ?>
              </div>
            <?php endif; ?>

            <form method="post" class="form-grid" style="margin-top:16px;padding-top:16px;border-top:1px solid var(--line);">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="test_smtp">
              <label>
                <span>Send test email to</span>
                <input type="email" name="test_email" placeholder="your@email.com" required maxlength="255">
              </label>
              <div>
                <button class="btn-secondary" type="submit">Send test email</button>
              </div>
            </form>
          </article>
        </div>
      </div>
    </section>

    <!-- === SUBSCRIBERS PANEL === -->
    <section class="admin-panel-page" id="panel-subscribers">
      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>Email subscribers</h2>
            <p class="table-meta"><?= e((string)$subTotal) ?> subscriber(s)<?= $subTotalPages > 1 ? ' — page ' . e((string)$subPage) . ' of ' . e((string)$subTotalPages) : '' ?>. Notifications are sent for announcements and node-down events.</p>
          </div>
        </div>

        <?php if ($subTotal === 0): ?>
          <div class="admin-empty">No subscribers yet. Users can subscribe via the public status page.</div>
        <?php else: ?>
          <div class="admin-subscriber-grid">
            <?php foreach ($subPaged as $sub): ?>
              <div class="admin-sub-card">
                <div class="asc-info">
                  <strong><?= e((string)$sub['email']) ?></strong>
                  <div class="asc-meta">
                    <span class="status-chip <?= (int)$sub['confirmed'] === 1 ? 'sc-up' : 'sc-stale' ?>"><?= (int)$sub['confirmed'] === 1 ? 'CONFIRMED' : 'PENDING' ?></span>
                    <span class="asc-date"><?= e(date('Y-m-d H:i', (int)$sub['created_at'])) ?></span>
                  </div>
                </div>
                <form method="post">
                  <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                  <input type="hidden" name="action" value="delete_subscriber">
                  <input type="hidden" name="id" value="<?= e((string)$sub['id']) ?>">
                  <input type="hidden" name="sub_page" value="<?= $subPage ?>">
                  <button class="btn-danger btn-sm" type="submit">Remove</button>
                </form>
              </div>
            <?php endforeach; ?>
          </div>

          <?php if ($subTotalPages > 1): ?>
            <nav class="nd-pagination">
              <?php if ($subPage > 1): ?>
                <a class="nd-page-link" href="?sub_page=<?= $subPage - 1 ?>#panel-subscribers">← Prev</a>
              <?php endif; ?>
              <?php for ($p = 1; $p <= $subTotalPages; $p++): ?>
                <a class="nd-page-link<?= $p === $subPage ? ' nd-page-active' : '' ?>" href="?sub_page=<?= $p ?>#panel-subscribers"><?= $p ?></a>
              <?php endfor; ?>
              <?php if ($subPage < $subTotalPages): ?>
                <a class="nd-page-link" href="?sub_page=<?= $subPage + 1 ?>#panel-subscribers">Next →</a>
              <?php endif; ?>
            </nav>
          <?php endif; ?>
        <?php endif; ?>
      </article>
    </section>

    <!-- === SECURITY PANEL === -->
    <section class="admin-panel-page" id="panel-security">
      <article class="panel">
        <div class="panel-head">
          <h2>Change password</h2>
        </div>

        <?php if ($passwordChanged): ?>
          <div class="alert alert-success" style="margin:0 16px 16px;">Password changed successfully.</div>
        <?php elseif ($passwordError !== ''): ?>
          <div class="alert alert-danger" style="margin:0 16px 16px;"><?= e($passwordError) ?></div>
        <?php endif; ?>

        <form method="post" class="admin-form" style="padding:16px;">
          <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
          <input type="hidden" name="action" value="change_password">

          <div class="form-group">
            <label for="current_password">Current password</label>
            <input type="password" id="current_password" name="current_password" required autocomplete="current-password">
          </div>

          <div class="form-group">
            <label for="new_password">New password</label>
            <input type="password" id="new_password" name="new_password" required minlength="6" autocomplete="new-password">
          </div>

          <div class="form-group">
            <label for="confirm_password">Confirm new password</label>
            <input type="password" id="confirm_password" name="confirm_password" required minlength="6" autocomplete="new-password">
          </div>

          <button type="submit" class="btn-primary">Update password</button>
        </form>
      </article>
    </section>

    <?php endif; ?>
  </main>

  <script>
    // Admin tab navigation
    document.querySelectorAll('.admin-tab').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.querySelectorAll('.admin-tab').forEach(function(t) { t.classList.remove('is-active'); });
        document.querySelectorAll('.admin-panel-page').forEach(function(p) { p.classList.remove('is-visible'); });
        btn.classList.add('is-active');
        var target = document.getElementById('panel-' + btn.getAttribute('data-panel'));
        if (target) target.classList.add('is-visible');
        history.replaceState(null, '', '#' + btn.getAttribute('data-panel'));
      });
    });

    // Restore tab from URL hash
    (function() {
      var hash = location.hash.replace('#', '');
      if (hash) {
        var tab = document.querySelector('.admin-tab[data-panel="' + hash + '"]');
        if (tab) tab.click();
      }
    })();
  </script>

  <footer class="site-footer">
    <div class="topbar-wrap footer-wrap">
      <div class="footer-left">
        <span class="footer-brand"><?= e(trim(get_state_value('network_asn', 'AS201131'))) ?></span>
        <span class="footer-org"><?= e(trim(get_state_value('network_org', 'LIGA HOSTING LTD'))) ?></span>
      </div>
      <div class="footer-right">
        <span>Admin Panel</span>
      </div>
    </div>
  </footer>
</body>
</html>
