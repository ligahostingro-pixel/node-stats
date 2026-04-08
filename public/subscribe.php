<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/config.php';
require_once dirname(__DIR__) . '/lib/functions.php';

secure_session_start();
send_security_headers();

ensure_storage();

$networkAsn = trim(get_state_value('network_asn', 'AS201131'));
$networkOrg = trim(get_state_value('network_org', 'LIGA HOSTING LTD'));

$action = isset($_GET['action']) && is_string($_GET['action']) ? trim($_GET['action']) : '';
$message = '';
$messageType = '';

if ($action === 'confirm' && isset($_GET['token']) && is_string($_GET['token'])) {
    $token = trim($_GET['token']);
    if ($token !== '' && confirm_subscriber($token)) {
        $message = 'Your email has been confirmed. You will now receive notifications.';
        $messageType = 'success';
    } else {
        $message = 'Invalid or already confirmed token.';
        $messageType = 'error';
    }
}

if ($action === 'unsubscribe' && isset($_GET['token']) && is_string($_GET['token'])) {
    $token = trim($_GET['token']);
    if ($token !== '' && unsubscribe_by_token($token)) {
        $message = 'You have been unsubscribed. You will no longer receive notifications.';
        $messageType = 'success';
    } else {
        $message = 'Invalid token or already unsubscribed.';
        $messageType = 'error';
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $csrfToken = (string)($_POST['csrf_token'] ?? '');
    $postAction = (string)($_POST['action'] ?? '');

    if (csrf_valid($csrfToken) && $postAction === 'subscribe') {
        $email = (string)($_POST['email'] ?? '');
        $result = subscribe_email($email);
        if ($result['ok']) {
            $message = (string)($result['message'] ?? 'Subscribed successfully! You will receive email notifications.');
            $messageType = 'success';
        } else {
            $message = (string)($result['error'] ?? 'Could not subscribe.');
            $messageType = 'error';
        }
    }

    if (csrf_valid($csrfToken) && $postAction === 'unsubscribe_email') {
        $email = (string)($_POST['email'] ?? '');
        if (send_unsubscribe_email($email)) {
            $message = 'A confirmation email has been sent. Please check your inbox and click the link to unsubscribe.';
            $messageType = 'success';
        } else {
            $message = 'Email not found or could not send confirmation.';
            $messageType = 'error';
        }
        $action = 'unsubscribe';
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Subscribe to status notifications for <?= e($networkOrg) ?>. Get email alerts for incidents, maintenance, and outages.">
  <meta name="robots" content="index, follow">
  <title><?= e(APP_NAME) ?> - Subscribe</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header class="topbar">
    <div class="topbar-wrap">
      <a class="brand" href="/">
        <span class="brand-as"><?= e($networkAsn !== '' ? $networkAsn : 'AS201131') ?></span>
        <span class="brand-name"><?= e($networkOrg !== '' ? $networkOrg : 'Liga Hosting Ltd') ?></span>
      </a>
      <nav class="topbar-nav">
        <a class="nav-link" href="/">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15.41 7.41 14 6l-6 6 6 6 1.41-1.41L10.83 12z"/></svg>
          Back to Status
        </a>
      </nav>
    </div>
  </header>

  <main class="wrap">
    <section class="login-shell">
      <article class="panel login-panel">
        <div class="panel-head">
          <div>
            <h2>Email notifications</h2>
            <p>Stay informed about operational announcements, maintenance windows, and node outages.</p>
          </div>
        </div>

        <?php if ($message !== ''): ?>
          <div class="sub-alert sub-<?= e($messageType) ?>">
            <?= e($message) ?>
          </div>
        <?php endif; ?>

        <?php if ($action !== 'unsubscribe' || $messageType !== 'success'): ?>
          <div class="sub-page-tabs">
            <button class="sub-tab is-active" type="button" data-tab="subscribe">Subscribe</button>
            <button class="sub-tab" type="button" data-tab="unsubscribe">Unsubscribe</button>
          </div>

          <div class="sub-panel-section is-visible" id="tab-subscribe">
            <form method="post" class="form-grid">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="subscribe">

              <label>
                <span>Email address</span>
                <input type="email" name="email" placeholder="you@example.com" required maxlength="255">
              </label>

              <div>
                <button class="btn-primary" type="submit" style="width:100%">Subscribe</button>
              </div>

              <p class="field-hint">You will receive email alerts when new announcements are posted or when a node goes down.</p>
            </form>
          </div>

          <div class="sub-panel-section" id="tab-unsubscribe">
            <form method="post" class="form-grid">
              <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
              <input type="hidden" name="action" value="unsubscribe_email">

              <label>
                <span>Email address</span>
                <input type="email" name="email" placeholder="you@example.com" required maxlength="255">
              </label>

              <div>
                <button class="btn-danger" type="submit" style="width:100%">Unsubscribe</button>
              </div>

              <p class="field-hint">We'll send a confirmation email to verify it's you. Click the link in the email to complete the unsubscribe.</p>
            </form>
          </div>
        <?php endif; ?>
      </article>
    </section>
  </main>

  <script>
    document.querySelectorAll('.sub-tab').forEach(function(btn) {
      btn.addEventListener('click', function() {
        document.querySelectorAll('.sub-tab').forEach(function(t) { t.classList.remove('is-active'); });
        document.querySelectorAll('.sub-panel-section').forEach(function(s) { s.classList.remove('is-visible'); });
        btn.classList.add('is-active');
        var target = document.getElementById('tab-' + btn.getAttribute('data-tab'));
        if (target) target.classList.add('is-visible');
      });
    });
  </script>

  <footer class="site-footer">
    <div class="topbar-wrap footer-wrap">
      <div class="footer-left">
        <span class="footer-brand"><?= e($networkAsn) ?></span>
        <span class="footer-org"><?= e($networkOrg) ?></span>
      </div>
      <div class="footer-right">
        <span>&copy; <?= e(date('Y')) ?> <?= e($networkOrg) ?></span>
      </div>
    </div>
  </footer>
</body>
</html>
