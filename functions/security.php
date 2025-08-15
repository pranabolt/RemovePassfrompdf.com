<?php
/* ===========================================================================
   Remove Password from PDF — Security Functions
*/

function send_common_headers(): void {
  header('X-Content-Type-Options: nosniff');
  header('X-Frame-Options: DENY');
  header('Referrer-Policy: strict-origin-when-cross-origin');
  // Strengthened CSP with frame-ancestors and object-src none
  header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'");
  // Cross-origin isolation / resource policy (best-effort; may be ignored on shared hosts)
  header('Cross-Origin-Resource-Policy: same-origin');
  header('Cross-Origin-Opener-Policy: same-origin');
  header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
}

function csrf_token(): string {
  if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
  }
  return (string)$_SESSION['csrf'];
}

// Best-effort same-origin check using Origin or Referer headers
function is_same_origin_request(): bool {
  $host = $_SERVER['HTTP_HOST'] ?? '';
  if ($host === '') return false;
  $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
  if ($origin) {
    $p = @parse_url($origin);
    if (is_array($p) && ($p['host'] ?? '') === $host) return true;
  }
  $ref = $_SERVER['HTTP_REFERER'] ?? '';
  if ($ref) {
    $p = @parse_url($ref);
    if (is_array($p) && ($p['host'] ?? '') === $host) return true;
  }
  return false;
}

function rate_limit_check(string $bucket, int $limit, int $windowSec): bool {
  $dir = STORAGE_DIR . '/rate';
  @mkdir($dir, 0775, true);
  $ip  = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
  $key = preg_replace('/[^A-Za-z0-9_\-\.]/', '_', $bucket . '_' . $ip);
  $file = $dir . '/' . $key . '.json';
  $now = time();
  $data = ['start' => $now, 'count' => 0];
  $fp = @fopen($file, 'c+');
  if (!$fp) return true; // fail-open to avoid blocking legit users
  @flock($fp, LOCK_EX);
  $raw = stream_get_contents($fp);
  if ($raw) {
    $tmp = json_decode($raw, true);
    if (is_array($tmp) && isset($tmp['start'], $tmp['count'])) $data = $tmp;
  }
  if ($now - (int)$data['start'] > $windowSec) {
    $data = ['start' => $now, 'count' => 0];
  }
  $data['count'] = (int)$data['count'] + 1;
  $ok = $data['count'] <= $limit;
  ftruncate($fp, 0); rewind($fp); fwrite($fp, json_encode($data)); fflush($fp); @flock($fp, LOCK_UN); fclose($fp);
  return $ok;
}