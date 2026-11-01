<?php
declare(strict_types=1);

/* =====================================================================
   FILMBIN — single-file encrypted image bin
   PHP 8.1+ · SQLite (PDO) blobs · AES-256-GCM at rest
   Features: password locks, custom expiry, delete links, paste upload
   ===================================================================== */

// ----------------------------- CONFIG ---------------------------------
const CONFIG = [
    'db'        => __DIR__ . '/filmbin.sqlite',   // created automatically
    'max_bytes' => 15 * 1024 * 1024,              // 15 MiB per image
    'allowed'   => ['image/jpeg','image/png','image/gif','image/webp','image/avif'],
    'rate'      => ['window' => 60, 'max' => 6],  // uploads per IP per window
];

// ----------------------------- HELPERS --------------------------------
function db(): PDO {
    static $pdo = null;
    if ($pdo === null) {
        $pdo = new PDO('sqlite:' . CONFIG['db']);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec('PRAGMA journal_mode = WAL;');
        $pdo->exec("CREATE TABLE IF NOT EXISTS images(
            id TEXT PRIMARY KEY, mime TEXT NOT NULL, filename TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL, width INTEGER NOT NULL DEFAULT 0, height INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL, expires_at INTEGER, pw_hash TEXT,
            delete_token TEXT NOT NULL, views INTEGER NOT NULL DEFAULT 0, blob BLOB NOT NULL)");
        $pdo->exec("CREATE TABLE IF NOT EXISTS throttle(ip TEXT, ts INTEGER)");
        $pdo->exec("DELETE FROM images WHERE expires_at IS NOT NULL AND expires_at <= " . time()); // lazy purge
    }
    return $pdo;
}

function e(string $s): string { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function b64u(string $b): string { return rtrim(strtr(base64_encode($b), '+/', '-_'), '='); }
function b64u_dec(string $s): string|false { return base64_decode(strtr($s, '-_', '+/'), true); }

function encrypt_blob(string $plain, string $key): string {
    $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) throw new RuntimeException('encrypt failed');
    return $iv . $tag . $ct;               // 12B IV + 16B tag + ciphertext
}
function decrypt_blob(string $packed, string $key): ?string {
    if (strlen($packed) < 29) return null;
    $pt = openssl_decrypt(substr($packed, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA,
                          substr($packed, 0, 12), substr($packed, 12, 16), '');
    return $pt === false ? null : $pt;
}
function parse_image_token(string $tok): ?array {           // id.key
    $p = strrpos($tok, '.'); if ($p === false) return null;
    $key = b64u_dec(substr($tok, $p + 1));
    if ($key === false || strlen($key) !== 32) return null;
    return [substr($tok, 0, $p), $key];
}
function parse_del_token(string $tok): ?array {             // id.deletetoken
    $p = strrpos($tok, '.'); if ($p === false) return null;
    return [substr($tok, 0, $p), substr($tok, $p + 1)];
}
function fetch_meta(string $id): ?array {
    $st = db()->prepare('SELECT id,mime,filename,size,width,height,created_at,expires_at,pw_hash,delete_token,views
                         FROM images WHERE id = ?');
    $st->execute([$id]); $r = $st->fetch(PDO::FETCH_ASSOC);
    return $r ?: null;
}
function fetch_blob(string $id): ?string {
    $st = db()->prepare('SELECT blob FROM images WHERE id = ?');
    $st->execute([$id]); $r = $st->fetchColumn();
    return $r === false ? null : (string)$r;
}
function expired(array $m): bool { return $m['expires_at'] !== null && (int)$m['expires_at'] <= time(); }

function base_url(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    return ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost')
         . strtok($_SERVER['SCRIPT_NAME'] ?? '/', '?');
}
function fmt_bytes(int $n): string {
    return $n >= 1048576 ? round($n/1048576,1).' MB' : ($n >= 1024 ? round($n/1024,1).' KB' : $n.' B');
}
function ago(int $ts): string {
    $d = time() - $ts;
    if ($d < 60) return 'just now';
    if ($d < 3600) return intdiv($d,60).'m ago';
    if ($d < 86400) return intdiv($d,3600).'h ago';
    return intdiv($d,86400).'d ago';
}
function fmt_dur(int $s): string {
    if ($s <= 0) return 'any moment';
    $d = intdiv($s,86400); $h = intdiv($s%86400,3600); $m = intdiv($s%3600,60); $sec = $s%60;
    if ($d) return "{$d}d {$h}h {$m}m";
    if ($h) return "{$h}h {$m}m";
    if ($m) return "{$m}m {$sec}s";
    return "{$sec}s";
}
function stats(): array {
    $st = db()->query('SELECT COUNT(*) c, COALESCE(SUM(size),0) s FROM images');
    return $st->fetch(PDO::FETCH_ASSOC);
}
function throttle_ok(PDO $pdo, string $ip): bool {
    $pdo->prepare('DELETE FROM throttle WHERE ts < ?')->execute([time() - CONFIG['rate']['window']]);
    $st = $pdo->prepare('SELECT COUNT(*) FROM throttle WHERE ip = ?'); $st->execute([$ip]);
    return (int)$st->fetchColumn() < CONFIG['rate']['max'];
}
function parse_expire(array $p): ?int {
    $v = (string)($p['expire'] ?? 'never');
    $presets = ['3600'=>3600,'43200'=>43200,'86400'=>86400,'604800'=>604800,'2592000'=>2592000];
    if ($v === 'never') return null;
    if ($v !== 'custom') return $presets[$v] ?? null;
    $n = max(0,(int)($p['custom_n'] ?? 0));
    $mult = match((string)($p['custom_unit'] ?? 'hours')) { 'minutes'=>60, 'days'=>86400, default=>3600 };
    return min(max($n * $mult, 300), 366 * 86400);          // clamp: 5 min … 1 year
}

// ----------------------------- UPLOAD ---------------------------------
function handle_upload(): array {
    $pdo = db(); $ip = $_SERVER['REMOTE_ADDR'] ?? '?';
    if (!throttle_ok($pdo, $ip)) return ['ok'=>false,'error'=>'Slow down — too many uploads in a short burst.'];

    $f = $_FILES['frame'] ?? null;
    if (!$f || $f['error'] === UPLOAD_ERR_INI_SIZE || $f['error'] === UPLOAD_ERR_FORM_SIZE)
        return ['ok'=>false,'error'=>'Upload too heavy — check the size limit.'];
    if (!$f || $f['error'] !== UPLOAD_ERR_OK)
        return ['ok'=>false,'error'=>'Upload failed (transport error '.$f['error'].').'];
    if ($f['size'] > CONFIG['max_bytes'])
        return ['ok'=>false,'error'=>'Too heavy. Limit is '.fmt_bytes(CONFIG['max_bytes']).'.'];

    $info = @getimagesize($f['tmp_name']);
    if ($info === false) return ['ok'=>false,'error'=>'That does not look like an image.'];
    $mime = strtolower((string)($info['mime'] ?? ''));
    if (!in_array($mime, CONFIG['allowed'], true))
        return ['ok'=>false,'error'=>'Format not allowed. JPEG, PNG, GIF, WEBP or AVIF.'];

    $plain = file_get_contents($f['tmp_name']);
    if ($plain === false) return ['ok'=>false,'error'=>'Could not read the uploaded file.'];
    $fmime = (string)((new finfo(FILEINFO_MIME_TYPE))->buffer($plain) ?: '');
    if (!in_array($fmime, CONFIG['allowed'], true))
        return ['ok'=>false,'error'=>'File content does not match an allowed image type.'];

    $key = random_bytes(32);
    $packed = encrypt_blob($plain, $key);
    $delTok = b64u(random_bytes(24));
    $pw = trim((string)($_POST['password'] ?? ''));
    $secs = parse_expire($_POST);
    $now = time(); $expiresAt = $secs !== null ? $now + $secs : null;

    for ($i = 0; $i < 3; $i++) {
        $id = b64u(random_bytes(9));
        try {
            $st = $pdo->prepare('INSERT INTO images
                (id,mime,filename,size,width,height,created_at,expires_at,pw_hash,delete_token,blob)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)');
            $st->bindValue(1,$id); $st->bindValue(2,$mime);
            $st->bindValue(3,basename((string)$f['name'])); $st->bindValue(4,strlen($plain));
            $st->bindValue(5,$info[0]); $st->bindValue(6,$info[1]);
            $st->bindValue(7,$now); $st->bindValue(8,$expiresAt);
            $st->bindValue(9,$pw !== '' ? password_hash($pw, PASSWORD_DEFAULT) : null);
            $st->bindValue(10,$delTok);
            $st->bindValue(11,$packed,PDO::PARAM_LOB);
            $st->execute(); break;
        } catch (PDOException $ex) { if ($i === 2) throw $ex; }
    }
    $pdo->prepare('INSERT INTO throttle(ip,ts) VALUES (?,?)')->execute([$ip,$now]);

    $token = $id.'.'.b64u($key); $base = base_url();
    return ['ok'=>true,'id'=>$id,
        'view'=>$base.'?v='.$token, 'direct'=>$base.'?img='.$token, 'download'=>$base.'?dl='.$token,
        'del'=>$base.'?del='.$id.'.'.$delTok,
        'expires_at'=>$expiresAt, 'size'=>strlen($plain), 'mime'=>$mime, 'w'=>$info[0], 'h'=>$info[1],
        'locked'=>$pw !== ''];
}

// ----------------------------- SERVE ----------------------------------
function serve_image(string $token, bool $download = false): never {
    $t = parse_image_token($token);
    if ($t === null) fail_http(400, 'Malformed link.');
    [$id, $key] = $t;
    $m = fetch_meta($id);
    if (!$m) fail_http(404, 'Frame not found.');
    if (expired($m)) { db()->prepare('DELETE FROM images WHERE id=?')->execute([$id]);
                       fail_http(410, 'This frame expired and was burned.'); }
    if ($m['pw_hash'] !== null) {
        session_start(['cookie_httponly'=>true,'cookie_samesite'=>'Lax']);
        if (empty($_SESSION['unlocked'][$id])) fail_http(403, 'Password required — open the view link.');
    }
    $blob = fetch_blob($id);
    $plain = $blob !== null ? decrypt_blob($blob, $key) : null;
    if ($plain === null) fail_http(400, 'Decryption failed — link is corrupt.');

    while (ob_get_level()) ob_end_clean();
    $fname = $m['filename'] !== '' ? $m['filename'] : $id;
    header('Content-Type: ' . $m['mime']);
    header('Content-Length: ' . strlen($plain));
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: ' . ($m['pw_hash'] !== null ? 'no-store' : 'private, max-age=600'));
    header('Content-Disposition: ' . ($download ? 'attachment' : 'inline') . '; filename="' . preg_replace('/[^\w.\- ]/','_',$fname) . '"');
    echo $plain; exit;
}

// ----------------------------- ROUTER ---------------------------------
$q = $_GET;
$str = fn($k) => is_string($q[$k] ?? null) ? $q[$k] : '';

if ($str('img') !== '') { serve_image($str('img')); }
if ($str('dl')  !== '') { serve_image($str('dl'), true); }
if ($str('v')   !== '') { render_view_page($str('v')); exit; }
if ($str('del') !== '') { render_delete_page($str('del')); exit; }

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'upload') {
    if (empty($_FILES) && empty($_POST)) {
        render_home(null, 'Upload too heavy for this server (check upload_max_filesize / post_max_size).'); exit;
    }
    $res = handle_upload();
    if (($res['ok'] ?? false) && isset($_POST['json'])) {
        header('Content-Type: application/json'); echo json_encode($res); exit;
    }
    if ($res['ok'] ?? false) { render_result_page($res); exit; }
    render_home(null, $res['error'] ?? 'Upload failed.'); exit;
}
render_home();

// =====================================================================
// TEMPLATES
// =====================================================================

function page_head(string $title): void { ?>
<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= e($title) ?> · FILMBIN</title>
<link rel="icon" href='data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="%230e1412"/><circle cx="16" cy="16" r="9" fill="none" stroke="%23ff6b3d" stroke-width="2.5"/><circle cx="16" cy="16" r="3" fill="%23ffb03a"/></svg>'>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,300..800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#0e1412; --panel:#141d19; --panel2:#0b100e; --line:#26332c; --line2:#1b2620;
  --ink:#f1ece1; --mut:#93a396; --dim:#5c6c61;
  --ember:#ff6b3d; --amber:#ffb03a; --mint:#7ee0b0; --red:#ff5d5d;
  --disp:'Bricolage Grotesque',system-ui,sans-serif;
  --body:'IBM Plex Sans',system-ui,sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,monospace;
}
*{box-sizing:border-box} html{scroll-behavior:smooth}
body{margin:0;color:var(--ink);font:15px/1.55 var(--body);background:
  radial-gradient(900px 480px at 88% -10%, rgba(255,107,61,.13), transparent 62%),
  radial-gradient(760px 520px at -8% 112%, rgba(126,224,176,.07), transparent 60%),
  radial-gradient(600px 400px at 55% 0%, rgba(255,176,58,.06), transparent 60%),
  var(--bg);min-height:100vh}
::selection{background:var(--ember);color:#160a04}
a{color:var(--amber)}
.grain{position:fixed;inset:-60%;width:220%;height:220%;pointer-events:none;z-index:70;opacity:.055;
  background-image:url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300"><filter id="n"><feTurbulence type="fractalNoise" baseFrequency="0.85" numOctaves="2"/></filter><rect width="300" height="300" filter="url(%23n)"/></svg>');
  animation:grain 7s steps(8) infinite}
@keyframes grain{0%{transform:translate(0,0)}25%{transform:translate(-2%,3%)}50%{transform:translate(3%,-2%)}75%{transform:translate(-3%,-3%)}100%{transform:translate(2%,2%)}}

.wrap{max-width:1120px;margin:0 auto;padding:0 22px}
.mono{font-family:var(--mono)}
.top{display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:20px 0 16px}
.logo{font:800 30px/1 var(--disp);letter-spacing:-.02em;color:var(--ink);text-decoration:none;display:inline-flex;align-items:baseline;gap:2px}
.logo b{color:var(--ember);font-weight:800}
.logo .reel{display:inline-block;width:22px;height:22px;margin-right:10px;align-self:center;transition:transform .6s cubic-bezier(.2,.8,.2,1)}
.logo:hover .reel{transform:rotate(120deg)}
.tag{color:var(--dim);font:12px var(--mono);text-transform:uppercase;letter-spacing:.14em;margin-left:2px}
.top .spacer{flex:1}
.stat{font:12px var(--mono);color:var(--mut);border:1px solid var(--line);padding:7px 12px;border-radius:6px;background:var(--panel2)}
.stat b{color:var(--amber);font-weight:600}
.led{display:inline-flex;align-items:center;gap:8px;font:11px var(--mono);letter-spacing:.16em;color:var(--ember);text-transform:uppercase}
.led i{width:8px;height:8px;border-radius:50%;background:var(--ember);box-shadow:0 0 12px var(--ember);animation:pulse 1.8s ease-in-out infinite}
@keyframes pulse{50%{opacity:.25;box-shadow:0 0 2px var(--ember)}}

.ticker{overflow:hidden;border-block:1px solid var(--line);background:var(--panel2)}
.ticker-track{display:flex;width:max-content;animation:tick 46s linear infinite}
.ticker:hover .ticker-track{animation-play-state:paused}
.ticker-track span{white-space:nowrap;font:11px/1 var(--mono);letter-spacing:.18em;color:var(--dim);text-transform:uppercase;padding:10px 0}
.ticker-track em{font-style:normal;color:var(--amber);padding:0 1.4rem}
@keyframes tick{to{transform:translateX(-50%)}}

.lab{display:grid;grid-template-columns:minmax(0,7fr) minmax(0,5fr);gap:22px;padding:34px 0 10px}
@media(max-width:920px){.lab{grid-template-columns:1fr}}

/* ---------- dropzone ---------- */
.drop{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:12px;min-height:420px;
  display:flex;align-items:center;justify-content:center;cursor:pointer;overflow:hidden;
  transition:border-color .25s, box-shadow .25s, transform .2s}
.drop::before,.drop::after{content:"";position:absolute;top:12px;bottom:12px;width:16px;border-radius:4px;
  background-image:radial-gradient(5px 7px at 50% 50%, #060a08 97%, transparent);background-size:16px 26px;background-position:center}
.drop::before{left:12px}.drop::after{right:12px}
.drop:hover{border-color:#3d4f44}
.drop.drag{border-color:var(--ember);box-shadow:0 0 0 3px rgba(255,107,61,.18), 0 22px 60px -20px rgba(255,107,61,.35);transform:scale(1.008)}
.drop-inner{text-align:center;padding:44px 60px;max-width:520px}
.aperture{width:84px;height:84px;margin:0 auto 18px;display:block;color:var(--amber);transition:transform .8s cubic-bezier(.2,.8,.2,1)}
.drop:hover .aperture{transform:rotate(45deg);color:var(--ember)}
.drop h1{font:700 clamp(28px,4.4vw,44px)/1.05 var(--disp);letter-spacing:-.02em;margin:0 0 10px}
.drop h1 span{color:var(--ember)}
.drop p{color:var(--mut);margin:0 0 22px}
.kbd{font:12px var(--mono);color:var(--amber);border:1px solid var(--line);background:var(--panel2);border-radius:5px;padding:2px 8px}
.btnrow{display:flex;gap:10px;justify-content:center;flex-wrap:wrap}
.formats{margin-top:26px;font:11px var(--mono);letter-spacing:.14em;color:var(--dim);text-transform:uppercase}
.loaded{display:none;text-align:center;padding:44px 60px;width:100%}
.drop.has-file{cursor:default}
.drop.has-file .drop-inner{display:none}
.drop.has-file .loaded{display:block}
.loaded img{max-height:230px;max-width:100%;border-radius:6px;border:1px solid var(--line);box-shadow:0 18px 50px -18px rgba(0,0,0,.8)}
.loaded .fn{margin-top:14px;font:13px var(--mono);color:var(--ink);word-break:break-all}
.loaded .fs{color:var(--dim);font:12px var(--mono);margin-top:2px}
.clearbtn{margin-top:14px;background:none;border:1px solid var(--line);color:var(--mut);font:12px var(--mono);letter-spacing:.1em;padding:7px 14px;border-radius:6px;cursor:pointer;transition:.2s}
.clearbtn:hover{border-color:var(--red);color:var(--red)}

/* uploading overlay */
.dev{position:absolute;inset:0;background:rgba(9,14,12,.92);display:none;flex-direction:column;gap:14px;align-items:center;justify-content:center;z-index:5}
.drop.uploading .dev{display:flex}
.dev .lbl{font:12px var(--mono);letter-spacing:.22em;color:var(--mint);text-transform:uppercase}
.dev .pct{font:800 54px/1 var(--disp);color:var(--ink)}
.dev .bar{width:min(320px,70%);height:6px;background:var(--line2);border-radius:3px;overflow:hidden}
.dev .bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,var(--ember),var(--amber));transition:width .15s}
.dev::after{content:"";position:absolute;left:0;right:0;height:2px;top:0;
  background:linear-gradient(90deg,transparent,var(--mint),transparent);opacity:.7;animation:scan 1.5s linear infinite}
@keyframes scan{to{top:100%}}

/* ---------- settings ---------- */
.settings{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:24px;align-self:start;position:relative}
.settings::before{content:"LAB SETTINGS";position:absolute;top:-9px;left:18px;background:var(--bg);padding:0 8px;
  font:11px var(--mono);letter-spacing:.24em;color:var(--amber)}
.field{margin:20px 0}
.field label{display:block;font:11px var(--mono);letter-spacing:.16em;text-transform:uppercase;color:var(--mut);margin-bottom:8px}
.field label small{color:var(--dim);letter-spacing:.06em;text-transform:none}
input[type=text],input[type=password],input[type=number],select{
  width:100%;background:var(--panel2);border:1px solid var(--line);color:var(--ink);
  font:14px var(--mono);padding:11px 12px;border-radius:7px;outline:none;transition:border-color .2s, box-shadow .2s}
input:focus,select:focus{border-color:var(--amber);box-shadow:0 0 0 3px rgba(255,176,58,.14)}
.pwwrap{position:relative}
.pwwrap button{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--dim);font:11px var(--mono);letter-spacing:.1em;cursor:pointer;padding:6px}
.pwwrap button:hover{color:var(--amber)}
.customrow{display:flex;gap:8px;margin-top:8px}
.customrow input{flex:1}
.customrow select{flex:1.3}
.btn{display:inline-block;border:none;cursor:pointer;font:600 14px var(--mono);letter-spacing:.12em;text-transform:uppercase;
  padding:15px 22px;border-radius:8px;text-decoration:none;transition:transform .18s, box-shadow .18s, background .18s}
.btn-ember{width:100%;background:linear-gradient(120deg,var(--ember),var(--amber));color:#1c0d04;
  box-shadow:0 10px 30px -12px rgba(255,107,61,.6)}
.btn-ember:hover{transform:translateY(-2px);box-shadow:0 16px 36px -12px rgba(255,107,61,.75)}
.btn-ember:active{transform:translateY(0)}
.btn-ghost{background:none;border:1px solid var(--line);color:var(--mut);padding:11px 18px}
.btn-ghost:hover{border-color:var(--amber);color:var(--amber);transform:translateY(-1px)}
.note{margin:18px 0 0;font-size:12.5px;color:var(--dim);border-left:2px solid var(--line);padding-left:12px}
.note b{color:var(--mint);font-weight:500}

/* ---------- result ---------- */
.result{margin:26px 0 8px;background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--mint);border-radius:12px;padding:24px;display:none}
.result.show{display:block;animation:rise .45s cubic-bezier(.2,.8,.2,1)}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.result h2{font:700 22px var(--disp);margin:0 0 4px;color:var(--mint)}
.result .sub{color:var(--dim);font:12px var(--mono);letter-spacing:.08em;margin-bottom:18px}
.linkrow{display:flex;gap:8px;align-items:center;margin:9px 0}
.linkrow .lbl{flex:0 0 108px;font:11px var(--mono);letter-spacing:.14em;color:var(--mut);text-transform:uppercase}
.linkrow input{flex:1;font-size:12.5px;color:var(--amber)}
.linkrow.danger input{color:var(--red)}
.copy{flex:0 0 auto;background:var(--panel2);border:1px solid var(--line);color:var(--mut);font:11px var(--mono);letter-spacing:.12em;padding:11px 14px;border-radius:7px;cursor:pointer;transition:.18s;min-width:92px}
.copy:hover{border-color:var(--amber);color:var(--amber);transform:translateY(-1px)}
.copy.ok{border-color:var(--mint);color:var(--mint)}
.warnchip{display:inline-block;margin-top:10px;font:11px var(--mono);letter-spacing:.1em;color:var(--red);border:1px dashed rgba(255,93,93,.4);padding:6px 10px;border-radius:6px}

/* ---------- error banner / toast ---------- */
.errbar{margin:26px 0 0;background:rgba(255,93,93,.08);border:1px solid rgba(255,93,93,.4);color:#ffb3b3;font:13px var(--mono);padding:13px 16px;border-radius:8px}
#toast{position:fixed;left:50%;bottom:26px;transform:translate(-50%,20px);opacity:0;z-index:120;pointer-events:none;
  background:#1a2420;border:1px solid var(--line);color:var(--ink);font:13px var(--mono);padding:12px 18px;border-radius:8px;
  box-shadow:0 14px 40px rgba(0,0,0,.5);transition:.3s}
#toast.on{opacity:1;transform:translate(-50%,0)}

/* ---------- footer film strip ---------- */
.how{margin:56px 0 26px}
.how h3{font:11px var(--mono);letter-spacing:.24em;color:var(--dim);text-transform:uppercase;margin:0 0 16px}
.strip{display:flex;gap:14px;overflow-x:auto;padding:16px 18px;background:var(--panel2);border:1px solid var(--line);border-radius:12px;
  background-image:radial-gradient(5px 6px at 12px 50%, #060a08 97%, transparent),radial-gradient(5px 6px at calc(100% - 12px) 50%, #060a08 97%, transparent);
  background-size:24px 100%,24px 100%;background-repeat:repeat-x}
.frame{flex:1 0 200px;border:1px solid var(--line);border-radius:8px;padding:16px;background:var(--panel);transition:.25s}
.frame:hover{border-color:var(--amber);transform:translateY(-3px)}
.frame .num{font:800 30px/1 var(--disp);color:var(--ember)}
.frame h4{font:600 13px var(--mono);letter-spacing:.14em;margin:10px 0 6px;color:var(--amber);text-transform:uppercase}
.frame p{margin:0;font-size:12.5px;color:var(--mut)}
.foot{padding:8px 0 40px;color:var(--dim);font:12px var(--mono);display:flex;gap:14px;flex-wrap:wrap;justify-content:space-between}

/* ---------- view / delete / error pages ---------- */
.center{max-width:860px;margin:0 auto;padding:44px 22px}
.photo{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;box-shadow:0 30px 80px -30px rgba(0,0,0,.8)}
.photo img{display:block;max-width:100%;max-height:70vh;margin:0 auto;border-radius:4px}
.metarow{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.chip{font:11px var(--mono);letter-spacing:.1em;color:var(--mut);border:1px solid var(--line);border-radius:5px;padding:6px 10px;background:var(--panel2)}
.chip.hot{color:var(--ember);border-color:rgba(255,107,61,.4)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:34px;text-align:center;max-width:520px;margin:8vh auto 0}
.card h1{font:700 clamp(24px,4vw,34px)/1.15 var(--disp);margin:12px 0 10px}
.card p{color:var(--mut)}
.bigcode{font:800 clamp(60px,12vw,110px)/1 var(--disp);color:var(--ember);letter-spacing:-.03em}
.shake{animation:shake .4s}
@keyframes shake{20%{transform:translateX(-7px)}40%{transform:translateX(6px)}60%{transform:translateX(-4px)}80%{transform:translateX(3px)}}
</style>
</head><body>
<div class="grain" aria-hidden="true"></div>
<?php }

function page_top(): void { $s = stats(); ?>
<div class="wrap">
  <header class="top">
    <a class="logo" href="?">
      <svg class="reel" viewBox="0 0 24 24" fill="none" stroke="#ff6b3d" stroke-width="2"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2.5" fill="#ffb03a" stroke="none"/><circle cx="12" cy="5.5" r="1.4" fill="#ffb03a" stroke="none"/><circle cx="12" cy="18.5" r="1.4" fill="#ffb03a" stroke="none"/><circle cx="5.5" cy="12" r="1.4" fill="#ffb03a" stroke="none"/><circle cx="18.5" cy="12" r="1.4" fill="#ffb03a" stroke="none"/></svg>
      FILM<b>BIN</b>
    </a>
    <span class="tag">encrypted image bin</span>
    <span class="spacer"></span>
    <span class="led"><i></i>safelight on</span>
    <span class="stat"><b id="frmCount"><?= (int)$s['c'] ?></b> frames · <b id="byteCount"><?= e(fmt_bytes((int)$s['s'])) ?></b> stored</span>
  </header>
</div>
<div class="ticker"><div class="ticker-track">
  <?php for ($i = 0; $i < 2; $i++) { ?><span>AES-256-GCM ENCRYPTED AT REST <em>✦</em> EVERY LINK CARRIES ITS OWN KEY <em>✦</em> SET A TIMER — FRAMES BURN ON SCHEDULE <em>✦</em> PASSWORD LOCKS HASHED, NEVER STORED PLAIN <em>✦</em> NO ACCOUNTS · NO LOGS <em>✦</em> SQLITE BLOB STORAGE — ONE FILE DOES IT ALL <em>✦</em></span><?php } ?>
</div></div>
<?php }

function page_foot(): void { ?>
<div class="wrap">
  <div class="how"><h3>// how the darkroom works</h3>
    <div class="strip">
      <div class="frame"><div class="num">01</div><h4>Drop</h4><p>Drag, browse, or paste an image straight into the frame.</p></div>
      <div class="frame"><div class="num">02</div><h4>Encrypt</h4><p>AES-256-GCM with a unique key per frame, stored as an opaque blob.</p></div>
      <div class="frame"><div class="num">03</div><h4>Share</h4><p>The link <i>is</i> the key. Without it the database is noise.</p></div>
      <div class="frame"><div class="num">04</div><h4>Burn</h4><p>Expiry timers and delete links. Purging runs on every visit.</p></div>
    </div>
  </div>
  <footer class="foot">
    <span>FILMBIN v1 · single file · sqlite blobs</span>
    <span>limits &amp; paths: edit CONFIG at the top of this file</span>
  </footer>
</div>
<div id="toast" role="status"></div>
</body></html>
<?php }

// ------------------------- HOME (upload) ------------------------------
function render_home(?array $flash = null, ?string $error = null): void {
    page_head('Drop a frame'); page_top();
    $maxMb = fmt_bytes(CONFIG['max_bytes']);
?>
<div class="wrap">
  <?php if ($error !== null) { ?><div class="errbar">⚠ <?= e($error) ?></div><?php } ?>
  <form id="upform" method="post" enctype="multipart/form-data" action="?">
    <input type="hidden" name="action" value="upload">
    <div class="lab">
      <div class="drop" id="drop" tabindex="0" role="button" aria-label="Upload an image">
        <div class="drop-inner">
          <svg class="aperture" viewBox="0 0 100 100" fill="none" stroke="currentColor" stroke-width="3">
            <circle cx="50" cy="50" r="44"/>
            <path d="M50 6 L66 46 M93 32 L52 34 M82 84 L58 48 M50 94 L34 54 M7 68 L48 66 M18 16 L42 52" stroke-width="2.4"/>
          </svg>
          <h1>DROP FRAME <span>HERE</span></h1>
          <p>drag &amp; drop · <span class="kbd">click</span> to browse · <span class="kbd">ctrl+v</span> to paste</p>
          <div class="btnrow"><span class="btn btn-ghost">BROWSE FILES</span></div>
          <div class="formats">jpeg · png · gif · webp · avif — up to <?= e($maxMb) ?></div>
        </div>
        <div class="loaded">
          <img id="thumb" alt="preview">
          <div class="fn" id="fn"></div><div class="fs" id="fs"></div>
          <button type="button" class="clearbtn" id="clear">✕ CLEAR FRAME</button>
        </div>
        <div class="dev">
          <div class="lbl">developing…</div>
          <div class="pct" id="pct">0%</div>
          <div class="bar"><i id="bar"></i></div>
        </div>
        <input type="file" id="file" name="frame" accept="image/jpeg,image/png,image/gif,image/webp,image/avif" hidden>
      </div>

      <aside class="settings">
        <div class="field">
          <label for="pw">Password lock <small>· optional</small></label>
          <div class="pwwrap">
            <input type="password" name="password" id="pw" autocomplete="new-password" placeholder="viewers will need this">
            <button type="button" id="eye">SHOW</button>
          </div>
        </div>
        <div class="field">
          <label for="expire">Self-destruct</label>
          <select name="expire" id="expire">
            <option value="never" selected>Never — keep it</option>
            <option value="3600">In 1 hour</option>
            <option value="43200">In 12 hours</option>
            <option value="86400">In 1 day</option>
            <option value="604800">In 1 week</option>
            <option value="2592000">In 30 days</option>
            <option value="custom">Custom…</option>
          </select>
          <div class="customrow" id="customRow" hidden>
            <input type="number" name="custom_n" id="customN" min="1" placeholder="amount">
            <select name="custom_unit"><option value="minutes">minutes</option><option value="hours" selected>hours</option><option value="days">days</option></select>
          </div>
        </div>
        <button class="btn btn-ember" type="submit">Develop ▸</button>
        <p class="note">Every upload gets its <b>own AES-256 key</b>. The key lives only inside your links — lose the link, lose the frame.</p>
      </aside>
    </div>
  </form>

  <section class="result" id="result">
    <h2>✓ FRAME DEVELOPED</h2>
    <div class="sub" id="rsub"></div>
    <div class="linkrow"><span class="lbl">View link</span><input readonly id="r_view"><button class="copy" data-for="r_view">COPY</button></div>
    <div class="linkrow"><span class="lbl">Direct image</span><input readonly id="r_direct"><button class="copy" data-for="r_direct">COPY</button></div>
    <div class="linkrow"><span class="lbl">Download</span><input readonly id="r_dl"><button class="copy" data-for="r_dl">COPY</button></div>
    <div class="linkrow danger"><span class="lbl">Delete link</span><input readonly id="r_del"><button class="copy" data-for="r_del">COPY</button></div>
    <span class="warnchip">⚠ The delete link burns the frame permanently. Keep it somewhere safe — it cannot be recovered.</span>
  </section>
</div>
<script>
(function(){
  var MAX = <?= (int)CONFIG['max_bytes'] ?>;
  var ALLOWED = <?= json_encode(CONFIG['allowed']) ?>;
  var $ = function(s){ return document.querySelector(s); };
  var dz=$('#drop'), fi=$('#file'), form=$('#upform'), currentFile=null;

  function toast(msg){ var t=$('#toast'); t.textContent=msg; t.classList.add('on');
    clearTimeout(t._h); t._h=setTimeout(function(){t.classList.remove('on');},3800); }

  function setFile(f){
    if(!f) return;
    if(ALLOWED.indexOf(f.type)===-1){ toast('Format not allowed.'); return; }
    if(f.size>MAX){ toast('Too heavy — limit is <?= e(fmt_bytes(CONFIG['max_bytes'])) ?>.'); return; }
    currentFile=f;
    var url=URL.createObjectURL(f);
    $('#thumb').src=url; $('#fn').textContent=f.name||'pasted-image';
    $('#fs').textContent=(f.size/1048576).toFixed(2)+' MB · '+f.type;
    dz.classList.add('has-file');
  }
  function clearFile(){ currentFile=null; dz.classList.remove('has-file'); fi.value=''; }

  dz.addEventListener('click', function(e){ if(!dz.classList.contains('has-file')) fi.click(); });
  dz.addEventListener('keydown', function(e){ if(e.key==='Enter'||e.key===' '){ e.preventDefault(); fi.click(); }});
  fi.addEventListener('change', function(){ setFile(fi.files[0]); });
  $('#clear').addEventListener('click', function(e){ e.stopPropagation(); clearFile(); });

  var dragN=0;
  ['dragenter','dragover'].forEach(function(ev){ dz.addEventListener(ev,function(e){ e.preventDefault(); if(ev==='dragenter')dragN++; dz.classList.add('drag'); }); });
  dz.addEventListener('dragleave', function(){ if(--dragN<=0){dragN=0;dz.classList.remove('drag');} });
  dz.addEventListener('drop', function(e){ e.preventDefault(); dragN=0; dz.classList.remove('drag'); setFile(e.dataTransfer.files[0]); });
  document.addEventListener('paste', function(e){
    var items=e.clipboardData&&e.clipboardData.items; if(!items) return;
    for(var i=0;i<items.length;i++){ if(items[i].type.indexOf('image/')===0){ setFile(items[i].getAsFile()); toast('Frame pasted from clipboard ✓'); break; } }
  });

  $('#eye').addEventListener('click', function(){
    var p=$('#pw'); var show=p.type==='password';
    p.type=show?'text':'password'; this.textContent=show?'HIDE':'SHOW';
  });
  $('#expire').addEventListener('change', function(){
    $('#customRow').hidden = this.value!=='custom';
    if(this.value==='custom') $('#customN').focus();
  });

  form.addEventListener('submit', function(ev){
    ev.preventDefault();
    if(!currentFile){ toast('Load a frame first.'); return; }
    var fd=new FormData(form); fd.append('json','1');
    var xhr=new XMLHttpRequest(); xhr.open('POST', location.pathname);
    dz.classList.add('uploading');
    xhr.upload.onprogress=function(e){ if(e.lengthComputable){ var p=Math.round(e.loaded/e.total*100);
      $('#pct').textContent=p+'%'; $('#bar').style.width=p+'%'; } };
    xhr.onload=function(){
      dz.classList.remove('uploading'); $('#bar').style.width='0';
      try{ var r=JSON.parse(xhr.responseText);
        if(r.ok){ showResult(r); } else { toast(r.error||'Upload failed.'); }
      }catch(e){ toast('Server error.'); }
    };
    xhr.onerror=function(){ dz.classList.remove('uploading'); toast('Network error.'); };
    xhr.send(fd);
  });

  function showResult(r){
    $('#r_view').value=r.view; $('#r_direct').value=r.direct; $('#r_dl').value=r.download; $('#r_del').value=r.del;
    var bits=[r.w+'×'+r.h, (r.size/1048576).toFixed(2)+' MB'];
    bits.push(r.expires_at? 'burns in '+dur(r.expires_at*1000-Date.now()) : 'never expires');
    if(r.locked) bits.push('🔒 password locked');
    $('#rsub').textContent=bits.join('  ·  ');
    var el=$('#result'); el.classList.add('show');
    el.scrollIntoView({behavior:'smooth',block:'center'});
    var c=$('#frmCount'); c.textContent=(parseInt(c.textContent,10)||0)+1;
    clearFile(); form.reset(); $('#customRow').hidden=true;
  }
  function dur(ms){ if(ms<=0)return 'any moment';
    var s=Math.floor(ms/1000),d=Math.floor(s/86400);s%=86400;
    var h=Math.floor(s/3600);s%=3600;var m=Math.floor(s/60);s%=60;
    return (d?d+'d ':'')+(h?h+'h ':'')+(m?m+'m ':'')+s+'s'; }

  document.addEventListener('click', function(e){
    var b=e.target.closest('.copy'); if(!b) return;
    var inp=document.getElementById(b.dataset.for); if(!inp) return;
    var done=function(){ b.classList.add('ok'); b.textContent='COPIED ✓';
      setTimeout(function(){b.classList.remove('ok');b.textContent='COPY';},1600); };
    if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(inp.value).then(done).catch(function(){fallback(inp,done);}); }
    else fallback(inp,done);
    function fallback(inp,done){ inp.select(); try{document.execCommand('copy');done();}catch(e){} }
  });
})();
</script>
<?php page_foot(); }

// ----------------- STANDALONE RESULT (no-JS fallback) -----------------
function render_result_page(array $r): void {
    page_head('Frame developed'); page_top(); ?>
<div class="wrap">
  <section class="result show">
    <h2>✓ FRAME DEVELOPED</h2>
    <div class="sub"><?= e($r['w'].'×'.$r['h'].' · '.fmt_bytes($r['size']).($r['expires_at']?' · burns '.date('Y-m-d H:i', (int)$r['expires_at']):' · never expires').($r['locked']?' · password locked':'')) ?></div>
    <?php foreach (['View link'=>'view','Direct image'=>'direct','Download'=>'download','Delete link'=>'del'] as $lbl=>$k) { ?>
      <div class="linkrow <?= $k==='del'?'danger':'' ?>"><span class="lbl"><?= e($lbl) ?></span>
        <input readonly value="<?= e($r[$k]) ?>" onclick="this.select()"></div>
    <?php } ?>
    <span class="warnchip">⚠ The delete link burns the frame permanently. Bookmark it now.</span>
    <div style="margin-top:18px"><a class="btn btn-ghost" href="?">← DEVELOP ANOTHER</a></div>
  </section>
</div>
<?php page_foot(); }

// --------------------------- VIEW PAGE --------------------------------
function render_view_page(string $token): never {
    $t = parse_image_token($token);
    if ($t === null) fail_http(400, 'Malformed link.');
    [$id, $key] = $t;
    $m = fetch_meta($id);
    if (!$m) fail_http(404, 'Frame not found.');
    if (expired($m)) { db()->prepare('DELETE FROM images WHERE id=?')->execute([$id]);
                       fail_http(410, 'This frame expired and was burned.'); }
    $blob = fetch_blob($id);
    if ($blob === null || decrypt_blob($blob, $key) === null) fail_http(400, 'Decryption failed — link is corrupt.');

    $pwErr = false;
    if ($m['pw_hash'] !== null) {
        session_start(['cookie_httponly'=>true,'cookie_samesite'=>'Lax']);
        if ($_SERVER['REQUEST_METHOD']==='POST' && isset($_POST['pw'])) {
            if (password_verify((string)$_POST['pw'], (string)$m['pw_hash'])) {
                $_SESSION['unlocked'][$id] = true;
                header('Location: ?v='.urlencode($token)); exit;
            }
            $pwErr = true;
        }
        if (empty($_SESSION['unlocked'][$id])) { render_gate($token, $pwErr); exit; }
    }
    db()->prepare('UPDATE images SET views = views + 1 WHERE id = ?')->execute([$id]);

    $fname = $m['filename'] !== '' ? $m['filename'] : 'frame-'.$id;
    page_head($fname); page_top(); ?>
<div class="center">
  <div class="photo">
    <img src="?img=<?= e($token) ?>" alt="<?= e($fname) ?>">
    <div class="metarow">
      <span class="chip mono"><?= e($fname) ?></span>
      <span class="chip"><?= (int)$m['width'] ?>×<?= (int)$m['height'] ?></span>
      <span class="chip"><?= e(fmt_bytes((int)$m['size'])) ?></span>
      <span class="chip">uploaded <?= e(ago((int)$m['created_at'])) ?></span>
      <span class="chip"><?= (int)$m['views'] ?> views</span>
      <?php if ($m['expires_at'] !== null) { ?>
        <span class="chip hot countdown" data-unix="<?= (int)$m['expires_at'] ?>">burns in <?= e(fmt_dur((int)$m['expires_at']-time())) ?></span>
      <?php } else { ?><span class="chip">never expires</span><?php } ?>
      <?php if ($m['pw_hash'] !== null) { ?><span class="chip hot">🔒 locked</span><?php } ?>
    </div>
    <div class="actions">
      <a class="btn btn-ember" style="width:auto" href="?dl=<?= e($token) ?>">Download</a>
      <a class="btn btn-ghost" href="?img=<?= e($token) ?>" target="_blank" rel="noopener">Open raw ↗</a>
      <button class="btn btn-ghost" id="copyLink" type="button">Copy link</button>
      <a class="btn btn-ghost" href="?">← new frame</a>
    </div>
  </div>
</div>
<script>
document.getElementById('copyLink').addEventListener('click', function(){
  var b=this; (navigator.clipboard?navigator.clipboard.writeText(location.href):Promise.reject())
    .then(function(){b.textContent='Copied ✓';}).catch(function(){})
    .finally(function(){setTimeout(function(){b.textContent='Copy link';},1600);});
});
var cd=document.querySelector('.countdown');
if(cd){ var u=parseInt(cd.dataset.unix,10)*1000;
  setInterval(function(){ var s=Math.floor((u-Date.now())/1000);
    if(s<=0){ cd.textContent='expiring now…'; return; }
    var d=Math.floor(s/86400);s%=86400;var h=Math.floor(s/3600);s%=3600;var m=Math.floor(s/60);s%=60;
    cd.textContent='burns in '+(d?d+'d ':'')+(h?h+'h ':'')+(m?m+'m ':'')+s+'s'; },1000); }
</script>
<?php page_foot(); exit; }

function render_gate(string $token, bool $err): never {
    page_head('Locked frame'); page_top(); ?>
<div class="card <?= $err?'shake':'' ?>">
  <svg width="64" height="64" viewBox="0 0 100 100" fill="none" stroke="#ff6b3d" stroke-width="4" style="margin:0 auto;display:block">
    <rect x="22" y="44" width="56" height="42" rx="6"/><path d="M34 44 V30 a16 16 0 0 1 32 0 V44"/><circle cx="50" cy="63" r="5" fill="#ffb03a" stroke="none"/>
  </svg>
  <h1>This frame is locked.</h1>
  <p>Enter the password it was developed with.</p>
  <form method="post" action="?v=<?= e($token) ?>">
    <div class="pwwrap" style="max-width:320px;margin:18px auto 14px">
      <input type="password" name="pw" autofocus autocomplete="current-password" placeholder="password" style="text-align:center">
    </div>
    <?php if ($err) { ?><div style="color:var(--red);font:12px var(--mono);margin-bottom:12px">✕ wrong password</div><?php } ?>
    <button class="btn btn-ember" style="width:auto;padding:13px 34px" type="submit">Unlock</button>
  </form>
  <p style="margin-top:20px"><a href="?" style="font:12px var(--mono);color:var(--dim)">← back to the darkroom</a></p>
</div>
<?php page_foot(); exit; }

// --------------------------- DELETE PAGE ------------------------------
function render_delete_page(string $token): never {
    $t = parse_del_token($token);
    if ($t === null) { render_delete_bad(); exit; }
    [$id, $given] = $t;
    $m = fetch_meta($id);
    if (!$m || !hash_equals((string)$m['delete_token'], $given)) { render_delete_bad(); exit; }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['confirm'] ?? '') === '1') {
        db()->prepare('DELETE FROM images WHERE id = ?')->execute([$id]);
        page_head('Frame burned'); page_top(); ?>
        <div class="card">
          <div style="font-size:46px">🔥</div>
          <h1>Frame burned.</h1>
          <p>The blob, its key reference and every byte of it are gone.<br>Ashes kept: none.</p>
          <a class="btn btn-ghost" href="?">← back to the darkroom</a>
        </div>
        <?php page_foot(); exit;
    }
    page_head('Burn frame?'); page_top(); ?>
<div class="card">
  <div style="font-size:46px">🗑</div>
  <h1>Burn this frame?</h1>
  <p class="mono" style="color:var(--amber)"><?= e($m['filename'] !== '' ? $m['filename'] : 'frame-'.$id) ?></p>
  <p><?= e(fmt_bytes((int)$m['size'])) ?> · uploaded <?= e(ago((int)$m['created_at'])) ?> · <?= e($m['mime']) ?><br>
  This cannot be undone. The encrypted blob is deleted immediately.</p>
  <form method="post" action="?del=<?= e($token) ?>" style="display:flex;gap:10px;justify-content:center;margin-top:20px">
    <input type="hidden" name="confirm" value="1">
    <button class="btn btn-ember" style="width:auto;padding:14px 30px" type="submit">🔥 Burn it</button>
    <a class="btn btn-ghost" href="?v=" onclick="history.length?window.history.back():location='?';return false;">Keep it</a>
  </form>
</div>
<?php page_foot(); exit; }

function render_delete_bad(): never {
    page_head('Invalid link'); page_top(); ?>
<div class="card"><div class="bigcode">∅</div><h1>Nothing to burn.</h1>
<p>This delete link is invalid — the frame never existed,<br>already burned, or the link was mistyped.</p>
<a class="btn btn-ghost" href="?">← back to the darkroom</a></div>
<?php page_foot(); exit; }

// --------------------------- ERROR PAGE -------------------------------
function fail_http(int $code, string $msg): never {
    http_response_code($code);
    $codes = [400=>'BAD LINK',403=>'LOCKED',404=>'MISSING FRAME',410=>'BURNED'];
    page_head((string)$code); page_top(); ?>
<div class="card"><div class="bigcode"><?= $code ?></div>
<h1><?= e($codes[$code] ?? 'ERROR') ?></h1><p><?= e($msg) ?></p>
<a class="btn btn-ghost" href="?">← back to the darkroom</a></div>
<?php page_foot(); exit; }