<?php
/**
 * Integration regression tests for verification token lifecycle.
 * Run with: docker compose exec -T app php tests/verification_token_regression.php
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

mysqli_report(MYSQLI_REPORT_OFF);
$requiredColumns = ['verification_token_hash', 'verification_expires_at'];
$columnResult = $mysqli->query("SHOW COLUMNS FROM users");
$columns = array_column($columnResult->fetch_all(MYSQLI_ASSOC), 'Field');
foreach ($requiredColumns as $requiredColumn) {
    if (!in_array($requiredColumn, $columns, true)) {
        fwrite(STDERR, "FAIL: missing schema column {$requiredColumn}; apply the verification-token migration first.\n");
        exit(1);
    }
}

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$created = [];
$fixtureEmails = [];
$now = gmdate('Y-m-d H:i:s');
$future = gmdate('Y-m-d H:i:s', time() + 3600);
$past = gmdate('Y-m-d H:i:s', time() - 3600);
$mysqli->begin_transaction();

try {
    for ($i = 0; $i < 7; $i++) {
        $email = 'verify-regression-' . bin2hex(random_bytes(8)) . '-' . $i . '@example.test';
        $name = 'Verify';
        $password = password_hash('test-only-password', PASSWORD_DEFAULT);
        $legacyHash = bin2hex(random_bytes(16));
        $token = createVerificationToken();
        $expiresAt = $future;
        $insert = $mysqli->prepare(
            'INSERT INTO users (first_name, last_name, email, password, hash, active, verification_token_hash, verification_expires_at) '
            . 'VALUES (?, ?, ?, ?, ?, 0, ?, ?)'
        );
        $insert->bind_param('sssssss', $name, $name, $email, $password, $legacyHash, $token['token_hash'], $expiresAt);
        $insert->execute();
        $created[] = ['email' => $email, 'token' => $token['token']];
        $fixtureEmails[] = $email;
        $insert->close();
    }

    [$validEmail, $validToken] = [$created[0]['email'], $created[0]['token']];
    $replacement = createVerificationToken();
    if (strlen($validToken) !== 64 || preg_match('/\A[a-f0-9]{64}\z/', $validToken) !== 1) {
        throw new RuntimeException('Generated token must be 256-bit URL-safe hex with a SHA-256 digest.');
    }
    if ($replacement['token_hash'] !== hash('sha256', $replacement['token'])) {
        throw new RuntimeException('Stored token digest is incorrect.');
    }
    echo "PASS: token generation uses 256-bit URL-safe randomness and stores a digest.\n";

    if (!consumeVerificationToken($mysqli, $validEmail, $validToken)) {
        throw new RuntimeException('Valid token was not accepted.');
    }
    $check = $mysqli->prepare('SELECT active, verification_token_hash FROM users WHERE email = ?');
    $check->bind_param('s', $validEmail);
    $check->execute();
    $state = $check->get_result()->fetch_assoc();
    $check->close();
    if ((int) $state['active'] !== 1 || $state['verification_token_hash'] !== null) {
        throw new RuntimeException('Valid verification did not activate the account and consume the token.');
    }
    echo "PASS: valid token activates its account and is consumed.\n";

    if (consumeVerificationToken($mysqli, $created[1]['email'], 'not-the-token')) {
        throw new RuntimeException('Invalid token was accepted.');
    }
    echo "PASS: invalid token is rejected.\n";

    $expiredEmail = $created[2]['email'];
    $expiredToken = createVerificationToken();
    $expiry = $past;
    $update = $mysqli->prepare('UPDATE users SET verification_token_hash = ?, verification_expires_at = ? WHERE email = ?');
    $update->bind_param('sss', $expiredToken['token_hash'], $expiry, $expiredEmail);
    $update->execute();
    $update->close();
    if (consumeVerificationToken($mysqli, $expiredEmail, $expiredToken['token'])) {
        throw new RuntimeException('Expired token was accepted.');
    }
    echo "PASS: expired token is rejected.\n";

    if (consumeVerificationToken($mysqli, $validEmail, $validToken)) {
        throw new RuntimeException('Reused token was accepted.');
    }
    echo "PASS: reused token is rejected.\n";

    if (consumeVerificationToken($mysqli, $created[4]['email'], $created[3]['token'])) {
        throw new RuntimeException('Token activated a different account.');
    }
    echo "PASS: token cannot verify a different account.\n";

    $alreadyActiveEmail = $created[5]['email'];
    $active = 1;
    $update = $mysqli->prepare('UPDATE users SET active = ? WHERE email = ?');
    $update->bind_param('is', $active, $alreadyActiveEmail);
    $update->execute();
    $update->close();
    if (consumeVerificationToken($mysqli, $alreadyActiveEmail, $created[5]['token'])) {
        throw new RuntimeException('Already verified account was reactivated through its old token.');
    }
    echo "PASS: already verified account rejects old token.\n";

    $replacementEmail = $created[6]['email'];
    $replacementExpiry = $future;
    if (!replaceVerificationToken($mysqli, $replacementEmail, $replacement['token_hash'], $replacementExpiry)) {
        throw new RuntimeException('Replacement token could not be stored.');
    }
    if (consumeVerificationToken($mysqli, $replacementEmail, $created[6]['token'])) {
        throw new RuntimeException('Replaced token was accepted.');
    }
    if (!consumeVerificationToken($mysqli, $replacementEmail, $replacement['token'])) {
        throw new RuntimeException('Replacement token was rejected.');
    }
    echo "PASS: replacement invalidates old token and accepts new token.\n";

    // Exercise two independent connections against the same token row.
    $concurrentEmail = 'verify-concurrent-' . bin2hex(random_bytes(8)) . '@example.test';
    $concurrent = createVerificationToken();
    $concurrentExpiry = $future;
    $insert = $mysqli->prepare(
        'INSERT INTO users (first_name, last_name, email, password, hash, active, verification_token_hash, verification_expires_at) '
        . 'VALUES (?, ?, ?, ?, ?, 0, ?, ?)'
    );
    $insert->bind_param('sssssss', $name, $name, $concurrentEmail, $password, $legacyHash, $concurrent['token_hash'], $concurrentExpiry);
    $insert->execute();
    $insert->close();
    $fixtureEmails[] = $concurrentEmail;
    $mysqli->commit();
    $concurrentConnection = new mysqli(
        getenv('DB_HOST') ?: 'db',
        getenv('DB_USER') ?: 'root',
        getenv('DB_PASSWORD') ?: 'local-dev-password',
        getenv('DB_NAME') ?: 'accounts'
    );
    $concurrentConnection->set_charset('utf8mb4');
    $first = consumeVerificationToken($mysqli, $concurrentEmail, $concurrent['token']);
    $second = consumeVerificationToken($concurrentConnection, $concurrentEmail, $concurrent['token']);
    $concurrentConnection->close();
    if (!$first || $second) {
        throw new RuntimeException('Verification token was not single-use across repeated attempts.');
    }
    echo "PASS: only one verification attempt can consume a token.\n";
} finally {
    if ($fixtureEmails !== []) {
        $delete = $mysqli->prepare('DELETE FROM users WHERE email = ?');
        foreach ($fixtureEmails as $fixtureEmail) {
            $delete->bind_param('s', $fixtureEmail);
            $delete->execute();
        }
        $delete->close();
    }
}
