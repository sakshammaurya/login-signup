<?php
/**
 * Database integration tests for password-reset token behavior.
 * Run with: docker compose exec -T app php tests/password_reset_regression.php
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$requiredColumns = ['password_reset_token_hash', 'password_reset_expires_at'];
$result = $mysqli->query('SHOW COLUMNS FROM users');
$columns = array_column($result->fetch_all(MYSQLI_ASSOC), 'Field');
foreach ($requiredColumns as $column) {
    if (!in_array($column, $columns, true)) {
        fwrite(STDERR, "FAIL: missing schema column {$column}; apply the AUTH-003 migration first.\n");
        exit(1);
    }
}

$fixtures = [];
$future = gmdate('Y-m-d H:i:s', time() + 3600);
$past = gmdate('Y-m-d H:i:s', time() - 3600);
$currentPassword = 'Original-Password-2026!';
$name = 'ResetTest';
$passwordHash = password_hash($currentPassword, PASSWORD_BCRYPT);
$legacyHash = bin2hex(random_bytes(16));
$verification = ['verification_token_hash' => hash('sha256', 'verification-fixture-token'), 'verification_expires_at' => $future];

function addResetFixture(mysqli $mysqli, array &$fixtures, ?string $resetHash, ?string $expiry, bool $withReset = true): string
{
    global $name, $passwordHash, $legacyHash, $verification;
    $email = 'password-reset-' . bin2hex(random_bytes(8)) . '@example.test';
    $storedHash = $withReset ? $resetHash : null;
    $storedExpiry = $withReset ? $expiry : null;
    $statement = $mysqli->prepare(
        'INSERT INTO users (first_name, last_name, email, password, hash, active, verification_token_hash, verification_expires_at, password_reset_token_hash, password_reset_expires_at) '
        . 'VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)'
    );
    $statement->bind_param(
        'sssssssss',
        $name,
        $name,
        $email,
        $passwordHash,
        $legacyHash,
        $verification['verification_token_hash'],
        $verification['verification_expires_at'],
        $storedHash,
        $storedExpiry
    );
    $statement->execute();
    $statement->close();
    $fixtures[] = $email;

    return $email;
}

function readResetFixture(mysqli $mysqli, string $email): ?array
{
    $statement = $mysqli->prepare(
        'SELECT password, hash, active, verification_token_hash, verification_expires_at, '
        . 'password_reset_token_hash, password_reset_expires_at FROM users WHERE email = ?'
    );
    $statement->bind_param('s', $email);
    $statement->execute();
    $user = $statement->get_result()->fetch_assoc() ?: null;
    $statement->close();

    return $user;
}

try {
    $generated = createPasswordResetToken();
    if (strlen($generated['token']) !== 64 || preg_match('/\A[a-f0-9]{64}\z/', $generated['token']) !== 1
        || $generated['token_hash'] !== hash('sha256', $generated['token'])) {
        throw new RuntimeException('Reset token must be 256-bit hex with a SHA-256 digest.');
    }
    $email = addResetFixture($mysqli, $fixtures, $generated['token_hash'], $future);
    $stored = readResetFixture($mysqli, $email);
    if ($stored['password_reset_token_hash'] !== $generated['token_hash']
        || hash_equals($stored['password_reset_token_hash'], $generated['token'])) {
        throw new RuntimeException('Raw token must not be stored in the database.');
    }
    echo "PASS: secure token format and digest-only storage.\n";

    $newPassword = 'Changed-Password-2026!';
    if (!consumePasswordResetToken($mysqli, $email, $generated['token'], password_hash($newPassword, PASSWORD_BCRYPT))) {
        throw new RuntimeException('Valid token did not update the password.');
    }
    $stored = readResetFixture($mysqli, $email);
    if (!password_verify($newPassword, $stored['password'])
        || $stored['password_reset_token_hash'] !== null
        || $stored['password_reset_expires_at'] !== null
        || $stored['verification_token_hash'] !== $verification['verification_token_hash']
        || $stored['verification_expires_at'] !== $verification['verification_expires_at']) {
        throw new RuntimeException('Valid reset did not consume only its own token fields.');
    }
    echo "PASS: valid reset changes password, consumes token, and preserves AUTH-002 fields.\n";

    if (consumePasswordResetToken($mysqli, $email, $generated['token'], password_hash('Another-Password!', PASSWORD_BCRYPT))) {
        throw new RuntimeException('Consumed token was reusable.');
    }
    echo "PASS: reused token is rejected.\n";

    $invalidEmail = addResetFixture($mysqli, $fixtures, $generated['token_hash'], $future);
    $before = readResetFixture($mysqli, $invalidEmail);
    if (consumePasswordResetToken($mysqli, $invalidEmail, 'not-the-token', password_hash('No-Change!', PASSWORD_BCRYPT))) {
        throw new RuntimeException('Invalid token was accepted.');
    }
    $after = readResetFixture($mysqli, $invalidEmail);
    if ($before['password'] !== $after['password']) {
        throw new RuntimeException('Password changed after an invalid token attempt.');
    }
    echo "PASS: invalid token is rejected and leaves password unchanged.\n";

    $expiredToken = createPasswordResetToken();
    $expiredEmail = addResetFixture($mysqli, $fixtures, $expiredToken['token_hash'], $past);
    if (isPasswordResetTokenValid($mysqli, $expiredEmail, $expiredToken['token'])
        || consumePasswordResetToken($mysqli, $expiredEmail, $expiredToken['token'], password_hash('Expired-No!', PASSWORD_BCRYPT))) {
        throw new RuntimeException('Expired token was accepted.');
    }
    echo "PASS: expired token is rejected.\n";

    $replaceToken = createPasswordResetToken();
    $replaceEmail = addResetFixture($mysqli, $fixtures, $replaceToken['token_hash'], $future);
    $replacement = createPasswordResetToken();
    if (!issuePasswordResetToken($mysqli, $replaceEmail, $replacement['token_hash'], $future)
        || isPasswordResetTokenValid($mysqli, $replaceEmail, $replaceToken['token'])
        || !isPasswordResetTokenValid($mysqli, $replaceEmail, $replacement['token'])) {
        throw new RuntimeException('Replacement token did not invalidate the earlier link.');
    }
    echo "PASS: issuing another reset invalidates the previous token.\n";

    $otherToken = createPasswordResetToken();
    $ownerEmail = addResetFixture($mysqli, $fixtures, $otherToken['token_hash'], $future);
    $otherEmail = addResetFixture($mysqli, $fixtures, null, null, false);
    $otherBefore = readResetFixture($mysqli, $otherEmail);
    if (consumePasswordResetToken($mysqli, $otherEmail, $otherToken['token'], password_hash('Wrong-Owner!', PASSWORD_BCRYPT))) {
        throw new RuntimeException('Token reset a different account.');
    }
    if ($otherBefore['password'] !== readResetFixture($mysqli, $otherEmail)['password']) {
        throw new RuntimeException('Different account password changed.');
    }
    echo "PASS: token cannot reset a different account.\n";

    $concurrentToken = createPasswordResetToken();
    $concurrentEmail = addResetFixture($mysqli, $fixtures, $concurrentToken['token_hash'], $future);
    $second = new mysqli(
        getenv('DB_HOST') ?: 'db',
        getenv('DB_USER') ?: 'root',
        getenv('DB_PASSWORD') ?: 'local-dev-password',
        getenv('DB_NAME') ?: 'accounts'
    );
    $firstResult = consumePasswordResetToken($mysqli, $concurrentEmail, $concurrentToken['token'], password_hash('First-Race!', PASSWORD_BCRYPT));
    $secondResult = consumePasswordResetToken($second, $concurrentEmail, $concurrentToken['token'], password_hash('Second-Race!', PASSWORD_BCRYPT));
    $second->close();
    if (!$firstResult || $secondResult) {
        throw new RuntimeException('Two connections consumed one reset token.');
    }
    echo "PASS: two database connections cannot consume one token twice.\n";
} finally {
    if ($fixtures !== []) {
        $delete = $mysqli->prepare('DELETE FROM users WHERE email = ?');
        foreach ($fixtures as $fixtureEmail) {
            $delete->bind_param('s', $fixtureEmail);
            $delete->execute();
        }
        $delete->close();
    }
}
