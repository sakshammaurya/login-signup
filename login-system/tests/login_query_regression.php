<?php
/**
 * Integration regression test for login credential checks.
 *
 * Run from the repository root after starting Compose:
 *   docker compose exec -T app php tests/login_query_regression.php
 *
 * The test wraps its fixture in a transaction and rolls it back.
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

$mysqli->begin_transaction();

try {
    $email = 'auth-regression-' . bin2hex(random_bytes(8)) . '@example.test';
    $passwordHash = password_hash('test-only-password', PASSWORD_DEFAULT);
    $firstName = 'Regression';
    $lastName = 'Test';
    $hash = bin2hex(random_bytes(16));

    $insert = $mysqli->prepare(
        'INSERT INTO users (first_name, last_name, email, password, hash) VALUES (?, ?, ?, ?, ?)'
    );
    $insert->bind_param('sssss', $firstName, $lastName, $email, $passwordHash, $hash);
    $insert->execute();
    $insert->close();

    $validLogin = checkLoginCredentials($mysqli, $email, 'test-only-password');
    if ($validLogin['status'] !== 'authenticated'
        || $validLogin['user'] === null
        || $validLogin['user']['email'] !== $email) {
        throw new RuntimeException('Expected valid credentials to authenticate the fixture user.');
    }

    $wrongPassword = checkLoginCredentials($mysqli, $email, 'wrong-password');
    if ($wrongPassword['status'] !== 'invalid_password' || $wrongPassword['user'] !== null) {
        throw new RuntimeException('Expected an incorrect password to be rejected without an authenticated user.');
    }

    $unknownEmail = checkLoginCredentials($mysqli, 'missing-' . $email, 'test-only-password');
    if ($unknownEmail['status'] !== 'unknown_email' || $unknownEmail['user'] !== null) {
        throw new RuntimeException('Expected an unknown email to be rejected without an authenticated user.');
    }

    $injectionInput = "' OR '1'='1";
    $injectionLogin = checkLoginCredentials($mysqli, $injectionInput, 'test-only-password');
    if ($injectionLogin['status'] !== 'unknown_email' || $injectionLogin['user'] !== null) {
        throw new RuntimeException('Injection-shaped input unexpectedly authenticated a user.');
    }

    echo "PASS: valid credentials authenticate the fixture user.\n";
    echo "PASS: an incorrect password is rejected.\n";
    echo "PASS: an unknown email is rejected.\n";
    echo "PASS: injection-shaped email input cannot authenticate.\n";
} finally {
    $mysqli->rollback();
}
