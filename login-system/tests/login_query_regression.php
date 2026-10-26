<?php
/**
 * Integration regression test for the login email lookup.
 *
 * Run against a disposable/test database with the users schema configured:
 *   php login-system/tests/login_query_regression.php
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

    $user = findUserByEmail($mysqli, $email);
    if ($user === null || $user['email'] !== $email) {
        throw new RuntimeException('Expected exact email lookup to find the fixture user.');
    }

    $injectionInput = "' OR '1'='1";
    if (findUserByEmail($mysqli, $injectionInput) !== null) {
        throw new RuntimeException('Injection-shaped input unexpectedly matched a user.');
    }

    echo "PASS: exact email lookup finds the fixture user.\n";
    echo "PASS: injection-shaped input is treated as a literal email value.\n";
} finally {
    $mysqli->rollback();
}
