<?php
/**
 * Fetch a user by exact email using a bound parameter.
 *
 * @return array<string, mixed>|null
 */
function findUserByEmail(mysqli $mysqli, string $email): ?array
{
    $statement = $mysqli->prepare(
        'SELECT id, first_name, last_name, email, password, active FROM users WHERE email = ? LIMIT 1'
    );
    $statement->bind_param('s', $email);
    $statement->execute();

    $result = $statement->get_result();
    $user = $result->fetch_assoc() ?: null;

    $statement->close();

    return $user;
}

/**
 * Check login credentials while retaining the existing failure categories.
 *
 * @return array{status: 'authenticated'|'unknown_email'|'invalid_password', user: array<string, mixed>|null}
 */
function checkLoginCredentials(mysqli $mysqli, string $email, string $password): array
{
    $user = findUserByEmail($mysqli, $email);

    if ($user === null) {
        return ['status' => 'unknown_email', 'user' => null];
    }

    if (!password_verify($password, $user['password'])) {
        return ['status' => 'invalid_password', 'user' => null];
    }

    return ['status' => 'authenticated', 'user' => $user];
}
