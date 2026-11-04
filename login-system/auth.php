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

/**
 * Create a URL-safe, high-entropy verification token and its database digest.
 *
 * @return array{token: string, token_hash: string}
 */
function createVerificationToken(): array
{
    $token = bin2hex(random_bytes(32));

    return ['token' => $token, 'token_hash' => hash('sha256', $token)];
}

/**
 * Store a digest of a new verification token with its expiration timestamp.
 */
function replaceVerificationToken(mysqli $mysqli, string $email, string $tokenHash, string $expiresAt): bool
{
    $statement = $mysqli->prepare(
        'UPDATE users SET verification_token_hash = ?, verification_expires_at = ? WHERE email = ? AND active = 0'
    );
    $statement->bind_param('sss', $tokenHash, $expiresAt, $email);
    $statement->execute();
    $updated = $statement->affected_rows === 1;
    $statement->close();

    return $updated;
}

/**
 * Atomically activate an unverified account if its token is valid and unexpired.
 */
function consumeVerificationToken(mysqli $mysqli, string $email, string $token): bool
{
    $tokenHash = hash('sha256', $token);
    $statement = $mysqli->prepare(
        'UPDATE users SET active = 1, verification_token_hash = NULL, verification_expires_at = NULL '
        . 'WHERE email = ? AND active = 0 AND verification_token_hash = ? '
        . 'AND verification_expires_at > UTC_TIMESTAMP()'
    );
    $statement->bind_param('ss', $email, $tokenHash);
    $statement->execute();
    $consumed = $statement->affected_rows === 1;
    $statement->close();

    return $consumed;
}

/**
 * Create a URL-safe, high-entropy password-reset token and its database digest.
 *
 * @return array{token: string, token_hash: string}
 */
function createPasswordResetToken(): array
{
    $token = bin2hex(random_bytes(32));

    return ['token' => $token, 'token_hash' => hash('sha256', $token)];
}

/** Replace any outstanding reset token for an account. */
function issuePasswordResetToken(mysqli $mysqli, string $email, string $tokenHash, string $expiresAt): bool
{
    $statement = $mysqli->prepare(
        'UPDATE users SET password_reset_token_hash = ?, password_reset_expires_at = ? WHERE email = ?'
    );
    $statement->bind_param('sss', $tokenHash, $expiresAt, $email);
    $statement->execute();
    $issued = $statement->affected_rows === 1;
    $statement->close();

    return $issued;
}

/** Clear a token only if it is still the token whose email delivery failed. */
function discardPasswordResetToken(mysqli $mysqli, string $email, string $tokenHash): void
{
    $statement = $mysqli->prepare(
        'UPDATE users SET password_reset_token_hash = NULL, password_reset_expires_at = NULL '
        . 'WHERE email = ? AND password_reset_token_hash = ?'
    );
    $statement->bind_param('ss', $email, $tokenHash);
    $statement->execute();
    $statement->close();
}

/** Check a reset link before rendering the password form. */
function isPasswordResetTokenValid(mysqli $mysqli, string $email, string $token): bool
{
    $tokenHash = hash('sha256', $token);
    $statement = $mysqli->prepare(
        'SELECT id FROM users WHERE email = ? AND password_reset_token_hash = ? '
        . 'AND password_reset_expires_at > UTC_TIMESTAMP() LIMIT 1'
    );
    $statement->bind_param('ss', $email, $tokenHash);
    $statement->execute();
    $isValid = $statement->get_result()->num_rows === 1;
    $statement->close();

    return $isValid;
}

/** Atomically change the password and consume its valid, unexpired reset token. */
function consumePasswordResetToken(mysqli $mysqli, string $email, string $token, string $passwordHash): bool
{
    $tokenHash = hash('sha256', $token);
    $statement = $mysqli->prepare(
        'UPDATE users SET password = ?, password_reset_token_hash = NULL, password_reset_expires_at = NULL '
        . 'WHERE email = ? AND password_reset_token_hash = ? '
        . 'AND password_reset_expires_at > UTC_TIMESTAMP()'
    );
    $statement->bind_param('sss', $passwordHash, $email, $tokenHash);
    $statement->execute();

    // Clearing the non-null token digest guarantees a valid matching row changes,
    // even if the newly generated password hash happens to match the old value.
    $consumed = $statement->affected_rows === 1;
    $statement->close();

    return $consumed;
}
