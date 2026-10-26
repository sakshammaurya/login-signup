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
