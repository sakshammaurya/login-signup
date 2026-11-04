<?php
/**
 * HTTP integration tests for forgot/reset endpoints.
 * Run with: docker compose exec -T app php tests/password_reset_endpoint_regression.php
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$baseUrl = rtrim(getenv('APP_TEST_BASE_URL') ?: 'http://127.0.0.1', '/');
$fixtures = [];
$cookieJars = [];
$name = 'ResetHttpTest';
$initialPassword = 'Original-Http-Password!';
$initialPasswordHash = password_hash($initialPassword, PASSWORD_BCRYPT);
$legacyHash = bin2hex(random_bytes(16));
$verificationHash = hash('sha256', 'verification-http-fixture');
$verificationExpiry = gmdate('Y-m-d H:i:s', time() + 3600);

function assertResetHttp(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function createResetHttpFixture(mysqli $mysqli, array &$fixtures, ?string $tokenHash, ?string $expiry): string
{
    global $name, $initialPasswordHash, $legacyHash, $verificationHash, $verificationExpiry;
    $email = 'password-reset-http-' . bin2hex(random_bytes(8)) . '@example.test';
    $statement = $mysqli->prepare(
        'INSERT INTO users (first_name, last_name, email, password, hash, active, verification_token_hash, verification_expires_at, password_reset_token_hash, password_reset_expires_at) '
        . 'VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)'
    );
    $statement->bind_param(
        'sssssssss',
        $name,
        $name,
        $email,
        $initialPasswordHash,
        $legacyHash,
        $verificationHash,
        $verificationExpiry,
        $tokenHash,
        $expiry
    );
    $statement->execute();
    $statement->close();
    $fixtures[] = $email;

    return $email;
}

function readResetHttpUser(mysqli $mysqli, string $email): ?array
{
    $statement = $mysqli->prepare(
        'SELECT password, password_reset_token_hash, password_reset_expires_at, verification_token_hash, verification_expires_at '
        . 'FROM users WHERE email = ?'
    );
    $statement->bind_param('s', $email);
    $statement->execute();
    $user = $statement->get_result()->fetch_assoc() ?: null;
    $statement->close();

    return $user;
}

function newCookieJar(array &$cookieJars): string
{
    $jar = tempnam(sys_get_temp_dir(), 'password-reset-cookie-');
    $cookieJars[] = $jar;

    return $jar;
}

function httpResetRequest(string $baseUrl, string $path, string $method, array $fields, ?string $cookieJar = null): array
{
    $query = http_build_query($fields, '', '&', PHP_QUERY_RFC3986);
    $url = $baseUrl . $path;
    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_TIMEOUT => 10,
    ];
    if ($method === 'GET' && $query !== '') {
        $url .= '?' . $query;
    } elseif ($method === 'POST') {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = $query;
        $options[CURLOPT_HTTPHEADER] = ['Content-Type: application/x-www-form-urlencoded'];
    }
    if ($cookieJar !== null) {
        $options[CURLOPT_COOKIEJAR] = $cookieJar;
        $options[CURLOPT_COOKIEFILE] = $cookieJar;
    }

    $curl = curl_init($url);
    curl_setopt_array($curl, $options);
    $raw = curl_exec($curl);
    if ($raw === false) {
        $error = curl_error($curl);
        curl_close($curl);
        throw new RuntimeException('HTTP request failed: ' . $error);
    }
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
    curl_close($curl);
    $headers = substr($raw, 0, $headerSize);
    preg_match('/^Location:\s*(.+)$/im', $headers, $matches);

    return ['status' => $status, 'location' => trim($matches[1] ?? ''), 'body' => substr($raw, $headerSize)];
}

function sessionPage(string $baseUrl, string $page, string $cookieJar): string
{
    return httpResetRequest($baseUrl, '/' . $page, 'GET', [], $cookieJar)['body'];
}

function simultaneousResetPosts(string $baseUrl, string $email, string $token, array $passwords): array
{
    $multi = curl_multi_init();
    $handles = [];
    foreach ($passwords as $password) {
        $handle = curl_init($baseUrl . '/reset_password.php');
        curl_setopt_array($handle, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'email' => $email,
                'token' => $token,
                'newpassword' => $password,
                'confirmpassword' => $password,
            ], '', '&', PHP_QUERY_RFC3986),
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 10,
        ]);
        $handles[] = $handle;
        curl_multi_add_handle($multi, $handle);
    }

    do {
        do {
            $multiStatus = curl_multi_exec($multi, $running);
        } while ($multiStatus === CURLM_CALL_MULTI_PERFORM);
        if ($multiStatus !== CURLM_OK) {
            throw new RuntimeException('Could not execute concurrent reset requests.');
        }
        if ($running > 0) {
            curl_multi_select($multi, 0.01);
        }
    } while ($running > 0);

    $responses = [];
    foreach ($handles as $handle) {
        $raw = curl_multi_getcontent($handle);
        $headerSize = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
        $headers = substr($raw, 0, $headerSize);
        preg_match('/^Location:\s*(.+)$/im', $headers, $matches);
        $responses[] = [
            'status' => curl_getinfo($handle, CURLINFO_RESPONSE_CODE),
            'location' => trim($matches[1] ?? ''),
        ];
        curl_multi_remove_handle($multi, $handle);
        curl_close($handle);
    }
    curl_multi_close($multi);

    return $responses;
}

try {
    $future = gmdate('Y-m-d H:i:s', time() + 3600);
    $past = gmdate('Y-m-d H:i:s', time() - 3600);
    $validToken = createPasswordResetToken();
    $validEmail = createResetHttpFixture($mysqli, $fixtures, $validToken['token_hash'], $future);
    $jar = newCookieJar($cookieJars);

    $form = httpResetRequest(
        $baseUrl,
        '/reset.php',
        'GET',
        ['email' => $validEmail, 'token' => $validToken['token']],
        $jar
    );
    assertResetHttp($form['status'] === 200 && str_contains($form['body'], 'name="token"'),
        'Valid link should display the reset form.');
    assertResetHttp(str_contains($form['body'], htmlspecialchars($validToken['token'], ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')),
        'Reset form should carry the submitted token forward.');
    echo "PASS: valid link displays reset form.\n";

    $newPassword = 'New-Http-Password-2026!';
    $posted = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => $validEmail,
        'token' => $validToken['token'],
        'newpassword' => $newPassword,
        'confirmpassword' => $newPassword,
    ], $jar);
    assertResetHttp($posted['status'] === 302 && str_contains($posted['location'], 'success.php'),
        'Valid reset should redirect to success.');
    assertResetHttp(str_contains(sessionPage($baseUrl, 'success.php', $jar), 'Your password has been reset successfully!'),
        'Success message should be available in the same session.');
    $user = readResetHttpUser($mysqli, $validEmail);
    assertResetHttp(password_verify($newPassword, $user['password'])
        && $user['password_reset_token_hash'] === null
        && $user['verification_token_hash'] === $verificationHash,
        'Valid reset should change password, consume reset token, and preserve verification token.');
    echo "PASS: valid HTTP reset updates password and consumes only reset token.\n";

    $reused = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => $validEmail,
        'token' => $validToken['token'],
        'newpassword' => 'Reuse-Should-Fail!',
        'confirmpassword' => 'Reuse-Should-Fail!',
    ], $jar);
    assertResetHttp($reused['status'] === 302 && str_contains($reused['location'], 'error.php'),
        'Reused token should be rejected.');
    assertResetHttp(password_verify($newPassword, readResetHttpUser($mysqli, $validEmail)['password']),
        'Password must remain unchanged after token reuse.');
    echo "PASS: reused HTTP token is rejected without changing password.\n";

    $invalidToken = createPasswordResetToken();
    $invalidEmail = createResetHttpFixture($mysqli, $fixtures, $invalidToken['token_hash'], $future);
    $invalidJar = newCookieJar($cookieJars);
    $invalid = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => $invalidEmail,
        'token' => str_repeat('a', 64),
        'newpassword' => 'Invalid-Token-Should-Fail!',
        'confirmpassword' => 'Invalid-Token-Should-Fail!',
    ], $invalidJar);
    assertResetHttp($invalid['status'] === 302 && str_contains($invalid['location'], 'error.php'),
        'Invalid token POST should be rejected.');
    assertResetHttp(readResetHttpUser($mysqli, $invalidEmail)['password'] === $initialPasswordHash,
        'Password must not change after invalid token POST.');
    echo "PASS: invalid HTTP token is rejected and password remains unchanged.\n";

    $expiredToken = createPasswordResetToken();
    $expiredEmail = createResetHttpFixture($mysqli, $fixtures, $expiredToken['token_hash'], $past);
    $expiredGet = httpResetRequest($baseUrl, '/reset.php', 'GET', [
        'email' => $expiredEmail,
        'token' => $expiredToken['token'],
    ]);
    assertResetHttp($expiredGet['status'] === 302 && str_contains($expiredGet['location'], 'error.php')
        && !str_contains($expiredGet['body'], 'name="newpassword"'), 'Expired link must not render the password form.');
    $expiredPost = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => $expiredEmail,
        'token' => $expiredToken['token'],
        'newpassword' => 'Expired-Should-Fail!',
        'confirmpassword' => 'Expired-Should-Fail!',
    ]);
    assertResetHttp($expiredPost['status'] === 302 && str_contains($expiredPost['location'], 'error.php'),
        'Expired token POST must be rejected.');
    echo "PASS: expired HTTP link and POST are rejected.\n";

    $ownerToken = createPasswordResetToken();
    $ownerEmail = createResetHttpFixture($mysqli, $fixtures, $ownerToken['token_hash'], $future);
    $otherEmail = createResetHttpFixture($mysqli, $fixtures, null, null);
    $wrongOwner = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => $otherEmail,
        'token' => $ownerToken['token'],
        'newpassword' => 'Wrong-Account-Should-Fail!',
        'confirmpassword' => 'Wrong-Account-Should-Fail!',
    ]);
    assertResetHttp($wrongOwner['status'] === 302 && str_contains($wrongOwner['location'], 'error.php')
        && readResetHttpUser($mysqli, $otherEmail)['password'] === $initialPasswordHash,
        'Token must not reset another account.');
    echo "PASS: token cannot reset another account over HTTP.\n";

    $mismatchToken = createPasswordResetToken();
    $mismatchEmail = createResetHttpFixture($mysqli, $fixtures, $mismatchToken['token_hash'], $future);
    $mismatch = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => $mismatchEmail,
        'token' => $mismatchToken['token'],
        'newpassword' => 'Mismatch-First!',
        'confirmpassword' => 'Mismatch-Second!',
    ]);
    assertResetHttp($mismatch['status'] === 302 && str_contains($mismatch['location'], 'error.php')
        && readResetHttpUser($mysqli, $mismatchEmail)['password'] === $initialPasswordHash,
        'Mismatched passwords must not change the password.');
    echo "PASS: password confirmation mismatch is rejected.\n";

    $replacedToken = createPasswordResetToken();
    $replacedEmail = createResetHttpFixture($mysqli, $fixtures, $replacedToken['token_hash'], $future);
    $newToken = createPasswordResetToken();
    issuePasswordResetToken($mysqli, $replacedEmail, $newToken['token_hash'], $future);
    $replaced = httpResetRequest($baseUrl, '/reset.php', 'GET', [
        'email' => $replacedEmail,
        'token' => $replacedToken['token'],
    ]);
    assertResetHttp($replaced['status'] === 302 && str_contains($replaced['location'], 'error.php'),
        'Replaced token must not display reset form.');
    echo "PASS: replaced HTTP token is rejected.\n";

    $raceToken = createPasswordResetToken();
    $raceEmail = createResetHttpFixture($mysqli, $fixtures, $raceToken['token_hash'], $future);
    $racePasswords = ['Concurrent-First-Password!', 'Concurrent-Second-Password!'];
    $raceResponses = simultaneousResetPosts($baseUrl, $raceEmail, $raceToken['token'], $racePasswords);
    $raceSuccesses = count(array_filter($raceResponses, static fn (array $row): bool =>
        $row['status'] === 302 && str_contains($row['location'], 'success.php')));
    $raceFailures = count(array_filter($raceResponses, static fn (array $row): bool =>
        $row['status'] === 302 && str_contains($row['location'], 'error.php')));
    $raceUser = readResetHttpUser($mysqli, $raceEmail);
    $onePasswordWon = password_verify($racePasswords[0], $raceUser['password'])
        !== password_verify($racePasswords[1], $raceUser['password']);
    assertResetHttp($raceSuccesses === 1 && $raceFailures === 1 && $onePasswordWon
        && $raceUser['password_reset_token_hash'] === null,
        'Concurrent reset POSTs should have exactly one successful single-use token consumer.');
    echo "PASS: simultaneous HTTP reset attempts allow exactly one token consumer.\n";

    $malformedGet = httpResetRequest($baseUrl, '/reset.php', 'GET', [
        'email' => [$validEmail],
        'token' => [$validToken['token']],
    ]);
    assertResetHttp($malformedGet['status'] === 302 && str_contains($malformedGet['location'], 'error.php'),
        'Array-shaped GET parameters must be rejected safely.');
    $malformedPost = httpResetRequest($baseUrl, '/reset_password.php', 'POST', [
        'email' => [$validEmail],
        'token' => [$validToken['token']],
        'newpassword' => ['Array-Password!'],
        'confirmpassword' => ['Array-Password!'],
    ]);
    assertResetHttp($malformedPost['status'] === 302 && str_contains($malformedPost['location'], 'error.php'),
        'Array-shaped POST parameters must be rejected safely.');
    echo "PASS: malformed array request parameters are rejected safely.\n";

    $knownJar = newCookieJar($cookieJars);
    $unknownJar = newCookieJar($cookieJars);
    $knownForgot = httpResetRequest($baseUrl, '/forgot.php', 'POST', ['email' => $ownerEmail], $knownJar);
    $unknownForgot = httpResetRequest($baseUrl, '/forgot.php', 'POST', ['email' => 'no-such-user-' . bin2hex(random_bytes(6)) . '@example.test'], $unknownJar);
    assertResetHttp($knownForgot['status'] === 302 && str_contains($knownForgot['location'], 'success.php')
        && $unknownForgot['status'] === 302 && str_contains($unknownForgot['location'], 'success.php'),
        'Forgot endpoint should use success redirect for known and unknown emails.');
    $knownMessage = sessionPage($baseUrl, 'success.php', $knownJar);
    $unknownMessage = sessionPage($baseUrl, 'success.php', $unknownJar);
    assertResetHttp(str_contains($knownMessage, 'If an account exists for that email, a password reset link has been sent.')
        && str_contains($unknownMessage, 'If an account exists for that email, a password reset link has been sent.'),
        'Forgot endpoint must use the same public response for known and unknown emails.');
    $afterMailAttempt = readResetHttpUser($mysqli, $ownerEmail);
    if (!is_executable('/usr/sbin/sendmail')) {
        assertResetHttp($afterMailAttempt['password_reset_token_hash'] === null
            && $afterMailAttempt['password_reset_expires_at'] === null,
            'Definite email delivery failure should clear the matching reset token.');
    }
    echo "PASS: forgot endpoint response is generic for known and unknown emails.\n";
    if (!is_executable('/usr/sbin/sendmail')) {
        echo "PASS: email delivery failure clears the newly issued token.\n";
    }
} finally {
    if ($fixtures !== []) {
        $delete = $mysqli->prepare('DELETE FROM users WHERE email = ?');
        foreach ($fixtures as $fixtureEmail) {
            $delete->bind_param('s', $fixtureEmail);
            $delete->execute();
        }
        $delete->close();
    }
    foreach ($cookieJars as $jar) {
        if (is_file($jar)) {
            unlink($jar);
        }
    }
}
