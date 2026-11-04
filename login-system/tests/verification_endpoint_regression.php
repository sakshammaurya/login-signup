<?php
/**
 * HTTP integration tests for the email verification endpoint.
 * Run with: docker compose exec -T app php tests/verification_endpoint_regression.php
 */
require_once __DIR__ . '/../db.php';
require_once __DIR__ . '/../auth.php';

mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$baseUrl = getenv('APP_TEST_BASE_URL') ?: 'http://127.0.0.1';
$cookieJar = tempnam(sys_get_temp_dir(), 'verify-cookie-');
$fixtures = [];

function expectEndpoint(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function createEndpointFixture(mysqli $mysqli, string $email, bool $active, string $expiry): array
{
    $name = 'EndpointTest';
    $passwordHash = password_hash('test-only-password', PASSWORD_DEFAULT);
    $legacyHash = bin2hex(random_bytes(16));
    $token = createVerificationToken();
    $activeValue = $active ? 1 : 0;
    $statement = $mysqli->prepare(
        'INSERT INTO users (first_name, last_name, email, password, hash, active, verification_token_hash, verification_expires_at) '
        . 'VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $statement->bind_param(
        'ssssiiss',
        $name,
        $name,
        $email,
        $passwordHash,
        $legacyHash,
        $activeValue,
        $token['token_hash'],
        $expiry
    );
    $statement->execute();
    $statement->close();

    return ['email' => $email, 'token' => $token['token']];
}

function requestVerificationEndpoint(string $baseUrl, string $cookieJar, array $fixture, ?string $overrideEmail = null): array
{
    $query = http_build_query(
        ['email' => $overrideEmail ?? $fixture['email'], 'token' => $fixture['token']],
        '',
        '&',
        PHP_QUERY_RFC3986
    );
    $curl = curl_init($baseUrl . '/verify.php?' . $query);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_HEADER => true,
        CURLOPT_COOKIEJAR => $cookieJar,
        CURLOPT_COOKIEFILE => $cookieJar,
        CURLOPT_TIMEOUT => 10,
    ]);
    $response = curl_exec($curl);
    if ($response === false) {
        $error = curl_error($curl);
        curl_close($curl);
        throw new RuntimeException('HTTP request failed: ' . $error);
    }
    $status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
    curl_close($curl);

    return ['status' => $status, 'headers' => substr($response, 0, $headerSize), 'body' => substr($response, $headerSize)];
}

function fetchEndpointUser(mysqli $mysqli, string $email): ?array
{
    $statement = $mysqli->prepare(
        'SELECT active, verification_token_hash, verification_expires_at FROM users WHERE email = ?'
    );
    $statement->bind_param('s', $email);
    $statement->execute();
    $user = $statement->get_result()->fetch_assoc() ?: null;
    $statement->close();

    return $user;
}

function fetchSessionPage(string $baseUrl, string $cookieJar, string $page): string
{
    $curl = curl_init($baseUrl . '/' . $page);
    curl_setopt_array($curl, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_COOKIEJAR => $cookieJar,
        CURLOPT_COOKIEFILE => $cookieJar,
        CURLOPT_TIMEOUT => 10,
    ]);
    $body = curl_exec($curl);
    if ($body === false) {
        $error = curl_error($curl);
        curl_close($curl);
        throw new RuntimeException('Could not fetch session page: ' . $error);
    }
    curl_close($curl);

    return $body;
}

try {
    $future = gmdate('Y-m-d H:i:s', time() + 3600);
    $past = gmdate('Y-m-d H:i:s', time() - 3600);
    $valid = createEndpointFixture($mysqli, 'verify-http-' . bin2hex(random_bytes(8)) . '@example.test', false, $future);
    $fixtures[] = $valid['email'];
    $response = requestVerificationEndpoint($baseUrl, $cookieJar, $valid);
    expectEndpoint($response['status'] === 302 && preg_match('/^Location:\s*success\.php/im', $response['headers']) === 1,
        'Valid token should redirect to success.php.');
    $user = fetchEndpointUser($mysqli, $valid['email']);
    expectEndpoint($user !== null && (int) $user['active'] === 1 && $user['verification_token_hash'] === null,
        'Valid endpoint request should activate only its account and consume its token.');
    $successPage = fetchSessionPage($baseUrl, $cookieJar, 'success.php');
    expectEndpoint(str_contains($successPage, 'Your account has been activated!'),
        'Success response should contain the activation message in the same session.');
    echo "PASS: valid endpoint request activates the account and redirects to success.\n";

    $response = requestVerificationEndpoint($baseUrl, $cookieJar, $valid);
    expectEndpoint($response['status'] === 302 && preg_match('/^Location:\s*error\.php/im', $response['headers']) === 1,
        'Reused token should redirect to error.php.');
    $errorPage = fetchSessionPage($baseUrl, $cookieJar, 'error.php');
    expectEndpoint(str_contains($errorPage, 'Account has already been activated or the URL is invalid!'),
        'Reused token should set the existing error message in the session.');
    echo "PASS: reused token redirects to the existing error flow.\n";

    $invalid = createEndpointFixture($mysqli, 'verify-http-' . bin2hex(random_bytes(8)) . '@example.test', false, $future);
    $fixtures[] = $invalid['email'];
    $invalid['token'] = str_repeat('a', 64);
    $response = requestVerificationEndpoint($baseUrl, $cookieJar, $invalid);
    expectEndpoint($response['status'] === 302 && preg_match('/^Location:\s*error\.php/im', $response['headers']) === 1,
        'Invalid token should redirect to error.php.');
    $user = fetchEndpointUser($mysqli, $invalid['email']);
    expectEndpoint($user !== null && (int) $user['active'] === 0, 'Invalid token must not activate its account.');
    echo "PASS: invalid token redirects to error and leaves the account inactive.\n";

    $expired = createEndpointFixture($mysqli, 'verify-http-' . bin2hex(random_bytes(8)) . '@example.test', false, $past);
    $fixtures[] = $expired['email'];
    $response = requestVerificationEndpoint($baseUrl, $cookieJar, $expired);
    expectEndpoint($response['status'] === 302 && preg_match('/^Location:\s*error\.php/im', $response['headers']) === 1,
        'Expired token should redirect to error.php.');
    $user = fetchEndpointUser($mysqli, $expired['email']);
    expectEndpoint($user !== null && (int) $user['active'] === 0, 'Expired token must not activate its account.');
    echo "PASS: expired token redirects to error and leaves the account inactive.\n";

    $wrongAccount = createEndpointFixture($mysqli, 'verify-http-' . bin2hex(random_bytes(8)) . '@example.test', false, $future);
    $fixtures[] = $wrongAccount['email'];
    $response = requestVerificationEndpoint($baseUrl, $cookieJar, $wrongAccount, 'different-' . $wrongAccount['email']);
    expectEndpoint($response['status'] === 302 && preg_match('/^Location:\s*error\.php/im', $response['headers']) === 1,
        'Wrong-account email should redirect to error.php.');
    $user = fetchEndpointUser($mysqli, $wrongAccount['email']);
    expectEndpoint($user !== null && (int) $user['active'] === 0, 'Wrong-account email must not activate token owner.');
    echo "PASS: token cannot verify a different email account.\n";

    $alreadyActive = createEndpointFixture($mysqli, 'verify-http-' . bin2hex(random_bytes(8)) . '@example.test', true, $future);
    $fixtures[] = $alreadyActive['email'];
    $response = requestVerificationEndpoint($baseUrl, $cookieJar, $alreadyActive);
    expectEndpoint($response['status'] === 302 && preg_match('/^Location:\s*error\.php/im', $response['headers']) === 1,
        'Already-active account should redirect to error.php.');
    $user = fetchEndpointUser($mysqli, $alreadyActive['email']);
    expectEndpoint($user !== null && (int) $user['active'] === 1, 'Already-active account state must remain unchanged.');
    echo "PASS: already-active account rejects its old token.\n";

    $invalidParameters = $baseUrl . '/verify.php?email=' . rawurlencode($valid['email']) . '&token[]=bad';
    $curl = curl_init($invalidParameters);
    curl_setopt_array($curl, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_HEADER => true]);
    $badResponse = curl_exec($curl);
    $badStatus = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
    $badHeaders = substr((string) $badResponse, 0, curl_getinfo($curl, CURLINFO_HEADER_SIZE));
    curl_close($curl);
    expectEndpoint($badStatus === 302 && preg_match('/^Location:\s*error\.php/im', $badHeaders) === 1,
        'Array-shaped token parameter should be rejected safely.');
    echo "PASS: malformed array parameter redirects safely to error.\n";
} finally {
    if ($fixtures !== []) {
        $delete = $mysqli->prepare('DELETE FROM users WHERE email = ?');
        foreach ($fixtures as $fixtureEmail) {
            $delete->bind_param('s', $fixtureEmail);
            $delete->execute();
        }
        $delete->close();
    }
    if (is_file($cookieJar)) {
        unlink($cookieJar);
    }
}
