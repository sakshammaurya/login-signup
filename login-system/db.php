<?php
/*
 * Database connection settings.
 * Configure these environment variables in your local/server environment:
 * DB_HOST, DB_USER, DB_PASSWORD, DB_NAME.
 * Do not commit real credentials to the repository.
 */
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

$host = getenv('DB_HOST') ?: 'localhost';
$user = getenv('DB_USER') ?: 'root';
$pass = getenv('DB_PASSWORD') ?: '';
$db = getenv('DB_NAME') ?: 'accounts';

try {
    $mysqli = new mysqli($host, $user, $pass, $db);
    $mysqli->set_charset('utf8mb4');
} catch (mysqli_sql_exception $exception) {
    error_log('Database connection failed: ' . $exception->getMessage());
    http_response_code(500);
    exit('A database error occurred. Please try again later.');
}
