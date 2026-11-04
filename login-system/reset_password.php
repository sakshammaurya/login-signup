<?php
/* Securely updates a password using a valid, single-use reset token. */
require 'db.php';
require_once __DIR__ . '/auth.php';
session_start();

function rejectPasswordResetSubmission(string $message = 'The password reset link is invalid, expired, or already used.'): never
{
    $_SESSION['message'] = $message;
    header('Location: error.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    rejectPasswordResetSubmission('Please submit the password reset form.');
}

$email = $_POST['email'] ?? null;
$token = $_POST['token'] ?? null;
$newPassword = $_POST['newpassword'] ?? null;
$confirmation = $_POST['confirmpassword'] ?? null;

if (!is_string($email)
    || !filter_var($email, FILTER_VALIDATE_EMAIL)
    || !is_string($token)
    || preg_match('/\A[a-f0-9]{64}\z/', $token) !== 1
    || !is_string($newPassword)
    || !is_string($confirmation)
    || $newPassword === ''
    || strlen($newPassword) > 72
    || $newPassword !== $confirmation) {
    rejectPasswordResetSubmission('The password reset request is invalid. Check the form and try again.');
}

$passwordHash = password_hash($newPassword, PASSWORD_BCRYPT);
try {
    if (!consumePasswordResetToken($mysqli, $email, $token, $passwordHash)) {
        rejectPasswordResetSubmission();
    }
} catch (mysqli_sql_exception $exception) {
    error_log('Password reset update failed.');
    rejectPasswordResetSubmission('The password could not be reset. Please try again later.');
}

$_SESSION['message'] = 'Your password has been reset successfully!';
header('Location: success.php');
exit;
