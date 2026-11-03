<?php 
/* Verifies registered user email, the link to this page
   is included in the register.php email message 
*/
require 'db.php';
require_once __DIR__ . '/auth.php';
session_start();

// Verify a scalar email and URL-safe token; the database stores only its digest.
if (isset($_GET['email'], $_GET['token'])
    && is_string($_GET['email'])
    && is_string($_GET['token'])
    && $_GET['email'] !== ''
    && preg_match('/\A[a-f0-9]{64}\z/', $_GET['token']) === 1)
{
    if (!consumeVerificationToken($mysqli, $_GET['email'], $_GET['token'])) {
        $_SESSION['message'] = "Account has already been activated or the URL is invalid!";
        header("location: error.php");
        exit;
    }

    $_SESSION['message'] = "Your account has been activated!";
    $_SESSION['active'] = 1;
    header("location: success.php");
    exit;
}
else {
    $_SESSION['message'] = "Invalid parameters provided for account verification!";
    header("location: error.php");
    exit;
}     
?>
