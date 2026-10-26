<?php
/* User login process, checks if user exists and password is correct */

require_once __DIR__ . '/auth.php';

$email = isset($_POST['email']) && is_string($_POST['email']) ? $_POST['email'] : '';
$password = isset($_POST['password']) && is_string($_POST['password']) ? $_POST['password'] : '';
$user = findUserByEmail($mysqli, $email);

if ($user === null) { // User doesn't exist
    $_SESSION['message'] = "User with that email doesn't exist!";
    header("location: error.php");
    exit;
}

if (password_verify($password, $user['password'])) {
    $_SESSION['email'] = $user['email'];
    $_SESSION['first_name'] = $user['first_name'];
    $_SESSION['last_name'] = $user['last_name'];
    $_SESSION['active'] = $user['active'];

    // This is how we'll know the user is logged in
    $_SESSION['logged_in'] = true;

    header("location: profile.php");
    exit;
}

$_SESSION['message'] = "You have entered wrong password, try again!";
header("location: error.php");
exit;
