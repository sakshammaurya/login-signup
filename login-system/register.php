<?php
require_once __DIR__ . '/auth.php';

/* Registration process, inserts user info into the database 
   and sends account confirmation email message
 */

// Set session variables to be used on profile.php page
$_SESSION['email'] = $_POST['email'];
$_SESSION['first_name'] = $_POST['firstname'];
$_SESSION['last_name'] = $_POST['lastname'];

// Validate scalar inputs before using the account values.
$first_name = is_string($_POST['firstname'] ?? null) ? $_POST['firstname'] : '';
$last_name = is_string($_POST['lastname'] ?? null) ? $_POST['lastname'] : '';
$email = is_string($_POST['email'] ?? null) ? $_POST['email'] : '';
$plainPassword = is_string($_POST['password'] ?? null) ? $_POST['password'] : '';
$password = password_hash($plainPassword, PASSWORD_BCRYPT);
$verification = createVerificationToken();
$verificationExpiresAt = gmdate('Y-m-d H:i:s', time() + 86400);
      
// Check if user with that email already exists
$lookup = $mysqli->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
$lookup->bind_param('s', $email);
$lookup->execute();
$result = $lookup->get_result();
$lookup->close();

// We know user email exists if the rows returned are more than 0
if ( $result->num_rows > 0 ) {
    
    $_SESSION['message'] = 'User with this email already exists!';
    header("location: error.php");
    
}
else { // Email doesn't already exist in a database, proceed...

    // active is 0 by DEFAULT (no need to include it here)
    $legacyHash = bin2hex(random_bytes(16));
    $insert = $mysqli->prepare(
        'INSERT INTO users (first_name, last_name, email, password, hash, verification_token_hash, verification_expires_at) '
        . 'VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $insert->bind_param(
        'sssssss',
        $first_name,
        $last_name,
        $email,
        $password,
        $legacyHash,
        $verification['token_hash'],
        $verificationExpiresAt
    );

    // Add user to the database
    if ( $insert->execute() ){
        $insert->close();

        $_SESSION['active'] = 0; //0 until user activates their account with verify.php
        $_SESSION['logged_in'] = true; // So we know the user has logged in
        $_SESSION['message'] =
                
                 "Confirmation link has been sent to $email, please verify
                 your account by clicking on the link in the message!";

        // Send registration confirmation link (verify.php)
        $to      = $email;
        $subject = 'Account Verification ( clevertechie.com )';
        $message_body = '
        Hello '.$first_name.',

        Thank you for signing up!

        Please click this link to activate your account:

        http://localhost/login-system/verify.php?email='.rawurlencode($email).'&token='.$verification['token'];

        mail( $to, $subject, $message_body );

        header("location: profile.php"); 

    }

    else {
        $insert->close();
        $_SESSION['message'] = 'Registration failed!';
        header("location: error.php");
    }

}
