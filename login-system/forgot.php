<?php 
/* Reset your password form, sends reset.php password link */
require 'db.php';
require_once __DIR__ . '/auth.php';
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $genericMessage = 'If an account exists for that email, a password reset link has been sent.';
    $email = $_POST['email'] ?? null;

    if (is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        try {
            $lookup = $mysqli->prepare('SELECT email, first_name FROM users WHERE email = ? LIMIT 1');
            $lookup->bind_param('s', $email);
            $lookup->execute();
            $user = $lookup->get_result()->fetch_assoc() ?: null;
            $lookup->close();

            if ($user !== null) {
                $reset = createPasswordResetToken();
                $expiresAt = gmdate('Y-m-d H:i:s', time() + 3600);
                if (!issuePasswordResetToken($mysqli, $user['email'], $reset['token_hash'], $expiresAt)) {
                    error_log('Password reset token could not be issued.');
                } else {
                    $baseUrl = rtrim(getenv('APP_BASE_URL') ?: 'http://localhost:8080', '/');
                    $resetUrl = $baseUrl . '/reset.php?email='
                        . rawurlencode($user['email']) . '&token=' . rawurlencode($reset['token']);
                    $messageBody = "Hello {$user['first_name']},\n\n"
                        . "You requested a password reset. Use this link within one hour:\n\n"
                        . $resetUrl . "\n";

                    if (!@mail($user['email'], 'Password Reset Link', $messageBody)) {
                        discardPasswordResetToken($mysqli, $user['email'], $reset['token_hash']);
                        error_log('Password reset email delivery failed.');
                    }
                }
            }
        } catch (mysqli_sql_exception $exception) {
            error_log('Password reset request database operation failed.');
        }
    }

    $_SESSION['message'] = $genericMessage;
    header('Location: success.php');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head>
  <title>Reset Your Password</title>
  <?php include 'css/css.html'; ?>
</head>

<body>
    
  <div class="form">

    <h1>Reset Your Password</h1>

    <form action="forgot.php" method="post">
     <div class="field-wrap">
      <label>
        Email Address<span class="req">*</span>
      </label>
      <input type="email"required autocomplete="off" name="email"/>
    </div>
    <button class="button button-block"/>Reset</button>
    </form>
  </div>
          
<script src='http://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js'></script>
<script src="js/index.js"></script>
</body>

</html>
