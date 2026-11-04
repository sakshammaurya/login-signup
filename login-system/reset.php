<?php
/* The password reset form, the link to this page is included
   from the forgot.php email message
*/
require 'db.php';
require_once __DIR__ . '/auth.php';
session_start();

function rejectPasswordResetLink(): never
{
    $_SESSION['message'] = 'You have entered an invalid or expired password reset link.';
    header('Location: error.php');
    exit;
}

$email = $_GET['email'] ?? null;
$token = $_GET['token'] ?? null;
if (!is_string($email)
    || !filter_var($email, FILTER_VALIDATE_EMAIL)
    || !is_string($token)
    || preg_match('/\A[a-f0-9]{64}\z/', $token) !== 1) {
    rejectPasswordResetLink();
}

try {
    if (!isPasswordResetTokenValid($mysqli, $email, $token)) {
        rejectPasswordResetLink();
    }
} catch (mysqli_sql_exception $exception) {
    error_log('Password reset link validation failed.');
    rejectPasswordResetLink();
}
?>
<!DOCTYPE html>
<html >
<head>
  <meta charset="UTF-8">
  <title>Reset Your Password</title>
  <?php include 'css/css.html'; ?>
</head>

<body>
    <div class="form">

          <h1>Choose Your New Password</h1>
          
          <form action="reset_password.php" method="post">
              
          <div class="field-wrap">
            <label>
              New Password<span class="req">*</span>
            </label>
            <input type="password"required name="newpassword" autocomplete="off"/>
          </div>
              
          <div class="field-wrap">
            <label>
              Confirm New Password<span class="req">*</span>
            </label>
            <input type="password"required name="confirmpassword" autocomplete="off"/>
          </div>
          
          <!-- This input field is needed, to get the email of the user -->
          <input type="hidden" name="email" value="<?= htmlspecialchars($email, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
          <input type="hidden" name="token" value="<?= htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') ?>">
              
          <button class="button button-block"/>Apply</button>
          
          </form>

    </div>
<script src='http://cdnjs.cloudflare.com/ajax/libs/jquery/2.1.3/jquery.min.js'></script>
<script src="js/index.js"></script>

</body>
</html>
