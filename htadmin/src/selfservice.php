<?php
session_start();
include_once ('tools/htpasswd.php');
include_once ('includes/head.php');
include_once ('includes/nav.php');

# Set some variable values:
$min_password_len = set_new_value_or_default($ini['min_password_len'], '8');
$max_password_len = set_new_value_or_default($ini['max_password_len'], '16');

$htpasswd = new htpasswd ( $ini ['secure_path'] );    # Create a new htpasswd object

?>

<div class="container box">
  <div class="row">
    <div class="col-xs-12">
    <h2>Change your account password here:</h2>
<?php
$equal   = true;
$success = false;

if (isset ( $_POST ['username'] ) && isset ( $_POST ['old_pwd'] ) && isset ( $_POST ['new_pwd'] ) && isset ( $_POST ['new_pwd_verify'] )) {
  $username       = $_POST ['username'];
  $old_pwd        = $_POST ['old_pwd'];
  $new_pwd        = $_POST ['new_pwd'];
  $new_pwd_verify = $_POST ['new_pwd_verify'];
  $error_msg      = "";
  $error_msg2     = "";
  $error_msg3     = "";

  $new_pwds_match  = ($new_pwd == $new_pwd_verify);
  $old_pwd_matches = $htpasswd->user_login_check ( $username, $old_pwd, $error_msg2);

  if (! $htpasswd->user_exists ( $username )) {
    $error_msg = 'Error: username: ' . $username . ' was not found in the password file!';
    echo_alert_danger_div("user_exists");
    echo $error_msg . '</div>';

  } elseif ($username == $ini['admin_user'] ) {
    echo_alert_danger_div("check_username");
    echo "Error: The administrator account password must be changed through the Administrator Login page." . '</div>';

  } elseif (! check_password_quality ( $new_pwd, $min_password_len, $max_password_len, $error_msg )) {
    echo_alert_danger_div("check_password_quality");
    echo "New password: " . $error_msg . '</div>';

  } elseif (! $old_pwd_matches) {
    $error_msg_ex = 'Error: Old password doesn\'t match the stored password. (' . $error_msg2 . ')';
    echo_alert_danger_div("not_old_passwd_matches");
    echo $error_msg_ex . '</div>';

  } elseif (! $new_pwds_match) {
    $error_msg = 'Error: New passwords don\'t match.';
    echo_alert_danger_div("new_pwds_match");
    echo $error_msg . '</div>';

  } elseif ($old_pwd_matches && $new_pwds_match) {
    # Success branch:
    echo_alert_info_div("pwds_changed");
    echo 'Password changed successfully.' . '</div>';
    $htpasswd->user_update ( $username, $new_pwd, $error_msg3 );    # Write out the new user password.
  }
}
?>

    <div class="result alert alert-info" style="display: none;"></div>    <!-- result class 'div' can be updated by Javascript? -->

  </div>
  </div>

  <div class=row>
    <div class="col-xs-12 col-md-4">
      <form class="navbar-form navbar-left" action="selfservice.php"
        method="post">
        <div class="form-group">

          <input type="text" class="userfield form-control"
            placeholder="Username" name="username" <?php if (isset($_POST['username'])) echo "value=".htmlspecialchars($_POST['username']);?>>
          </p>
          <p>
            <input class="passwordfield form-control" type="password"
              name="old_pwd" placeholder="Old Password" <?php if (isset($_POST['username'])) echo "autofocus" ?>/>
          </p>
          <p>
            <input class="passwordfield form-control" type="password"
              name="new_pwd" placeholder="New Password" />
          </p>
          <p>
            <input class="passwordverifyfield form-control" type="password"
              name="new_pwd_verify" placeholder="Password Verify" />
          </p>
          <button type="submit" class="btn btn-default">Change</button>
        </div>
      </form>

    </div>

  </div>

</div>
<?php
include_once ('includes/footer.php');
?>
