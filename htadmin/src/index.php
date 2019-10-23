<?php

/* DBG: if page is started from the command line, wrap passed parameters to $_POST and $_GET */
if (!isset($_SERVER["HTTP_HOST"])) {
  parse_str($argv[1], $_GET);
  parse_str($argv[1], $_POST);
}

include_once ('includes/check_admin_login.php');    # Make sure an admin 'logged in' session exists
include_once ('tools/htpasswd.php');
include_once ('includes/head.php');          # Include the HTTP header; Load config.ini into $ini; tools/util.php included here
include_once ('includes/nav.php');           # Build the top navigation bar menu
include_once ('tools/util.php');             # Include some utility functions


#echo "<p>" . "htpasswd_file_path=" . $ini ['secure_path'] . "</p>";
#echo "<p>" . "metadata_file_path=" . $ini ['metadata_path'] . "</p>";

$htpasswd_path = $ini ['secure_path'];    # Req'd .ini field
$metadata_path = $ini ['metadata_path'];
$use_metadata  = !is_null_or_empty_string($metadata_path);    # Set boolean flag

# Set some variable values:
$min_password_len = set_new_value_or_default($ini['min_password_len'], '8');
$max_password_len = set_new_value_or_default($ini['max_password_len'], '16');

$min_username_len = set_new_value_or_default($ini['min_username_len'], '4');
$max_username_len = set_new_value_or_default($ini['max_username_len'], '12');


# The $ini array was loaded by the 'nav.php' src file.
# Create a new 'httpasswd' object. The metadata_path file contains the user account data.
#
$htpasswd = new htpasswd ( $htpasswd_path, $metadata_path );

?>

<div class="container box">      <!-- container: fixed width container -->
  <div class="row">            <!-- row: A row of columns -->
    <div class="col-xs-12">  <!-- col-xs-12: Column 'eXtraSmall' device screen; Span all 12 columns; Bootstrap 3.3.6 -->
<?php

$form_field_error = False;
$error_msg        = '';

echo "<h2>" . $ini ['app_title'] . "</h2>";    # Output the app's title

if (isset ( $_POST ['user'] )) {         # The username has been POSTED to this iteration of the current page
  $username      = $_POST ['user'];      # (someone clicked on a 'username' on this page, to update it)
  $passwd        = $_POST ['pwd'];
  $passwd_verify = $_POST ['pwd_verify'];

  if ($use_metadata) {                   # The 'metadata' (user accounts) file exists.
    $meta_model = new meta_model ();     # Create an instance of the user account meta data fields.
    $meta_model->user  = $username;
    $meta_model->email = $_POST ['email'];
    $meta_model->name  = $_POST ['name'];
    $meta_model->mailkey = random_password(PASSWORD_LENGTH);
  }

    # Here was an endPHP, startPHP;

  if (! check_username_quality ( $username, $min_username_len, $max_username_len, $error_msg )) {
    #echo '<div class="alert alert-danger" id="username_quality">';
    echo_alert_danger_div("username_quality");
    echo $error_msg;
    echo '</div>';
    $form_field_error = True;

  } elseif (! check_password_quality ( $passwd, $min_password_len, $max_password_len, $error_msg )) {
    #echo '<div class="alert alert-danger" id="password_quality">';
    echo_alert_danger_div("password_quality");
    echo $error_msg;
    echo '</div>';
    $form_field_error = True;

  } elseif (! ( $passwd == $passwd_verify )) {
    #echo '<div class="alert alert-danger">';
    echo_alert_danger_div("password_verify");
    echo "<p>Error: New passwords don\'t match.</p> ";
    echo '</div>';
    $form_field_error = True;
    #dbg_print("passwd="        . $passwd);
    #dbg_print("passwd_verify=" . $passwd_verify);
    #
    callSetUserField($username, $meta_model->email, $meta_model->name);

  } else {
    #echo '<div class="alert alert-info">';
    $error_msg_1 = "";
    $error_msg_2 = "";
    #phpAlert("index.php: Before user_exists check");

    if (! $htpasswd->user_exists ( $username )) {
      $success = $htpasswd->user_add ( $username, $passwd, $error_msg_2 );
      $success_str = bool_to_string($success);

      $success_msg = "Username: <em>" . htmlspecialchars ( $username ) . "</em>, created.";
      $error_msg_1 = "Error: Username: <em>" . htmlspecialchars ( $username ) . "</em>, not created.";
      echo_approp_div_msg( $success, $success_msg, $error_msg_1, $error_msg_2);

    } else {
      $success     = $htpasswd->user_update ( $username, $passwd, $error_msg_2 );
      $success_msg = "Username: <em>" . htmlspecialchars ( $username ) . "</em>, updated.";
      $error_msg_1 = "Error: Username: <em>" . htmlspecialchars ( $username ) . "</em>, not updated.";
      echo_approp_div_msg( $success, $success_msg, $error_msg_1, $error_msg_2);
    }

    if ($use_metadata) {
      if (! $htpasswd->meta_exists ( $username )) {
        $success = $htpasswd->meta_add ( $meta_model, $error_msg_2 );
        $success_msg = "";
        $error_msg_1 = "Error: Metadata for username: <em>" . htmlspecialchars ( $username ) . "</em>, not added.";
        if (! $success) {
          echo_approp_div_msg( $success, $success_msg, $error_msg_1, $error_msg_2);
        }

      } else {
        $success = $htpasswd->meta_update ( $meta_model, $error_msg_2 );
        $success_msg = "";
        $error_msg_1 = "Error: Metadata for username: <em>" . htmlspecialchars ( $username ) . "</em>, not updated.";
        if (! $success) {
          echo_approp_div_msg( $success, $success_msg, $error_msg_1, $error_msg_2);
        }
      }
    }
  }
} # if (isset ( $_POST ['user'] ))
?>

<div class="result2 alert alert-info" style="display: none;"></div>    <!-- .result2 class updated by delete.php -->

    </div>  <!-- end div "col-xs-12" -->
    </div>  <!-- end div "row" -->

    <div class=row>
      <div class="col-xs-12 col-md-4">
        <h3>Create or update user:</h3>
        <form class="navbar-form navbar-left" action="index.php"
          method="post">
          <div class="form-group">
            <p>
              <input type="text" class="userfield form-control"
                placeholder="Username" name="user">
            </p>
          <?php
          if ($use_metadata) {
          ?>
            <p>
              <input class="emailfield form-control" type="email" name="email"
                placeholder="Email" />
            </p>
            <p>
              <input class="namefield form-control" type="text" name="name"
                placeholder="Real Name" />
            </p>
          <?php
          }
          ?>
          <p>
              <input class="passwordfield form-control" type="password"
                name="pwd" placeholder="Password" />
            </p>
          <p>
              <input class="passwordverifyfield form-control" type="password"
                name="pwd_verify" placeholder="Password Verify" />
            </p>
            <button type="submit" class="btn btn-default">Submit</button>
          </div>
        </form>

      </div>

      <div class="col-xs-12 col-md-6">
        <h3>Users:</h3>
      <?php
      # Get list of user account usernames:
      $users = $htpasswd->get_users ();

            #dbg_var_dump($users, "index.php");

      if ($use_metadata) {
        $meta_map = $htpasswd->get_metadata ();
      }

      include_once ("includes/user_table.php");

      if ($form_field_error) {
        # Reload the previously input 'user data' form field values:
        # (Call PHP, then Javascript function.)
        callSetUserField($username, $meta_model->email, $meta_model->name);
      }
      ?>
    </div>
    </div>
  </div>
<?php
include_once ('includes/footer.php');
?>
