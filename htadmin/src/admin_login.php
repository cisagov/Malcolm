<?php                             # File admin_login.php:  Start PHP code block
session_start();                  # Start PHP session (Create $_SESSION[] store )
$_SESSION ['admin_login'] = false;                    # Mark the $_SESSION as (admin)    logged-out

include_once ('tools/util.php');
include_once ('tools/htpasswd.php');

$ini = read_config();             # Read in this application's 'config.ini' file into the $ini array

$htpasswd_path = $ini ['secure_path'];

if (! file_exists ( $htpasswd_path )) {
  $error_msg = "Error: htpasswd_path: " . $htpasswd_path . ", does not exist!";
  phpAlert($error_msg);
  dbg_print($error_msg, "admin_login.php");
  $error_msg = "(1) Exiting current web page!";
  dbg_print($error_msg);
  die ();                                        # No more output from this page
}

$htpasswd = new htpasswd ( $ini ['secure_path'] );

if ($htpasswd->no_htpasswd_file() ) {
  # Added the secondary check to prevent further execution.
  $error_msg = "Error: htpasswd_path: " . $htpasswd_path . ", does not exist!";
  dbg_print($error_msg, "admin_login.php");
  $error_msg = "(2) Exiting current web page!";
  dbg_print($error_msg);
  die ();                                        # No more output from this page
}

$not_report_errors = False;

if (isset ( $_POST ['user'] ) && isset ( $_POST ['password'] )) {    # User POSTed this admin_login.php page w/ $_POST[] array
  $username = $_POST ['user'];
  $password = $_POST ['password'];

  $error_msg = "";

  # Check the username -and- the htpasswd file entry for the 'admin' user account:
  if (( $username == $ini['admin_user']) &&
        ( $htpasswd->user_login_check ( $username, $password, $error_msg ))) {

    $_SESSION ['admin_login'] = true;                    # Mark the $_SESSION as (admin) active
                # Uncomment the following line and comment out the 'header()' call, to see the login creds.
                #echo "<p>" . "DBG: username=" . $username . "; password=" . $password . "</p>";
                #echo  "<p>";
                #print_r($ini);
                #echo  "</p>";

    header ( 'LOCATION:index.php' );               # Redirect the user's browser to our index.php page
    die ();                                        # No more output from this page

  } else if ($username != $ini['admin_user'])  {
    $error = "Error: Invalid administrator account username.";

  } else {
    # NOTE: Only the admin user should be able to login to the htadmin admin_login.php web page.
    #
    $error = $error_msg;      # Else, invalid password entered. Load $error var below.. to display on next form.
  }

}

include_once ('includes/head.php');                      # Load the 'HTML page' header lines
include_once ('includes/nav.php');                       # Load the 'HTML page' navigation-bar menu

# end php
?>

<div class="container box">
  <div class="row">
    <div class="col-xs-12">
      <h2>Administrator Login:</h2>
<?php  # start php

if (isset ( $error )) {    # The $_POST array was received (with the current page request)

  ?>                               <!-- end php -->
<div class="alert alert-danger">   <!-- This <div> is always output -->
  <?php
  echo "<p>" . $error . "</p>";    # Display the pink $error msg box above the "Login:" field
  ?>
    </div>
<?php
}
?>

<!-- The following HTML form POSTS vars to this same file (i.e. "admin_login.php") when the user clicks on the form "submit" button.  -->
<!-- If the user has entered the correct 'admin' account password, the '( $_POST ['user'] )' check at the top of the -->
<!-- page redirects us to the 'index.php' page (and lets us into the rest of the application's pages) -->
<!-- The index.php (via check_admin_login.php) page checks to see if there is an active PHP session at the top of that page.  If there is no session, -->
<!-- the user is redirected back to this admin_login.php page. -BDR -->

<form class="navbar-form navbar-left" action="admin_login.php" method="post">
  <div class="form-group">
    <input type="text" class="form-control" placeholder="Username" name="user">
    </p>
    <p>
    <input class="form-control" type="password" name="password" placeholder="Password" />
    </p>
    <button type="submit" class="btn btn-default">Login</button>
  </div>

</form>

</div>    <!-- end class="col-xs-12" -->
</div>    <!-- end class="row" -->
</div>    <!-- end class="container box" -->
<?php
include_once ('includes/footer.php');    # The </body></html>
?>
