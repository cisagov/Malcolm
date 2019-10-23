<?php
/**
 * This page Redirects to the admin_login.php page, if an admin user is not already logged in.
 */
session_start();

include_once("tools/util.php");

# The check_admin_login() funct. is located in the util.php file. This funct. will check
# the $_SESSION[] array 'admin_login' key value.

if (!check_admin_login()) {
    phpAlert("User is not logged in yet.");
	header('LOCATION:admin_login.php');    # Redirect the admin user back to the admin_login.php
	die();                                 #
}
?>
