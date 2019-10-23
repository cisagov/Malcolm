<?php
#
# PHP Page to delete a user account and related metadata fields.
#
# Note: You -must- return response strings as formatted below..so that the
#   (Javascript) caller can properly parse the genereated pseudo response page.
#

/* DBG: if page is started from the command line, wrap passed parameters to $_POST and $_GET */
if (!isset($_SERVER["HTTP_HOST"])) {
  parse_str($argv[1], $_GET);
  parse_str($argv[1], $_POST);
}

session_start();
include_once("tools/util.php");

if (!check_admin_login()) {
  echo "error|Error: Only the system administrator is authorized to perform this operation.";
  die();
}

include_once ('tools/dbg_log.php');
include_once ('tools/htpasswd.php');

$ini           = read_config();           # Read in the config.ini file array
$metadata_path = $ini ['metadata_path'];
$use_metadata  = !is_null_or_empty_string($metadata_path);

$htpasswd      = new htpasswd ( $ini ['secure_path'], $metadata_path );

if (isset ( $_POST['user'] )) {
  $user = $_POST['user'];      # Load the username
  $del_error_msg = "";
  $meta_error_msg = "";

  if ($htpasswd->user_delete($user, $del_error_msg)) {

    if ($use_metadata) {

      if ($htpasswd->meta_delete($user, $meta_error_msg)) {
        echo "success|User account successfully deleted.";

      } else{
        echo "error|Error deleting user account metadata. (" . $meta_error_msg . ")";
      }

    } else {
     echo "error|Error \$use_metadata is set to False.";
    }

  } else {
    echo "error|Error deleting user account from htpasswd file. (" . $del_error_msg . ")";
  }

} else {
  echo "error|Logic error: user account entry not found in \$_POST[] array!";
}
?>
