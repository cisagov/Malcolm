<?php
session_start();
include_once("tools/util.php");
if (!check_login()) {
	echo "unauthorized";
	die();
}
include_once ('tools/htpasswd.php');
$ini = read_config();
$metadata_path = $ini ['metadata_path'];
$use_metadata = !is_null_or_empty_string($metadata_path);

$htpasswd = new htpasswd ( $ini ['secure_path'], $metadata_path );

if (isset ( $_POST['user'] )) {
	$user = $_POST['user'];
	if ($htpasswd->user_delete($user)) {
		if ($use_metadata) {
			$htpasswd->meta_delete($user);
		}
		echo "success";
	} else {
		echo "error";
	}
	
} else {
	echo "error";
}
?>
