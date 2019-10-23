<?php
#
# This generates the HTML <head> section of several php pages.
# This pulls in Javascript and CSS style defin. files.
# This application used the 'bootstrap' CSS templating files.
# This page also defines the HTML <title> for the application.
#
include_once ('tools/util.php');
if (!isset($ini)) {                 # We haven't loaded the config/config.ini vars yet.
	$ini = read_config ();            # Read in the config.ini vars.
	#dbg_var_dump($ini);
}
# Turn on full PHP error reporting:
error_reporting(E_ALL);
?>

<html>
<head>
<!-- Latest compiled and minified CSS -->
<!-- <link rel="stylesheet" href="bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">  -->

<!-- We're currently using non-minified bootstrap.css files (so you can read them). -->
<link rel="stylesheet" href="bootstrap.css" crossorigin="anonymous">

<!-- Optional theme -->
<!-- <link rel="stylesheet" href="bootstrap-theme.min.css" integrity="sha384-fLW2N01lMqjakBkx3l/M9EahuwpSfeNvV63J5ezn3uZzapT0u7EYsXMjQV+0En5r" crossorigin="anonymous"> -->

<!-- Latest compiled and minified JavaScript -->
<script src="script/jquery-1.12.0.min.js"></script>
<script src="bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>
<script src="script/script.js"></script>
<link rel="stylesheet" href="styles/style.css">    <!-- These are local (overriding) css styles. -->

<!-- viewport: To ensure proper rendering and touch zooming. See 3.3.6 bootstrap docs -->
<meta name="viewport" content="width=device-width, initial-scale=1">

<title><?php echo $ini ['app_title']; ?></title>
</head>
<body>

