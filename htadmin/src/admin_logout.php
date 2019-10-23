<?php
#
# Logout admin user.
#
session_start();
include_once ('includes/head.php');
$_SESSION ['admin_login'] = false;       # Mark the admin user as logged out.

include_once ('includes/nav.php');
?>

<div class="container box">
	<div class="row">
		<div class="col-xs-12">
			<h2>Logout</h2>
			<div class="alert alert-info">
				<p>Administrator logout successful.</p>
			</div>
		</div>
	</div>
</div>
<?php
include_once ('includes/footer.php');
?>
