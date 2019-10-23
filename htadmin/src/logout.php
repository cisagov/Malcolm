<?php
session_start();
include_once ('includes/head.php');
$_SESSION ['login'] = false;

include_once ('includes/nav.php');
?>

<div class="container box">
	<div class="row">
		<div class="col-xs-12">
			<h2>Logout</h2>
<div class="alert alert-info">
	<p>Logout successful.</p>
		</div>


</div>
</div>
</div>
<?php
include_once ('includes/footer.php');
?>