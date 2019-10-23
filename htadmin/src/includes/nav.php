<?php
if (check_admin_login ()) {    # 'admin' user is logged in. Include code block below...
	?>
<nav class="navbar navbar-default">
	<div class="container">
		<div class="navbar-header">
			<ul class="nav navbar-nav navbar-left">
				<a class="navbar-brand" href="index.php"><span class="glyphicon glyphicon-home">&nbsp;</span>
				<?php
				echo $ini['app_title'];
	?>
				</a>
				<li><a href="admin_logout.php">Logout</a></li>
			</ul>
		</div>
	</div>
</nav>
<?php
} else {                  # The 'admin' user is NOT logged in. Display regular nav menu login options.
	?>
<nav class="navbar navbar-default">
	<div class="container">
		<div class="navbar-header">

			<ul class="nav navbar-nav navbar-left navbar-custom">    <!-- ul= unordered list -->
				<a class="navbar-brand" href="index.php"><span class="glyphicon glyphicon-home">&nbsp;</span>
				<?php
				echo $ini['app_title'];
	?>
				</a>
				<li><a href="admin_login.php">Administrator Login</a></li>
				<li><a href="selfservice.php">Account Self Service</a></li>
			</ul>
		</div>
	</div>
</nav>
<?php
}

?>
