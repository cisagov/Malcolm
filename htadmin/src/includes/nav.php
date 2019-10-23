<?php
if (check_login ()) {
	?>
<nav class="navbar navbar-default">
	<div class="container">
		<div class="navbar-header">
			<ul class="nav navbar-nav navbar-left">
				<a class="navbar-brand" href="index.php"><span
					class="glyphicon glyphicon-home">&nbsp;</span>
				<?php
	echo $ini['app_title'];
	?>
				</a>
				<li><a href="adminpwd.php">Admin password</a></li>
				<li><a href="logout.php">Logout</a></li>
				<li><a href="selfservice.php">User Self Service</a></li>
			</ul>
		</div>
	</div>
</nav>
<?php
} else {
	?>
<nav class="navbar navbar-default">
	<div class="container">
		<div class="navbar-header">

			<ul class="nav navbar-nav navbar-left">
				<a class="navbar-brand" href="index.php"><span
					class="glyphicon glyphicon-home">&nbsp;</span>
				<?php
	echo $ini['app_title'];
	?>
				</a>
				<li><a href="login.php">Login</a></li>
				<li><a href="selfservice.php">User Self Service</a></li>
				<li><a href="forgotten.php">Password forgotten</a></li>
			</ul>
		</div>
	</div>
</nav>
<?php
}

?>



