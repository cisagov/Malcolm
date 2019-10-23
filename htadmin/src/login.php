<?php
session_start();
include_once ('tools/util.php');
include_once ('tools/htpasswd.php');
$ini = read_config();

if (isset ( $_POST ['user'] ) && isset ( $_POST ['password'] )) {
	$username = $_POST ['user'];
	$password = $_POST ['password'];
	
	if ($username == $ini['admin_user'] && htpasswd::check_password_hash($password,$ini['admin_pwd_hash'])) {
		$_SESSION ['login'] = true;
		header ( 'LOCATION:index.php' );
		die ();
	}

	$error = 'Invalid user or password!';

} 


include_once ('includes/head.php');
include_once ('includes/nav.php');


?>

<div class="container box">
	<div class="row">
		<div class="col-xs-12">
			<h2>Please Login:</h2>
<?php


if (isset ( $error )) {
	
	?>
<div class="alert alert-danger">
	<?php
	echo "<p>" . $error . "</p>";
	?>
		</div>
<?php
}
?>

<form class="navbar-form navbar-left" action="login.php" method="post">
	<div class="form-group">
		<p>Login:</p>
		<input type="text" class="form-control" placeholder="Username"
			name="user">
		</p>
		<p>
			<input class="form-control" type="password" name="password"
				placeholder="Password" />
		</p>
		<button type="submit" class="btn btn-default">Login</button>
	</div>

</form>

</div>
</div>
</div>
<?php
include_once ('includes/footer.php');
?>
