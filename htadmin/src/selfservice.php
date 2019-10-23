<?php
session_start();
include_once ('tools/htpasswd.php');
include_once ('includes/head.php');
include_once ('includes/nav.php');

$htpasswd = new htpasswd ( $ini ['secure_path'] );

?>

<div class="container box">
	<div class="row">
		<div class="col-xs-12">
		<h2>Change your password here:</h2>
<?php
$equal = true;
$success = false;
if (isset ( $_POST ['user'] ) && isset ( $_POST ['oldpwd'] ) && isset ( $_POST ['newpwd'] ) && isset ( $_POST ['newpwd2'] )) {
	$username = $_POST ['user'];
	$old = $_POST ['oldpwd'];
	$new = $_POST ['newpwd'];
	$new2 = $_POST ['newpwd2'];
	
	if ($new == $new2 && $htpasswd->user_check ( $username, $old )) {
		$htpasswd->user_update ( $username, $new );
		?>
			<div class="alert alert-info">Password changed successfully.</div>
		<?php
	} else {
		?>
				<div class="alert alert-danger">Could not change password.</div>
				<?php
	}
}

?>
<div class="result alert alert-info" style="display: none;"></div>

		</div>
	</div>
	<div class=row>
		<div class="col-xs-12 col-md-4">
			<form class="navbar-form navbar-left" action="selfservice.php"
				method="post">
				<div class="form-group">

					<input type="text" class="userfield form-control"
						placeholder="Username" name="user" <?php if (isset($_GET['user'])) echo "value=".htmlspecialchars($_GET['user']);?>>
					</p>
					<p>
						<input class="passwordfield form-control" type="password"
							name="oldpwd" placeholder="Old Password" <?php if (isset($_GET['user'])) echo "autofocus" ?>/>
					</p>
					<p>
						<input class="passwordfield form-control" type="password"
							name="newpwd" placeholder="New Password" />
					</p>
					<p>
						<input class="passwordfield form-control" type="password"
							name="newpwd2" placeholder="Repeat new Password" />
					</p>
					<button type="submit" class="btn btn-default">Change</button>
				</div>
			</form>

		</div>


	</div>
	<p>Forgot your password? Click <a href="forgotten.php">here</a>.
		<div class=row>
	<br/><br/>
		<div class="col-xs-12 col-md-10 well">
			<p>Note: You can't change the admin password here. This is only for user passwords.</p>
		</div>
	</div>
</div>
<?php
include_once ('includes/footer.php');
?>
