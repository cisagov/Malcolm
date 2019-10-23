<?php
include_once ('includes/checklogin.php');
include_once ('tools/htpasswd.php');
include_once ('includes/head.php');
include_once ('includes/nav.php');
include_once ('tools/util.php');

$htpasswd = new htpasswd ( $ini ['secure_path'], $ini ['metadata_path'] );
$metadata_path = $ini ['metadata_path'];
$use_metadata = !is_null_or_empty_string($metadata_path);

?>

<div class="container box">
	<div class="row">
		<div class="col-xs-12">
<?php

echo "<h2>" . $ini ['app_title'] . "</h2>";

if (isset ( $_POST ['user'] )) {
	$username = $_POST ['user'];
	$passwd = $_POST ['pwd'];
	if ($use_metadata) {
		$meta_model = new meta_model ();
		$meta_model->user = $username;
		$meta_model->email = $_POST ['email'];
		$meta_model->name = $_POST ['name'];
		$meta_model->mailkey = random_password(PASSWORD_LENGTH);
	}
	
	if (! check_username ( $username ) || ! check_password_quality ( $passwd )) {
		?>
			<div class="alert alert-danger">
			<?php
		echo "<p>User <em>" . htmlspecialchars ( $username ) . "</em> is invalid!.</p>";
	} else {
		?>
			<div class="alert alert-info">
			<?php
		if (! $htpasswd->user_exists ( $username )) {
			$htpasswd->user_add ( $username, $passwd );
			echo "<p>User <em>" . htmlspecialchars ( $username ) . "</em> created.</p>";
		} else {
			$htpasswd->user_update ( $username, $passwd );
			echo "<p>User <em>" . htmlspecialchars ( $username ) . "</em> changed.</p>";
		}
		if ($use_metadata) {
			if (! $htpasswd->meta_exists ( $username )) {
				$htpasswd->meta_add ( $meta_model );
			} else {
				$htpasswd->meta_update ( $meta_model );
			}
		}
	}
	
	?>
		</div>
    <?php
}
?>
<div class="result alert alert-info" style="display: none;"></div>

			</div>
		</div>
		<div class=row>
			<div class="col-xs-12 col-md-4">
				<h3>Create or update user:</h3>
				<form class="navbar-form navbar-left" action="index.php"
					method="post">
					<div class="form-group">
						<p>
							<input type="text" class="userfield form-control"
								placeholder="Username" name="user">
						</p>
					<?php
					if ($use_metadata) {
						?>
						<p>
							<input class="emailfield form-control" type="email" name="email"
								placeholder="Email" />
						</p>
						<p>
							<input class="namefield form-control" type="text" name="name"
								placeholder="Real Name" />
						</p>
					<?php
					}
					?>
					<p>
							<input class="passwordfield form-control" type="password"
								name="pwd" placeholder="Password" />
						</p>
						<button type="submit" class="btn btn-default">Submit</button>
					</div>
				</form>

			</div>

			<div class="col-xs-12 col-md-6">
				<h3>Users:</h3>
			<?php
			$users = $htpasswd->get_users ();
			if ($use_metadata) {
				$meta_map = $htpasswd->get_metadata ();
			}
			include_once ("includes/user_table.php");			
			?>			
		</div>
		</div>
		<div class=row>
			<br /> <br />
			<div class="col-xs-12 col-md-10 well">
				<p>
					Create new users for the htpasswd file here. A user can change
					his/her password with this <a href="selfservice.php">self service
						link.</a><br /> You can fill the username in the form if you add
					the url parameter user=&lt;username&gt;
				</p>
			</div>
		</div>
	</div>
<?php
include_once ('includes/footer.php');
?>
