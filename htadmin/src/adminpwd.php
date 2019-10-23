<?php
include_once ('includes/checklogin.php');
include_once ('includes/head.php');
include_once ('includes/nav.php');
include_once ('tools/htpasswd.php');

?>

<div class="container box">
	<div class="row">
		<div class="col-xs-12">
			<h2>Create Admin Password Hash</h2>
			<?php 
			
			if (isset ( $_POST ['pwd'] )) {
				?>
					<div class="alert alert-info">
					<?php
					echo "<p>Your new hash: <code>" . htpasswd::htcrypt($_POST['pwd']) . "</code></p>";
					?>
						</div>
				    <?php
			
			}
				
			?>
<p>Create a new password hash for the config file:</p>
<form class="navbar-form navbar-left" action="adminpwd.php" method="post">
				<div class="form-group">
					<p>
						<input class="form-control" type="password" name="pwd"
							placeholder="Password" />
					</p>
					<button type="submit" class="btn btn-default">Submit</button>
				</div>
			</form>
			
		</div>
	</div>
		<div class=row>
	<br/><br/>
		<div class="col-xs-12 col-md-10 well">
			<p>Use this generated hash in <code>config/config.ini</code> for the <code>admin_pwd_hash</code> key.</p>
		</div>
	</div>
</div>

<?php
include_once ('includes/nav.php');
include_once ('includes/footer.php');
?>
