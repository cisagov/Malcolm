<?php
include_once ('tools/util.php');
include_once ('tools/mail.php');
include_once ('tools/htpasswd.php');
include_once ('includes/head.php');
include_once ('includes/nav.php');

$htpasswd = new htpasswd ( $ini ['secure_path'], $ini ['metadata_path'] );

$protocol = strpos ( strtolower ( $_SERVER ['SERVER_PROTOCOL'] ), 'https' ) === FALSE ? 'http' : 'https';
$host = $_SERVER ['HTTP_HOST'];
$script = $_SERVER ['SCRIPT_NAME'];
$params = $_SERVER ['QUERY_STRING'];
$mailUrl = $protocol . '://' . $host . $script;
$show_standardform = true;

?>
<div class="container box">
	<div class="row">
		<div class="col-xs-12">
		<?php
		if (isset ( $_POST ['email'] )) {
			$email = $_POST ['email'];
			$user = $htpasswd->meta_find_user_for_mail ( $email );
			if (! isset ( $user )) {
				$alert_class = "alert-danger";
				$alert_message = "Email not found: " . htmlspecialchars ( $email );
				include_once ('includes/inline_message.php');
			} else {
				$meta_models = $htpasswd->get_metadata ();
				$meta_model = $meta_models [$user];
				$link = $mailUrl . '?' . 'user=' . urldecode ( $user ) . '&' . 'key=' . urlencode ( $meta_model->mailkey );
				send_forgotten_mail ( $email, $meta_model->name, $link );
				$alert_class = "alert-info";
				$alert_message = "Email successfully sent. Please check your inbox. " . htmlspecialchars ( $email );
				include_once ('includes/inline_message.php');
			}
		}
		
		if (isset ( $_GET ['user'] ) && isset ( $_GET ['key'] )) {
			$user = $_GET ['user'];
			$key = $_GET ['key'];
			$meta_models = $htpasswd->get_metadata ();
			$meta_model = $meta_models [$user];
			if (isset ( $meta_model ) && $meta_model->mailkey === $key) {
				$show_standardform = false;
				?>
			<div class=row>
				<div class="col-xs-12 col-md-4">
					<h3>Reset Password:</h3>
					<form class="navbar-form navbar-left" action="forgotten.php"
						method="post">
						<div class="form-group">
							<p>
								<input type="password" class="userfield form-control"
									placeholder="Password" name="pwd">
							</p>
							<input type="hidden" class="userfield form-control"
								placeholder="Password" name="user"
								value='<?php echo htmlspecialchars($user);?>'> <input
								type="hidden" class="userfield form-control"
								placeholder="Password" name="key"
								value='<?php echo htmlspecialchars($key);?>'>


							<button type="submit" class="btn btn-default">Submit</button>
						</div>
					</form>

				</div>
			</div>				
				<?php
			} else {
				$alert_class = "alert-danger";
				$alert_message = "Security problem detected, can not display password change form.";
				include_once ('includes/inline_message.php');
			}
		}
		
		if (isset ( $_POST ['user'] ) && isset ( $_POST ['key'] ) && isset ( $_POST ['pwd'] )) {
			$user = $_POST ['user'];
			$key = $_POST ['key'];
			$pwd = $_POST ['pwd'];
			$meta_models = $htpasswd->get_metadata ();
			$meta_model = $meta_models[$user];
			if (isset ( $meta_model ) && $meta_model->mailkey === $key) {
				$htpasswd->user_update ( $user, $pwd );
				$meta_model->mailkey = random_password ( PASSWORD_LENGTH );
				$htpasswd->meta_update ( $meta_model );
				$alert_class = "alert-info";
				$alert_message = "Password changed.";
				include_once ('includes/inline_message.php');
			} else {
				$alert_class = "alert-danger";
				$alert_message = "Could not reset password.";
				include_once ('includes/inline_message.php');
			}
		}
		if ($show_standardform) {
			?>
			<div class=row>
				<div class="col-xs-12 col-md-4">
					<h3>Password forgotten?</h3>
					<form class="navbar-form navbar-left" action="forgotten.php"
						method="post">
						<div class="form-group">
							<p>
								<input type="text" class="userfield form-control"
									placeholder="Email" name="email">
							</p>

							<button type="submit" class="btn btn-default">Submit</button>
						</div>
					</form>

				</div>
			</div>
		</div>
	</div>
</div>

<?php
		}
		?>
