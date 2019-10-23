<?php
#
# Define a (class) data model for the user account data.
#
class meta_model {       # Meta-data for a user's account
	var $user;       # User's login username  (e.g. "joew")
	var $email;      # User's email address (e.g. joe_w@gmail.com)
	var $name;       # User's formal name (e.g. "Joe Wilson" )
	var $mailkey;    # User's temp. account reset password (sent via email) ??
}
?>
