<?php
require 'phpmailer/PHPMailerAutoload.php';
include_once ('tools/util.php');


function send_forgotten_mail($email, $name, $link) {
	if (!isset($ini)) {
		$ini = read_config ();
	}
	$mail = new PHPMailer ();
	
	$mail->isSMTP (); // Set mailer to use SMTP
	
	$mail->Host = $ini ["mail_server"]; // Specify main and backup SMTP servers
	$mail->SMTPAuth = true; // Enable SMTP authentication
	$mail->Username = $ini ["mail_user"]; // SMTP username
	$mail->Password = $ini ["mail_pwd"]; // SMTP password
	//$mail->SMTPSecure = 'ssl'; // Enable encryption, 'ssl' also accepted
	$mail->Port = $ini ["mail_port"];
	
	$mail->From = $ini ["mail_from"];
    $mail_from_name = 'HTAdmin';
    if (!is_null_or_empty_string($ini ['mail_from_name'])) {
        $mail_from_name = $ini ['mail_from_name'];
    }
	$mail->FromName = $mail_from_name;
	$mail->addAddress ( $email ); // Add a recipient
	
	$mail->Subject = 'Reset password';

    $mail->isHTML(true);
    $mail->Body = '<p>Hello, ' . $name . '! ' .
        'You can reset your password with <a href="' . $link . '">this</a> link.</p>';
    $mail->AltBody = 'Hello, ' . $name . '! ' .
        'You can reset your password with this link: ' . $link;
    $mail->CharSet = 'utf-8';
	//$mail->SMTPDebug = 2;
	
	if (! $mail->send ()) {
		return false;
	} else {
		return true;
	}
}

?>
