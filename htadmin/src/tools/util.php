<?php
function check_login() {
	if (isset($_SESSION['login']) && $_SESSION ['login'] === true) {
		return true;
	}
	return false;
}

function read_config() {
	return parse_ini_file('config/config.ini');
}

function check_password_quality($pwd) {
	if (!isset($pwd)||strlen($pwd)<4) {
		return false;
	}
	return true;
}

function check_username($username) {
	if (!isset($username)||strlen($username)>20 || strlen($username)<3) {
		return false;
	}
	return preg_match('/^[a-zA-Z][a-zA-Z0-9_\-.]+$/', $username);

}

const PASSWORD_LENGTH = 24;

function random_password($length) {
	$alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ1234567890';
	$pass = array(); //remember to declare $pass as an array
	$alphaLength = strlen($alphabet) - 1; //put the length -1 in cache
	for ($i = 0; $i < $length; $i++) {
		$n = rand(0, $alphaLength);
		$pass[] = $alphabet[$n];
	}
	return implode($pass); //turn the array into a string
}

function is_null_or_empty_string($str){
    return (!isset($str) || trim($str) === '');
}

?>
