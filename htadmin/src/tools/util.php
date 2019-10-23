<?php    # util.php: Utility functions

function check_admin_login() {
        #return true;
        # Return true, if the 'admin' user is logged in.
    if (isset($_SESSION['admin_login']) && $_SESSION ['admin_login'] === true) {
        return true;
    }

    return false;
}

function read_config() {    # Read in the config.ini file into an array
    return parse_ini_file('config/config.ini');
}

function check_password_quality($passwd, $min_password_len, $max_password_len, &$error_msg) {
    # See if the $passwd passes all quality checks.
    #   The &$error_msg is pass-by-reference.
    $error_msg = '';

    if (!isset($passwd) || (strlen($passwd) < $min_password_len)) {
        #phpAlert("Error min_password_len=" . $min_password_len . " test.");
        $error_msg = "<p>Error: User's password is less than (" . $min_password_len . ") chars long.</p>";
        return false;
    } elseif (strlen($passwd) > $max_password_len) {
        #phpAlert("Error max_password_len=" . $max_password_len . " test.");
        $error_msg = "<p>Error: User's password is greater than (" . $max_password_len . ") chars long.</p>";
        return false;
    }

    return true;
}

function check_username_quality($username, $min_username_len, $max_username_len, &$error_msg) {
    $error_msg = '';

    if (!isset($username) || strlen($username) < $min_username_len) {
        #phpAlert("Error min_username_len=" . $min_username_len . " test.");
        # <em> Means use emphasis (italics).
        $error_msg = "<p>Error: Username '<em>" . htmlspecialchars ( $username ) .  "</em>' is invalid!. Minimum length is (" . $min_username_len . ") characters long.";
        return false;
    } elseif (strlen($username) > $max_username_len) {
        #phpAlert("Error max_username_len=" . $max_username_len . " test.");
        $error_msg = "<p>Error: username '<em>" . $username . "</em>' is greater than (" . $max_username_len . ") characters long.</p>";
        return false;
    }

    $reg_ok = preg_match('/^[a-zA-Z][a-zA-Z0-9_\-.]+$/', $username);

    if (! $reg_ok) {
        #phpAlert("Error in username_legal_chars test.");
        $error_msg = "Error: username '" . $username . "'  must start with an alpha character; Allowed special chars are: -, _</p>";
    }
    return $reg_ok;
}

const PASSWORD_LENGTH = 24;

function random_password($length) {
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNPQRSTUVWXYZ1234567890';
    $pass = array();                      //remember to declare $pass as an array
    $alphaLength = strlen($alphabet) - 1; //put the length -1 in cache
    for ($i = 0; $i < $length; $i++) {
        $n = rand(0, $alphaLength);    # 0=min. value; $alphaLength= max value;
        $pass[] = $alphabet[$n];
    }
    return implode($pass);   //turn the array into a string
}

function is_null_or_empty_string($str){
     # Return True, if the $str is: 1) not set; 2) Contains only whitespace chars;
     # 3) contains no chars
    return (!isset($str) || trim($str) === '');
}

function echo_alert_danger_div($div_id){
    # Output a boostrap alert-danger type div. Assign it a unique 'id' value
    # so you can find it in the generated HTML code.
    echo '<div class="result alert alert-danger" id="' . $div_id . '">';
}

function echo_alert_info_div($div_id){
    # Output a boostrap alert-info type div. Assign it a unique 'id' value
    # so you can find it in the generated HTML code.
    echo '<div class="result alert alert-info" id="' . $div_id . '">';
}


function echo_approp_div_msg($funct_success, $success_msg, $error_msg_1, $error_msg_2) {
    #
    # If $funct_success is True: (i.e. previous function call was successful)
    #    Output the $sucess_msg with the appropriate Bootstrap 'alert' type  (i.e. alert-info)
    # else
    #    Output the $error_msg_1, $error_msg_2 error strings with the approp Bootstrap
    #    'alert' type (i.e. alert-danger)
    #
    # Wrap each output message in an HTML <div></div> -and- <p></p> (paragraph) tag set.)
    #
    # (Code after this function call will output the closing </div> HTML tag.
    #
    if ($funct_success) {
        $div_id = "echo_approp_div_msg_on_success";
        echo_alert_info_div($div_id);
        echo "<p>" . $success_msg . "</p>";
        echo "</div>";
    } else {
        $div_id = "echo_approp_div_msg_on_error";
        echo_alert_danger_div($div_id);
        echo "<p>" . $error_msg_1 . '   (' . $error_msg_2 . ")</p>";
        echo "</div>";
    }
}


function bool_to_string($bool_value) {
    # Convert the $bool_value to the appropriate string value.
    # (The PHP strval() converts a boolean False value to the "" string. Not what we need.)
    #
    if ($bool_value) {
        return "True";
    } else {
        return "False";
    }
}


function array_to_string($array_in, $field_sep="") {
    # Conver the passed in $array_in array to a string.
    #   $array_in: The user supplied array
    #   $field_sep: (Optional) array field separator
    #
    $new_str = join($field_separator, $array_in);
    return $new_str;
}

function error_get_last_as_str () {
    # Call PHP error_get_last() to get the last recorded PHP error message.
    # Convert the array returned by error_get_last() into a string and
    # return it.
    $last_error_array = error_get_last();

    if (array_key_exists("message", $last_error_array) ) {
        # Extract just the array 'message' value:
        $message = "message=";
        $message = $message . $last_error_array["message"];

        if (array_key_exists("file", $last_error_array) ) {
            $file    = $last_error_array["file"];
            $message = $message . "; file=" . $file;
        }

        if (array_key_exists("line", $last_error_array) ) {
            $line    = $last_error_array["line"];
            $message = $message . "; line=" . $line;
        }

        # Return a formatted message:
        return $message;
    }

    # Else, dump the entire raw array:
    return array_to_string( $last_error_array, "," );
}



function phpAlert($msg) {
    # Display a Javascript popup dialog and display the passed in $msg.
    #
    echo '<script type="text/javascript">alert("' . $msg . '")</script>';
}


function callSetUserField($user, $email, $name ) {
    # Call a Javascript function 'setUserField()':
    # The $( ) jquery function will cause the called Javascript function to be
    # called after the page loads.
    echo '<script type="text/javascript">$(function () {setUserField("' . $user . '",' . '"' . $email . '",' . '"' . $name . '");})</script>';
}

function set_new_value_or_default($value, $default_value) {
    # If the $value is null, or an empty string, return
    # the $default_value.  Else, return the new $value.
    #
    if (is_null_or_empty_string($value)){
      return $defalt_value;
    } else {
      return $value;
    }
}


function dbg_print($msg, $caller=""){
    # Prints the passed in $msg string.
    #   $msg: Message to be printed
    #   $caller:    Calling src file or procedure name.
    #

    echo "<pre>";

    if (strlen($caller) > 0) {
      echo "<p>caller: " . $caller . "</p>";
    }
    print($msg);
    echo "</pre>";
}

function dbg_print_r($array_obj, $caller=""){
    # Prints the passed in array in a vertical format.  Array value 'types'
    # are not # included in the output stream. (See the dbg_var_dump()  proc.)
    # (The HTML <pre> tag preserves whitespace and line breaks and uses a fixed width font.)
    #   $array_obj: Array object to print.
    #   $caller:    Calling src file or procedure name.
    #
    echo "<pre>";

    if (strlen($caller) > 0) {
      echo "<p>caller: " . $caller . "</p>";
    }
    print_r($array_obj);
    echo "</pre>";
}

function dbg_var_dump($array_obj, $caller=""){
    # Prints the passed in array in a vertical format.  Array value 'types'
    # -are- included in the output
    # (The HTML <pre> tag preserves whitespace and line breaks and uses a fixed width font.)
    #   $array_obj: Array object to print.
    #   $caller:    Calling src file or procedure name.
    #
    echo "<pre>";

    if (strlen($caller) > 0) {
      echo "<p>caller: " . $caller . "</p>";
    }
    var_dump($array_obj);
    echo "</pre>";
}

?>
