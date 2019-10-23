<?php
# htpasswd.php

include_once ("model/meta_model.php");
include_once ("tools/util.php");
include_once ("tools/dbg_log.php");

/**
 * htpasswd tools for 'Apache Basic Authentication'
 *
 * Uses crypt only!
 */

class htpasswd {

    var $fp;            # File pointer;
    var $metafp;        # Meta-data file file pointer;
    var $filename;      # Path to password file
    var $metafilename;  # Path to user's formal name, email address.

    function htpasswd( $htpasswdfile, $metadata_path = "") {
      @$this->fp = @$this::open_or_create ( $htpasswdfile );

      if (!is_null_or_empty_string($metadata_path)) {
        @$this->metafp = @$this::open_or_create ( $metadata_path );
        $this->metafilename = $metadata_path;
      }

      $this->filename = $htpasswdfile;
    } # htpasswd

    function no_htpasswd_file() {
      if ($this->fp == False) {
        # There is no htpasswd file
        return True;
      }
      return False;
    } # no_htpasswd_file

    function user_exists($username) {                   # Username exists in the ->fp file.
      return self::exists ( @$this->fp, $username );    # Call the class level function
    } # user_exists

    function meta_exists($username) {                   # Username exists in metadata file.
      return self::exists ( @$this->metafp, $username );
    } # meta_exists

    function meta_find_user_for_mail($email) {
      # Get username associated with passed in $email address.

      while ( ! feof ( $this->metafp ) && $meta = explode ( ":", $line = rtrim ( fgets ( $this->metafp ) ) ) ) {
        if (count ( $meta ) > 1) {
          $username = trim ( $meta [0] );
          $lemail = $meta [1];

          if ($lemail == $email) {
            return $username;
          }
        }
      }
      return null;
    } # meta_find_user_for_mail

    function get_metadata() {
      # Load a new 'meta_model' object for each username into the returned $meta_model_map array.
      # Each meta_model object contains a: username, user's email address, and user's mailkey.

      rewind ( $this->metafp );
      $meta_model_map = array ();
      $metaarr        = array ();

      while ( ! feof ( $this->metafp ) && $line = rtrim ( fgets ( $this->metafp ) ) ) {
        $metaarr = explode ( ":", $line );
        $model   = new meta_model ();
        $model->user = $metaarr [0];

        if (count ( $metaarr ) > 1) {
          $model->email = $metaarr [1];
        }

        if (count ( $metaarr ) > 2) {
          $model->name = $metaarr [2];
        }

        if (count ( $metaarr ) > 3) {
          $model->mailkey = $metaarr [3];
        }

        $meta_model_map [$model->user] = $model;
      }

      return $meta_model_map;
    } # get_metadata

    function get_users() {
      # Return an array of usernames.  (The array is indexed from 0..N-1 users.)

      rewind ( $this->fp );    # $this->fp is handle to the htpasswd file
      $users = array ();
      $i     = 0;

      # fgets() - Get line of text from file;  rtrim() - Trim off trailing whitespace;
      # explode() -  Split string into an array; ":" is delimitter;
      # array_shift() - Shift off first element of array and return it; Shortens orig array by one element;
      # trim() - Remove leading/trailing whitespace from $param;

      while ( ! feof ( $this->fp ) && trim ( $lusername = array_shift ( explode ( ":", $line = rtrim ( fgets ( $this->fp ) ) ) ) ) ) {
        $users [$i] = $lusername;
        $i ++;
      }

      return $users;
    } # get_users

    function user_add($username, $password, &$error_msg) {
      # Added a new $username, $password to the htpasswd file.
      # Return True, if successful.
      # Return False if a $username already exists.

      $error_msg = "";

      if (self::exists ( @$this->fp, $username )) {
        $error_msg = "Error: username already exists in htpasswd file.";
        return false;
      }

      $i_result = fseek ( $this->fp, 0, SEEK_END );
      if ($i_result == -1) {
        # File seek error.
        $error_msg = "Error: htpassword file seek error.";
        return false;
      }

      # Add the username and password hash to the htpasswd file.
      $i_result = fwrite ( $this->fp, $username . ':' . self::htcrypt ( $password ) . "\n" );

      if ($i_result == False) {
        # htpasswd file write error.
        $last_error_msg = error_get_last_as_str();
        $error_msg   = "Error: htpasswd file write error. last_error_msg: " . $last_error_msg;
        return false;
      }

      return true;
    } # user_add

    function meta_add(meta_model $meta_model, &$error_msg) {
      # Add user's metadata fields to the metadata file.
      # (e.g. 'Real Name', 'Email addr' )
      #
      # $error_msg- can be updated by this function.

      if (self::exists ( @$this->metafp, $meta_model->user )) {
        $error_msg = "Error: username already exists in metadata file.";
        return false;
      }

      $i_result = fseek ( $this->metafp, 0, SEEK_END );
      if ($i_result == -1) {
        # File seek error.
        $error_msg = "Error: metadata file seek error.";
        return false;
      }

      $i_result = fwrite ( $this->metafp, $meta_model->user . ':' . $meta_model->email . ':' .  $meta_model->name . ':' . $meta_model->mailkey . "\n" );

      if ($i_result == False) {
        # File write error.
        $last_error_msg = error_get_last_as_str();
        $error_msg   = "Error: metadata file write error. last_error_msg: " . $last_error_msg;
        return false;
      }

      return true;
    } # meta_add


    /**
     * User Login credentials check.
     * Note: The first 2 characters of the password hash is the salt.
     *
     * Each htpasswd entry looks something like this:
     *   bras:$2y$20$4MQ.fMF7Vmncm8eJ/1959..SGn/2UDcS1HWSHWNX6LzOFv/W4sRYG
     *
     * @param $username (The user entered username string)
     * @param $password (The user entered password string)
     * @param $error_msg (If the function returns False, an error message describing
     *                    the error.)
     *
     * @return boolean True if: user exists and  password is correct.
     *         Else, if the username is not found, or the password doesn't match, or is
     *         errors.
     */
    function user_login_check($username, $password, &$error_msg) {
      #phpAlert("user_login_check: Enter proc.:");
      rewind ( $this->fp );    # Move read ptr to start of the file
      $error_msg      = "";
      $username_found = False;

      #$dbg_log_h = new dbg_log("user_debug_log.txt");

      while ( ! feof ( $this->fp ) ) {
        $line = fgets( $this->fp );

        if (strlen($line) == 0) {
          #$dbg_log_h->log_msg("Dbg: (0) Read \$line='" . $line . "'");
          break;      # fgets() returned "";
        }

        #phpAlert("TEST Alert.");
        #$dbg_log_h->log_msg("Dbg:(1) Read \$line='" . $line . "'");

        $line             = rtrim($line);
        $user_passw_array = explode ( ":", $line);
        $lusername        = trim ( $user_passw_array [0] );

        if (strlen($lusername) == 0) {
          if ($report_errors) {
            $error_msg = ("Error: Missing username field found in password file.");
          }

          return False;
        }

        #phpAlert("Dbg:(2) Read \$line='" . $line . "'");
        #phpAlert("Dbg: sizeof(\$user_passw_array)=" . sizeof($user_passw_array));

        if (sizeof($user_passw_array) < 2) {
          $error_msg = ("Error: Missing/corrupt user password hash found in password file.");

          return False;
        }

        if (strlen($user_passw_array[1]) == 0) {
          $error_msg = ("Error: Missing user password hash found in password file.");

          return False;
        }


        $hash = trim ($user_passw_array [1] );   # 2nd field is the passw hash.

        if ($lusername == $username) {
          $username_found = True;
          break;
        }
      } # endwhile

      if ($username_found) {
        $valid_creds = self::check_password_hash($password, $hash);

        if ($valid_creds) {
          return True;
        } else {
          $error_msg = ("Error: Incorrect username or password entered.");
          #phpAlert("Returned error_msg=" . $error_msg);

          if ($username_found) {
              #phpAlert("DBG: username was valid.");   # @@ Disable line in production code
          }

          return False;
        }

      }

      $error_msg = ("Error: username: " . $username . " was not found in the password file.");
      return False;
    } # user_login_check


    function user_delete($username, &$error_msg) {
      # Delete username's data from the htpasswd file.
      # Return True, if successful.
      # Return False on error..and load the applicable $error_msg.

      return self::delete ( @$this->fp, $username, @$this->filename, $error_msg);
    } # user_delete


    function meta_delete($username, &$error_msg) {
      # Delete username's data from the metadata file.
      # Return True, if successful.
      # Return False on error..and load the applicable $error_msg.
      return self::delete ( @$this->metafp, $username, @$this->metafilename, $error_msg );
    } # meta_delete


    function user_update($username, $password, &$error_msg) {

      $error_msg = '';

      rewind ( $this->fp );

      while ( ! feof ( $this->fp ) && trim ( $lusername = array_shift (
          explode ( ":", $line = rtrim ( fgets ( $this->fp ) ) ) ) ) ) {
          if ($lusername == $username) {
              fseek ( $this->fp, (- 1 - strlen($line)), SEEK_CUR );
              $tmp_error_msg = '';
              $success = self::delete($this->fp, $username, $this->filename, $tmp_error_msg, false);
              if ($success) {
                file_put_contents ($this->filename,
                    $username . ':' . self::htcrypt ( $password ) . "\n" ,
                    FILE_APPEND | LOCK_EX);
                return true;
              } elseif ($error_msg != '') {
                $error_msg = $tmp_error_msg;
              }
          }
      }
      $error_msg = "Error deleting existing username: " . $username . " (".$error_msg.")";
      return false;
    } # user_update

    function meta_update(meta_model $meta_model, &$error_msg) {
        # Delete the $meta_model defined username data.
        # Then, add the new username data to the metadata file.

        $success = $this->meta_delete ( $meta_model->user, $error_msg);

        if (! $success ) {
          $error_msg = "Error updating metafile (meta_delete). (" . $error_msg . ")";
          return False;
        }

        $success = $this->meta_add ( $meta_model, $error_msg );

        if (! $success ) {
          $error_msg = "Error updating metafile (meta_add). (" . $error_msg . ")";
          return False;
        }

        return True;
    } # meta_update

    static function write_meta_line($fp, meta_model $meta_model) {
      fwrite ( $fp, $meta_model->user . ':' . $meta_model->email . ':' . $meta_model->name . "\n" );
    }

    static function exists($fp, $username) {
      # See if the username exists in the specified $fp file:
      rewind ( $fp );
      while ( ! feof ( $fp ) && trim ( $lusername = array_shift ( explode ( ":", $line = rtrim ( fgets ( $fp ) ) ) ) ) ) {
          if ($lusername == $username)
              return true;
      }
    } # exists

    static function open_or_create($filename) {
      if (! file_exists ( $filename )) {
        return fopen ( $filename, 'w+' );
      } else {
        return fopen ( $filename, 'r+' );
      }
    } # open_or_create

    static function delete($fp, $username, $filename, &$error_msg, $dorewind = true) {
      #
      # Delete username's data from the (already open) $fp referenced file handle.
      #
      #   $username - Account's username
      #   $filename - Filename of the $fp file
      #   $error_msg- in, out: On error, the returned error msg.

      $data = '';
      $pos = ftell($fp);
      if ($dorewind) {
        rewind ( $fp );
      }

      while ( ! feof ( $fp ) && trim ( $lusername = array_shift ( explode (
        ":", $line = rtrim ( fgets ( $fp ) ) ) ) ) ) {
        if (! trim ( $line ))
          break;
        if ($lusername != $username)
          $data .= $line . "\n";
      }
      $fp = fopen ( $filename, 'r+' );
      if (!$dorewind) {
        fseek($fp, $pos);
      }
      $success = fwrite ( $fp, rtrim ( $data ) . (trim ( $data ) ? "\n" : '') );
      #if (! $success) {
      #  $error_msg = ("Error writing to filename: " . $filename);
      #  return False;
      #}

      # flush updates to disk, then reopen the file
      ftruncate( $fp, ftell($fp));
      fclose ( $fp );
      $fp = fopen ( $filename, 'r+' );
      if (! $fp ) {
        $error_msg = "Error re-opening file after filename: " . $filename;
        return false;
      }

      #$dbg_log_h->close_log();
      return true;

    } # delete

    static function htcrypt($password) {
      return password_hash($password,PASSWORD_DEFAULT);
    } # htcrypt

    static function check_password_hash($password, $hash) {
        return password_verify($password, $hash);
    } # check_password_hash

} # class htpasswd

?>
