<?php
#include_once ("tools/util.php");

/**
 * dbg_log: Set of routines to write debug msg strings out to a file.
 *
*/

## Global variables: ######################################################

###########################################################################

class dbg_log {
    var $fp;                # Debug log file pointer;
    var $last_error_msg;    # Last error message captured by this class instance


    public function __construct( $filename, $log_file_path=".", $truncate_old_log=true) {
        # dbg_log constructor function.
        # Create/open the debug log file. Then, seek to end of file.
        #
        $this->size_zero     = 0;
        $this->full_filename = $log_file_path . "/" . $filename;

        if ( $truncate_old_log && file_exists( $this->full_filename ) ) {
            # Truncate the existing debug log file:
            $this->tmp_fp = fopen  ( $this->full_filename, 'r+' );
            rewind ( $this->tmp_fp );
            $this->trunc_result = ftruncate( $this->tmp_fp, $this->size_zero );
            $this->fclose( $this->tmp_fp );
        }

        $this->fp = $this::append_or_create_file ( $this->full_filename );

        if (! $this->fp) {
          $this->last_error_msg = ("dbg_log: Error opening file: " . $this->full_filename);
        }


       # A handle to the class instance will be auto returned to the caller.
    }  # end __construct


    public function log_msg($msg, $src_proc="") {
        #
        # Log the passed in message to the debug log file.
        #   msg: The message string to be logged
        #   src_proc: The source procedure/function
        #
        if (strlen($src_proc) > 0) {
           $full_msg = $src_proc . ": " . $msg;
        }
        else {
           $full_msg = $msg;
        }

        fwrite ( $this->fp, ($full_msg . "\n" ) );
    }


    public function get_last_error_msg() {
        return ( $this->last_error_msg );    # The last error captured by this object.
    }


    public function close_log() {
        fclose( $this->fp );
    }


    public function __destruct() {
        # User's don't explicitly call __destruct().  It's called when the class goes out
        # of scope. (Apparently, the 'this->' handle does not exist during the call.
        #fclose( $this->fp );
    }


    ##################################################################################
    # Class level functions:

    static function open_or_create_file($filename) {
        if (! file_exists ( $filename )) {
            #echo "Create: Not file exists: " . $filename . "\n";
            return fopen ( $filename, 'w+' );    # Create a new file. Open for reading and writing;
                                                 # Move file ptr to start of file. (truncate to zero length) 
        } else {
            #echo "Open: File exists: " . $filename . "\n";
            return fopen ( $filename, 'r+' );    # Open existing file for reading and writing;
        }                                        # Move file ptr to start of file.
    }


    static function append_or_create_file($filename) {
        if (! file_exists ( $filename )) {
            #echo "Create: Not, file exists: " . $filename . "\n";
            return fopen ( $filename, 'a' );    # Create a new file.. in append mode (writing only).
        } else {                                # fseek() has no effect in append mode.
            #echo "Open: File exists: " . $filename . "\n";
            return fopen ( $filename, 'a' );    # Open an existing file in append mode (writing only).
        }
    }

} # end dbg_log class

?>
