<?php

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');

require_once('FilePond.class.php');

require_once('config.php');

// Catch server exceptions and auto jump to 500 response code if caught
FilePond\catch_server_exceptions();

FilePond\route_form_post(ENTRY_FIELD, [
    'FILE_OBJECTS' => 'handle_file_post',
    'BASE64_ENCODED_FILE_OBJECTS' => 'handle_base64_encoded_file_post',
    'TRANSFER_IDS' => 'handle_transfer_ids_post'
]);

function console_log($data, $add_script_tags = false) {
    $command = 'console.log('. json_encode($data, JSON_HEX_TAG).');';
    if ($add_script_tags) {
        $command = '<script>'. $command . '</script>';
    }
    echo $command;
}

function sanitize_tagged_filename($filename) {
    $info = pathinfo($filename);
    $name = sanitize_tagged_filename_part($info['filename']);
    $extension = sanitize_tagged_filename_part($info['extension']);
    return (strlen($name) > 0 ? $name : '_') . '.' . $extension;
}

function sanitize_tagged_filename_part($str) {
    return preg_replace("/[^a-zA-Z0-9\s_\(\)\.,-]/", "", $str);
}

function move_temp_file_prefixed($file, $path, $prefix) {
    move_uploaded_file($file['tmp_name'], $path . DIRECTORY_SEPARATOR . sanitize_tagged_filename($prefix . $file['name']));
}

function move_file_prefixed($file, $path, $prefix) {
    if (is_uploaded_file($file['tmp_name'])) {
        return move_temp_file_prefixed($file, $path, $prefix);
    }
    return rename($file['tmp_name'], $path . DIRECTORY_SEPARATOR . sanitize_tagged_filename($prefix . $file['name']));
}


function handle_file_post($files) {

    foreach($files as $file) {
        FilePond\move_file($file, UPLOAD_DIR);
    }

}

function handle_base64_encoded_file_post($files) {

    foreach ($files as $file) {

        // Suppress error messages, we'll assume these file objects are valid
        /* Expected format:
        {
            "id": "iuhv2cpsu",
            "name": "picture.jpg",
            "type": "image/jpeg",
            "size": 20636,
            "metadata" : {...}
            "data": "/9j/4AAQSkZJRgABAQEASABIAA..."
        }
        */
        $file = @json_decode($file);
        if (!is_object($file)) continue;

        FilePond\write_file(
            UPLOAD_DIR, 
            base64_decode($file->data), 
            FilePond\sanitize_filename($file->name)
        );
    }

}

function handle_transfer_ids_post($ids) {

    foreach ($ids as $id) {
        
        $transfer = FilePond\get_transfer(TRANSFER_DIR, $id);
        if (!$transfer) continue;

        $new_name_prefix = '';
        if (isset($_POST["tags"]) && (strlen($_POST["tags"]) > 0)) {
            $new_name_prefix = $_POST["tags"] . ",USERTAG,";
        }
        
        $files = $transfer->getFiles(defined('TRANSFER_PROCESSOR') ? TRANSFER_PROCESSOR : null);
        if($files != null){
           foreach($files as $file) {
                move_file_prefixed($file, UPLOAD_DIR, $new_name_prefix);
            } 
        }

        FilePond\remove_transfer_directory(TRANSFER_DIR, $id);
    }

    $return_to = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '/upload';
    header("Location: ". $return_to);
}