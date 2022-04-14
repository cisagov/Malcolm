<?php
// Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.
error_reporting(E_ALL | E_STRICT);
require('UploadHandler.php');
class CustomUploadHandler extends UploadHandler {
  protected function trim_file_name($file_path, $name, $size, $type, $error, $index, $content_range) {
    $enabled_carve_modes = array("interesting", "mapped", "known", "all");
    if (isset($_POST["tags"]) && !empty($_POST["tags"])) {
      $name = $_POST["tags"] . ",USERTAG," . $name;
    }
    if (isset($_POST["auto-carve"]) && in_array($_POST["auto-carve"], $enabled_carve_modes)) {
      $name = "AUTOCARVE".$_POST["auto-carve"]."," . $name;
    }
    if (isset($_POST["auto-zeek"]) && $_POST["auto-zeek"] == "enabled") {
      $name = "AUTOZEEK," . $name;
    }
    if (isset($_POST["auto-suricata"]) && $_POST["auto-suricata"] == "enabled") {
      $name = "AUTOSURICATA," . $name;
    }
    return parent::trim_file_name($file_path, preg_replace("/[^a-zA-Z0-9\s_\(\)\.,-]/", "", $name), $size, $type, $error, $index, $content_range);
  }
}
$upload_handler = new CustomUploadHandler();
