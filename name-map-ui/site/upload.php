<?php

header('Content-Type: text/plain; charset=utf-8');

try {

  // invalid multiple files / $_FILES corruption attack
  if (!isset($_FILES['upfile']['error']) ||
      is_array($_FILES['upfile']['error'])) {
    throw new RuntimeException('Invalid parameters');
  }

  // validate $_FILES['upfile']['error']
  switch ($_FILES['upfile']['error']) {
    case UPLOAD_ERR_OK:
      break;
    case UPLOAD_ERR_NO_FILE:
      throw new RuntimeException('No file sent');
    case UPLOAD_ERR_INI_SIZE:
    case UPLOAD_ERR_FORM_SIZE:
      throw new RuntimeException('Exceeded filesize limit');
    default:
      throw new RuntimeException('Unknown error');
  }

  // maximum upload filesize
  if ($_FILES['upfile']['size'] > 67108864) {
    throw new RuntimeException('Exceeded filesize limit');
  }

  // check upload MIME type
  $finfo = new finfo(FILEINFO_MIME_TYPE);
  $fmime = $finfo->file($_FILES['upfile']['tmp_name']);
  if (false === $ext = array_search($fmime,
                                    array('json' => 'application/json',
                                          'txt' => 'text/plain'),
                                    true)) {
    throw new RuntimeException(sprintf('Invalid file format: "%s"', $fmime));
  }

  // give file unique name based on sha
  $ftmpname = $_FILES['upfile']['tmp_name'];
  $fdstname = sprintf('./upload/%s.%s',
                      sha1_file($_FILES['upfile']['tmp_name']),
                      $ext);
  if (!move_uploaded_file($ftmpname, $fdstname)) {
    throw new RuntimeException(sprintf('Failed to move uploaded file ("%s" -> "%s")', $ftmpname, $fdstname));
  }

  echo 'Success';

} catch (RuntimeException $e) {
  error_log ($e->getMessage());
  echo $e->getMessage();
}

?>