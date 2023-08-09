<?php

// where to get files from
const ENTRY_FIELD = array('filepond');

// where to write files to
const UPLOAD_DIR = __DIR__ . '/upload';
const TRANSFER_DIR = __DIR__ . '/upload/tmp';
const VARIANTS_DIR = __DIR__ . '/upload/variants';

// name to use for the file metadata object
const METADATA_FILENAME = '.metadata';

// allowed file formats, if empty all files allowed
const ALLOWED_FILE_FORMATS = array(
);

if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0775);
if (!is_dir(TRANSFER_DIR)) mkdir(TRANSFER_DIR, 0775);
if (!is_dir(VARIANTS_DIR)) mkdir(VARIANTS_DIR, 0775);
