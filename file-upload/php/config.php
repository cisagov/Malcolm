<?php

// where to get files from
const ENTRY_FIELD = array('filepond');

// where to write files to
const UPLOAD_DIR = __DIR__ . '/files';
const TRANSFER_DIR = __DIR__ . '/files/tmp';
const SPOOL_DIR = __DIR__ . '/files/tmp/spool';
const VARIANTS_DIR = __DIR__ . '/files/variants';

// name to use for the file metadata object
const METADATA_FILENAME = '.metadata';

// Allowed file formats for server-side MIME type validation; left empty (all formats
// permitted at upload time) because MIME type detection is unreliable across browsers
// for capture file formats (e.g. pcap, pcapng) and users commonly upload files with
// non-standard extensions. File type enforcement is handled downstream by
// watch-pcap-uploads-folder.py in pcap-monitor, which uses libmagic to route accepted
// types (pcap/pcapng, archives, Windows event logs) to the appropriate processing
// directory and deletes everything else.
const ALLOWED_FILE_FORMATS = array(
);

// Deny-list of extensions that must never be stored, regardless of allowlist
const BLOCKED_EXTENSIONS = array(
    'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
    'shtml', 'pl', 'py', 'rb', 'cgi', 'asp', 'aspx', 'jsp',
    'sh', 'bash', 'exe', 'dll', 'so',
);

if (!is_dir(UPLOAD_DIR)) mkdir(UPLOAD_DIR, 0775);
if (!is_dir(TRANSFER_DIR)) mkdir(TRANSFER_DIR, 0775);
if (!is_dir(SPOOL_DIR)) mkdir(SPOOL_DIR, 0775);
if (!is_dir(VARIANTS_DIR)) mkdir(VARIANTS_DIR, 0775);
