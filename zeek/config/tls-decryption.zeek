##! Optional TLS 1.2 decryption for capture files with session secrets.
##! Secrets must be supplied via a private, read-only mounted file; only the
##! path is read from the environment, never the key contents.
@if (getenv("ZEEK_TLS_KEYLOG_FILE") != "")
  @load protocols/ssl/decryption
  redef SSL::keylog_file = getenv("ZEEK_TLS_KEYLOG_FILE");
@endif
