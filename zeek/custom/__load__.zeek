global zeek_tls_keylog_file = getenv("ZEEK_TLS_KEYLOG_FILE");

@if (zeek_tls_keylog_file != "")
  @load ./tls-decryption.zeek
@endif
