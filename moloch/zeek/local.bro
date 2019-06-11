##! Zeek local site policy. Customize as appropriate.
##!
##! See https://github.com/zeek/zeekctl
##!     https://docs.zeek.org/en/stable/script-reference/scripts.html
##!     https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek

redef Broker::default_listen_address = "127.0.0.1";
redef ignore_checksums = T;

@load tuning/defaults
@load misc/scan
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/http/detect-webapps
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load tuning/track-all-assets.bro
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load protocols/http/detect-sqli
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load ./ja3
