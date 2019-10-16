##! Zeek local site policy. Customize as appropriate.
##!
##! See https://github.com/zeek/zeekctl
##!     https://docs.zeek.org/en/stable/script-reference/scripts.html
##!     https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek

redef Broker::default_listen_address = "127.0.0.1";
redef ignore_checksums = T;
redef HTTP::default_capture_password = T;
redef FTP::default_capture_password = T;
redef SOCKS::default_capture_password = T;

@load tuning/defaults
@load misc/scan
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/software/windows-version-detection
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dhcp/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/ftp/software
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load protocols/http/software
@load protocols/http/software-browser-plugins
@load protocols/mysql/software
@load protocols/smtp/software
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software
@load protocols/ssl/known-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssl/validate-certs
@load tuning/track-all-assets.zeek
@load frameworks/files/hash-all-files
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/modbus/track-memmap
@load policy/protocols/modbus/known-masters-slaves
@load policy/protocols/mqtt
# @load frameworks/files/detect-MHR

# custom packages installed manually
@load Salesforce/GQUIC
@load Bro::LDAP
@load ./bzar
# custom packages managed by zkg via packages/packages.zeek
@load ./packages/packages.zeek
