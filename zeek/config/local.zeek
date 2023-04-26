##! Zeek local site policy. Customize as appropriate.
##!
##! See https://github.com/zeek/zeekctl
##!     https://docs.zeek.org/en/stable/script-reference/scripts.html
##!     https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek

global disable_hash_all_files = (getenv("ZEEK_DISABLE_HASH_ALL_FILES") == "") ? F : T;
global disable_log_passwords = (getenv("ZEEK_DISABLE_LOG_PASSWORDS") == "") ? F : T;
global disable_ssl_validate_certs = (getenv("ZEEK_DISABLE_SSL_VALIDATE_CERTS") == "") ? F : T;
global disable_track_all_assets = (getenv("ZEEK_DISABLE_TRACK_ALL_ASSETS") == "") ? F : T;
global disable_best_guess_ics = (getenv("ZEEK_DISABLE_BEST_GUESS_ICS") == "") ? F : T;
global synchrophasor_detailed = (getenv("ZEEK_SYNCHROPHASOR_DETAILED") == "") ? F : T;
global synchrophasor_ports_str = getenv("ZEEK_SYNCHROPHASOR_PORTS");

global disable_spicy_dhcp = (getenv("ZEEK_DISABLE_SPICY_DHCP") == "") ? F : T;
global disable_spicy_dns = (getenv("ZEEK_DISABLE_SPICY_DNS") == "") ? F : T;
global disable_spicy_http = (getenv("ZEEK_DISABLE_SPICY_HTTP") == "") ? F : T;
global disable_spicy_ipsec = (getenv("ZEEK_DISABLE_SPICY_IPSEC") == "") ? F : T;
global disable_spicy_ldap = (getenv("ZEEK_DISABLE_SPICY_LDAP") == "") ? F : T;
global disable_spicy_openvpn = (getenv("ZEEK_DISABLE_SPICY_OPENVPN") == "") ? F : T;
global disable_spicy_stun = (getenv("ZEEK_DISABLE_SPICY_STUN") == "") ? F : T;
global disable_spicy_tailscale = (getenv("ZEEK_DISABLE_SPICY_TAILSCALE") == "") ? F : T;
global disable_spicy_tftp = (getenv("ZEEK_DISABLE_SPICY_TFTP") == "") ? F : T;
global disable_spicy_wireguard = (getenv("ZEEK_DISABLE_SPICY_WIREGUARD") == "") ? F : T;

redef Broker::default_listen_address = "127.0.0.1";
redef ignore_checksums = T;

@load tuning/defaults
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/software/windows-version-detection
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dhcp/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/ftp/detect-bruteforcing.zeek
@load protocols/ftp/software
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load protocols/http/software
@load protocols/http/software-browser-plugins
@load protocols/mysql/software
@load protocols/ssl/weak-keys
@load protocols/smb/log-cmds
@load protocols/smtp/software
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software
@load protocols/ssl/known-certs
@load protocols/ssl/log-hostcerts-only
@if (!disable_ssl_validate_certs)
  @load protocols/ssl/validate-certs
@endif
@if (!disable_track_all_assets)
  @load tuning/track-all-assets.zeek
@endif
@if (!disable_hash_all_files)
  @load frameworks/files/hash-all-files
@endif
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/modbus/known-masters-slaves
@load ./login.zeek

@if (!disable_best_guess_ics)
  @load ./guess.zeek
@endif

@load packages
@load intel

event zeek_init() &priority=-5 {
  if (disable_spicy_dhcp) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_DHCP);
  }
  if (disable_spicy_dns) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_DNS);
  }
  if (disable_spicy_http) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_HTTP);
  }
  if (disable_spicy_ipsec) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_IPSEC_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_IPSEC_UDP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_IPSEC_IKE_UDP);
  }
  if (disable_spicy_ldap) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_LDAP_TCP);
  }
  if (disable_spicy_openvpn) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_MD5);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_SHA1);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_SHA256);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_TCP_HMAC_SHA512);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_UDP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_MD5);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_SHA1);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_SHA256);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_OPENVPN_UDP_HMAC_SHA512);
  }
  if (disable_spicy_stun) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_STUN);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_STUN_TCP);
  }
  if (disable_spicy_tailscale) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_TAILSCALE);
  }
  if (disable_spicy_tftp) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_TFTP);
  }
  if (disable_spicy_wireguard) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_WIREGUARD);
  }

  # register additional ports for Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_...
  if (synchrophasor_ports_str != "") {
    local synchrophasor_ports = split_string(synchrophasor_ports_str, /,/);
    if (|synchrophasor_ports| > 0) {
      local synch_ports_tcp: set[port] = {};
      local synch_ports_udp: set[port] = {};
      for (synch_port_idx in synchrophasor_ports) {
        local synch_port = to_port(synchrophasor_ports[synch_port_idx]);
        local synch_prot = get_port_transport_proto(synch_port);
        if (synch_prot == tcp) {
          add synch_ports_tcp[synch_port];
        } else if (synch_prot == udp) {
          add synch_ports_udp[synch_port];
        }
      }
      if (|synch_ports_tcp| > 0) {
        Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_TCP, synch_ports_tcp);
      }
      if (|synch_ports_udp| > 0) {
        Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_SYNCHROPHASOR_UDP, synch_ports_udp);
      }
    }
  }

}

@if (!disable_log_passwords)
  redef HTTP::default_capture_password = T;
  redef FTP::default_capture_password = T;
  redef SOCKS::default_capture_password = T;
  redef SNIFFPASS::log_password_plaintext = T;
  redef LDAP::default_capture_password = T;
@endif
redef LDAP::default_log_search_attributes = F;
redef SNIFFPASS::notice_log_enable = F;
redef CVE_2021_44228::log = F;
@if (synchrophasor_detailed)
  redef SYNCHROPHASOR::log_data_frame = T;
  redef SYNCHROPHASOR::log_data_detail = T;
  redef SYNCHROPHASOR::log_cfg_detail = T;
@endif
