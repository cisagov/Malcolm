##! Zeek local site policy. Customize as appropriate.
##!
##! See https://github.com/zeek/zeekctl
##!     https://docs.zeek.org/en/stable/script-reference/scripts.html
##!     https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek

global true_regex: pattern = /^\s*(?i:t(rue)?|y(es)?|on|1)\s*$/;

global disable_stats = (getenv("ZEEK_DISABLE_STATS") == true_regex) ? T : F;
global disable_hash_all_files = (getenv("ZEEK_DISABLE_HASH_ALL_FILES") == true_regex) ? T : F;
global disable_log_passwords = (getenv("ZEEK_DISABLE_LOG_PASSWORDS") == true_regex) ? T : F;
global disable_ssl_validate_certs = (getenv("ZEEK_DISABLE_SSL_VALIDATE_CERTS") == true_regex) ? T : F;
global disable_track_all_assets = (getenv("ZEEK_DISABLE_TRACK_ALL_ASSETS") == true_regex) ? T : F;
global disable_best_guess_ics = (getenv("ZEEK_DISABLE_BEST_GUESS_ICS") == true_regex) ? T : F;
global disable_detect_routers = (getenv("ZEEK_DISABLE_DETECT_ROUTERS") == true_regex) ? T : F;
global omron_fins_detailed = (getenv("ZEEK_OMRON_FINS_DETAILED") == true_regex) ? T : F;
global synchrophasor_detailed = (getenv("ZEEK_SYNCHROPHASOR_DETAILED") == true_regex) ? T : F;
global synchrophasor_ports_str = getenv("ZEEK_SYNCHROPHASOR_PORTS");
global genisys_ports_str = getenv("ZEEK_GENISYS_PORTS");
global enip_ports_str = getenv("ZEEK_ENIP_PORTS");
global ja4_ssh_packet_count = (getenv("ZEEK_JA4SSH_PACKET_COUNT") == "") ? 200 : to_count(getenv("ZEEK_JA4SSH_PACKET_COUNT"));
global local_nets_str = getenv("ZEEK_LOCAL_NETS");
global long_conn_durations = getenv("ZEEK_LONG_CONN_DURATIONS");
global long_conn_repeat_last_duration = (getenv("ZEEK_LONG_CONN_REPEAT_LAST_DURATION") == true_regex) ? T : F;
global long_conn_do_notice = (getenv("ZEEK_LONG_CONN_DO_NOTICE") == true_regex) ? T : F;

global disable_spicy_ipsec = (getenv("ZEEK_DISABLE_SPICY_IPSEC") == true_regex) ? T : F;
global disable_spicy_ldap = (getenv("ZEEK_DISABLE_SPICY_LDAP") == true_regex) ? T : F;
global disable_spicy_openvpn = (getenv("ZEEK_DISABLE_SPICY_OPENVPN") == true_regex) ? T : F;
global disable_spicy_quic = (getenv("ZEEK_DISABLE_SPICY_QUIC") == true_regex) ? T : F;
global disable_spicy_stun = (getenv("ZEEK_DISABLE_SPICY_STUN") == true_regex) ? T : F;
global disable_spicy_tailscale = (getenv("ZEEK_DISABLE_SPICY_TAILSCALE") == true_regex) ? T : F;
global disable_spicy_tftp = (getenv("ZEEK_DISABLE_SPICY_TFTP") == true_regex) ? T : F;
global disable_spicy_wireguard = (getenv("ZEEK_DISABLE_SPICY_WIREGUARD") == true_regex) ? T : F;

global disable_ics_all = (getenv("ZEEK_DISABLE_ICS_ALL") == true_regex) ? T : F;
global disable_ics_bacnet = (getenv("ZEEK_DISABLE_ICS_BACNET") == true_regex) ? T : F;
global disable_ics_bsap = (getenv("ZEEK_DISABLE_ICS_BSAP") == true_regex) ? T : F;
global disable_ics_dnp3 = (getenv("ZEEK_DISABLE_ICS_DNP3") == true_regex) ? T : F;
global disable_ics_enip = (getenv("ZEEK_DISABLE_ICS_ENIP") == true_regex) ? T : F;
global disable_ics_ethercat = (getenv("ZEEK_DISABLE_ICS_ETHERCAT") == true_regex) ? T : F;
global disable_ics_genisys = (getenv("ZEEK_DISABLE_ICS_GENISYS") == true_regex) ? T : F;
global disable_ics_ge_srtp = (getenv("ZEEK_DISABLE_ICS_GE_SRTP") == true_regex) ? T : F;
global disable_ics_hart_ip = (getenv("ZEEK_DISABLE_ICS_HART_IP") == true_regex) ? T : F;
global disable_ics_omron_fins = (getenv("ZEEK_DISABLE_ICS_OMRON_FINS") == true_regex) ? T : F;
global disable_ics_opcua_binary = (getenv("ZEEK_DISABLE_ICS_OPCUA_BINARY") == true_regex) ? T : F;
global disable_ics_modbus = (getenv("ZEEK_DISABLE_ICS_MODBUS") == true_regex) ? T : F;
global disable_ics_profinet = (getenv("ZEEK_DISABLE_ICS_PROFINET") == true_regex) ? T : F;
global disable_ics_profinet_io_cm = (getenv("ZEEK_DISABLE_ICS_PROFINET_IO_CM") == true_regex) ? T : F;
global disable_ics_roc_plus = (getenv("ZEEK_DISABLE_ICS_ROC_PLUS") == true_regex) ? T : F;
global disable_ics_s7comm = (getenv("ZEEK_DISABLE_ICS_S7COMM") == true_regex) ? T : F;
global disable_ics_synchrophasor = (getenv("ZEEK_DISABLE_ICS_SYNCHROPHASOR") == true_regex) ? T : F;

global zeek_kafka_enabled = (getenv("ZEEK_KAFKA_ENABLED") == true_regex) ? T : F;
global zeek_kafka_brokers = getenv("ZEEK_KAFKA_BROKERS");
global zeek_kafka_topic = getenv("ZEEK_KAFKA_TOPIC");

redef Broker::default_listen_address = "127.0.0.1";
redef ignore_checksums = T;

global capture_filter_str = getenv("CAPTURE_FILTER");
@if (capture_filter_str != "")
  redef restrict_filters += { ["user-defined capture filter"] = capture_filter_str };
@endif

global json_format = (getenv("ZEEK_JSON") == true_regex) ? T : F;
@if (json_format)
  redef LogAscii::use_json = T;
@endif

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
@load protocols/http/header-names
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
@if (!disable_stats)
  @load policy/misc/stats
  @load policy/misc/capture-loss
@endif
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/modbus/known-masters-slaves
@load policy/frameworks/notice/community-id
@load ./login.zeek

@if (!disable_best_guess_ics)
 @load ./guess.zeek
@endif
@if (!disable_detect_routers)
  @load ./known-routers.zeek
@endif

@load packages
@if (!disable_ics_all)
  @load ACID/scripts
@endif
@load intel
@load custom

event zeek_init() &priority=-5 {

  if (local_nets_str != "") {
    local nets_strs = split_string(local_nets_str, /,/);
    if (|nets_strs| > 0) {
      for (net_idx in nets_strs) {
        local local_subnet = to_subnet(nets_strs[net_idx]);
        if (local_subnet != [::]/0) {
          add Site::local_nets[local_subnet];
        }
      }
    }
  }

  if (long_conn_durations != "") {
    local durations_strs = split_string(long_conn_durations, /,/);
    if (|durations_strs| > 0) {
      local new_durations = vector(0min);
      delete new_durations;
      for (dur_idx in durations_strs) {
        local dur_doub = to_double(durations_strs[dur_idx]);
        if (dur_doub > 0.0) {
          new_durations += double_to_interval(dur_doub);
        }
      }
      if (|new_durations| > 0) {
        delete LongConnection::default_durations;
        LongConnection::default_durations += new_durations;
      }
    }
  }

  if (disable_ics_all || disable_ics_bacnet) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_BACNET);
  }
  if (disable_ics_all || disable_ics_bsap) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_BSAP);
  }
  if (disable_ics_all || disable_ics_dnp3) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_DNP3_TCP);
    Analyzer::disable_analyzer(Analyzer::ANALYZER_DNP3_UDP);
  }
  if (disable_ics_all || disable_ics_enip) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_ENIP_TCP);
    Analyzer::disable_analyzer(Analyzer::ANALYZER_ENIP_UDP);
  }
  if (disable_ics_all || disable_ics_ethercat) {
    PacketAnalyzer::__disable_analyzer(PacketAnalyzer::ANALYZER_ETHERCAT);
  }
  if (disable_ics_all || disable_ics_genisys) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_GENISYS_TCP);
  }
  if (disable_ics_all || disable_ics_ge_srtp) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_GE_SRTP_TCP);
  }
  if (disable_ics_all || disable_ics_hart_ip) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_HART_IP_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_HART_IP_UDP);
  }
  if (disable_ics_all || disable_ics_opcua_binary) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_ICSNPP_OPCUA_BINARY);
  }
  if (disable_ics_all || disable_ics_modbus) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_MODBUS);
  }
  if (disable_ics_all || disable_ics_omron_fins) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_OMRON_FINS_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_OMRON_FINS_UDP);
  }
  if (disable_ics_all || disable_ics_profinet) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_PROFINET);
  }
  if (disable_ics_all || disable_ics_profinet_io_cm) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_PROFINET_IO_CM);
  }
  if (disable_ics_all || disable_ics_roc_plus) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_ROC_PLUS_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_ROC_PLUS_UDP);
  }
  if (disable_ics_all || disable_ics_s7comm) {
    Analyzer::disable_analyzer(Analyzer::ANALYZER_S7COMM_TCP);
  }
  if (disable_ics_all || disable_ics_synchrophasor) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SYNCHROPHASOR_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SYNCHROPHASOR_UDP);
  }
  if (disable_spicy_ipsec) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_IPSEC_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_IPSEC_UDP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_SPICY_IPSEC_IKE_UDP);
  }
  if (disable_spicy_ldap) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_LDAP_TCP);
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_LDAP_UDP);
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
  if (disable_spicy_quic) {
    Spicy::disable_protocol_analyzer(Analyzer::ANALYZER_QUIC);
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

  # register additional ports for Analyzers
  if ((!disable_ics_all) && (!disable_ics_synchrophasor) && (synchrophasor_ports_str != "")) {
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
        Analyzer::register_for_ports(Analyzer::ANALYZER_SYNCHROPHASOR_TCP, synch_ports_tcp);
      }
      if (|synch_ports_udp| > 0) {
        Analyzer::register_for_ports(Analyzer::ANALYZER_SYNCHROPHASOR_UDP, synch_ports_udp);
      }
    }
  }
  if ((!disable_ics_all) && (!disable_ics_genisys) && (genisys_ports_str != "")) {
    local genisys_ports = split_string(genisys_ports_str, /,/);
    if (|genisys_ports| > 0) {
      local gen_ports_tcp: set[port] = {};
      for (gen_port_idx in genisys_ports) {
        local gen_port = to_port(genisys_ports[gen_port_idx]);
        local gen_prot = get_port_transport_proto(gen_port);
        if (gen_prot == tcp) {
          add gen_ports_tcp[gen_port];
        }
      }
      if (|gen_ports_tcp| > 0) {
        Analyzer::register_for_ports(Analyzer::ANALYZER_GENISYS_TCP, gen_ports_tcp);
      }
    }
  }
  if ((!disable_ics_all) && (!disable_ics_enip) && (enip_ports_str != "")) {
    local enip_ports = split_string(enip_ports_str, /,/);
    if (|enip_ports| > 0) {
      local enip_ports_tcp: set[port] = {};
      local enip_ports_udp: set[port] = {};
      for (enip_port_idx in enip_ports) {
        local enip_port = to_port(enip_ports[enip_port_idx]);
        local enip_prot = get_port_transport_proto(enip_port);
        if (enip_prot == tcp) {
          add enip_ports_tcp[enip_port];
        } else if (enip_prot == udp) {
          add enip_ports_udp[enip_port];
        }
      }
      if (|enip_ports_tcp| > 0) {
        Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_TCP, enip_ports_tcp);
      }
      if (|enip_ports_udp| > 0) {
        Analyzer::register_for_ports(Analyzer::ANALYZER_ENIP_UDP, enip_ports_udp);
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

redef FINGERPRINT::JA4SSH::ja4_ssh_packet_count = ja4_ssh_packet_count;
redef HTTP::log_client_header_names = T;
redef HTTP::log_server_header_names = T;
redef LDAP::default_log_search_attributes = F;
redef SNIFFPASS::notice_log_enable = F;
redef CVE_2021_44228::log = F;
redef LongConnection::repeat_last_duration = long_conn_repeat_last_duration;
redef LongConnection::do_notice=long_conn_do_notice;

@if ((!disable_ics_all) && (!disable_ics_synchrophasor) && (!synchrophasor_detailed))
  hook SYNCHROPHASOR::log_policy_sychrophasor_data_detail(
    rec : SYNCHROPHASOR::Synchrophasor_Data_Detail,
    id : Log::ID,
    filter : Log::Filter) {
      break;
  }
  hook SYNCHROPHASOR::log_policy_sychrophasor_config_detail(
    rec : SYNCHROPHASOR::Synchrophasor_Config_Detail,
    id : Log::ID,
    filter : Log::Filter) {
      break;
  }

  hook SYNCHROPHASOR::log_policy_sychrophasor_data(
    rec : SYNCHROPHASOR::Synchrophasor_Data,
    id : Log::ID,
    filter : Log::Filter) {
      break;
  }
@endif
@if ((!disable_ics_all) && (!disable_ics_omron_fins) && (!omron_fins_detailed))
  hook OMRON_FINS::log_policy_detail(
    rec : OMRON_FINS::detail_log,
    id : Log::ID,
    filter : Log::Filter) {
      break;
  }
@endif

##! Other logs we're just disabling unilaterally

# amzn/zeek-plugin-profinet's profinet_dce_rpc.log is covered by cisagov/icsnpp-profinet-io-cm
hook Profinet::log_policy_dce_rpc(
  rec: Profinet::Profinet_DCE_RPC,
  id: Log::ID,
  filter: Log::Filter) {
  break;
}

# we're not tracking the BSAP "unknown" logs
hook Bsap::log_policy_bsap_ip_unknown(
  rec: Bsap::BSAP_IP_UNKNOWN,
  id: Log::ID,
  filter: Log::Filter) {
  break;
}

hook Bsap::log_policy_bsap_serial_unknown(
  rec: Bsap::BSAP_SERIAL_UNKNOWN,
  id: Log::ID,
  filter: Log::Filter) {
  break;
}

# all ARP traffic is logged by the ethercat parser, which is overkill
hook PacketAnalyzer::ECAT::log_policy_ecat_arp(
  rec: PacketAnalyzer::ECAT::ECAT_ARP_INFO,
  id: Log::ID,
  filter: Log::Filter) {
  break;
}

@if (zeek_kafka_enabled)
 @load packages/zeek-kafka
 redef Kafka::send_all_active_logs = T;
 redef Kafka::topic_name = zeek_kafka_topic;
 redef Kafka::tag_json = T;
 redef Kafka::kafka_conf = table(
     ["metadata.broker.list"] = zeek_kafka_brokers
);
@endif
