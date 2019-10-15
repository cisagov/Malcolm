var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  ;

//////////////////////////////////////////////////////////////////////////////////
// Moloch WISE Data Source definition for Zeek logs.
//
// Part of Malcolm (https://github.com/idaholab/malcolm)
//
// Data may be populated with Malcolm's Zeek Logstash filters:
//   (particularly https://raw.githubusercontent.com/idaholab/Malcolm/master/logstash/pipeline-main/11_zeek_logs.conf)
//
// Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.
// see https://raw.githubusercontent.com/idaholab/Malcolm/master/License.txt
//////////////////////////////////////////////////////////////////////////////////
function ZeekLogs (api, section) {
  ZeekLogs.super_.call(this, api, section);

  // todo: put in sane human-readable field names for all of them

  // see https://docs.zeek.org/en/stable/script-reference/log-files.html for Zeek logfile documentation

  // id information
  this.uidField = this.api.addField("field:zeek.uid;db:zeek.uid;kind:termfield;friendly:Zeek Connection ID;help:Zeek Connection ID");
  this.communityIdField = this.api.addField("field:zeek.community_id;db:zeek.community_id;kind:termfield;friendly:Zeek Connection Community ID;help:Zeek Connection Community ID");
  this.logTypeField = this.api.addField("field:zeek.logType;db:zeek.logType;kind:termfield;friendly:Zeek Log Type;help:Zeek Log Type");
  this.tsField = this.api.addField("field:zeek.ts;db:zeek.ts;kind:termfield;friendly:Timestamp;help:Zeek Timestamp");
  this.hostField = this.api.addField("field:host.name;db:host.name;kind:termfield;friendly:Zeek Node;help:Zeek Node");

  // basic connection information
  this.orig_hField = this.api.addField("field:zeek.orig_h;db:zeek.orig_h;kind:termfield;friendly:Originating host;help:Originating Host");
  this.orig_pField = this.api.addField("field:zeek.orig_p;db:zeek.orig_p;kind:integer;friendly:Originating port;help:Originating Port");
  this.orig_l2_addrField = this.api.addField("field:zeek.orig_l2_addr;db:zeek.orig_l2_addr;kind:termfield;friendly:Originating MAC;help:Originating MAC");
  this.orig_l2_ouiField = this.api.addField("field:zeek.orig_l2_oui;db:zeek.orig_l2_oui;kind:termfield;friendly:Originating OUI;help:Originating OUI");
  this.orig_hostnameField = this.api.addField("field:zeek.orig_hostname;db:zeek.orig_hostname;kind:termfield;friendly:Originating Host Name;help:Originating Host Name");
  this.orig_segmentField = this.api.addField("field:zeek.orig_segment;db:zeek.orig_segment;kind:termfield;friendly:Originating Network Segment;help:Originating Network Segment");
  this.source_ip_reverse_dnsField = this.api.addField("field:zeek.source_ip_reverse_dns;db:zeek.source_ip_reverse_dns;kind:termfield;friendly:Originating IP Reverse DNS;help:Originating IP Reverse DNS");
  this.source_geo_cityField = this.api.addField("field:zeek.source_geo.city_name;db:zeek.source_geo.city_name;kind:termfield;friendly:Originating GeoIP City;help:Originating GeoIP City");
  this.source_geo_countryField = this.api.addField("field:zeek.source_geo.country_name;db:zeek.source_geo.country_name;kind:termfield;friendly:Originating GeoIP Country;help:Originating GeoIP Country");
  this.resp_hField = this.api.addField("field:zeek.resp_h;db:zeek.resp_h;kind:termfield;friendly:Responding host;help:Responding Host");
  this.resp_pField = this.api.addField("field:zeek.resp_p;db:zeek.resp_p;kind:integer;friendly:Responding port;help:Responding Port");
  this.resp_l2_addrField = this.api.addField("field:zeek.resp_l2_addr;db:zeek.resp_l2_addr;kind:termfield;friendly:Responding MAC;help:Responding MAC");
  this.resp_l2_ouiField = this.api.addField("field:zeek.resp_l2_oui;db:zeek.resp_l2_oui;kind:termfield;friendly:Responding OUI;help:Responding OUI");
  this.resp_hostnameField = this.api.addField("field:zeek.resp_hostname;db:zeek.resp_hostname;kind:termfield;friendly:Responding Host Name;help:Responding Host Name");
  this.resp_segmentField = this.api.addField("field:zeek.resp_segment;db:zeek.resp_segment;kind:termfield;friendly:Responding Network Segment;help:Responding Network Segment");
  this.destination_ip_reverse_dnsField = this.api.addField("field:zeek.destination_ip_reverse_dns;db:zeek.destination_ip_reverse_dns;kind:termfield;friendly:Responding IP Reverse DNS;help:Responding IP Reverse DNS");
  this.destination_geo_cityField = this.api.addField("field:zeek.destination_geo.city_name;db:zeek.destination_geo.city_name;kind:termfield;friendly:Responding GeoIP City;help:Responding GeoIP City");
  this.destination_geo_countryField = this.api.addField("field:zeek.destination_geo.country_name;db:zeek.destination_geo.country_name;kind:termfield;friendly:Responding GeoIP Country;help:Responding GeoIP Country");
  this.protoField = this.api.addField("field:zeek.proto;db:zeek.proto;kind:lotermfield;friendly:Protocol;help:Protocol");
  this.serviceField = this.api.addField("field:zeek.service;db:zeek.service;kind:termfield;friendly:Service;help:Service");
  this.userField = this.api.addField("field:zeek.user;db:zeek.user;kind:termfield;friendly:User;help:User");

  // file information
  this.fuidField = this.api.addField("field:zeek.fuid;db:zeek.fuid;kind:termfield;friendly:File ID;help:File ID");
  this.filenameField = this.api.addField("field:zeek.filename;db:zeek.filename;kind:termfield;friendly:File Name;help:File Name");
  this.filetypeField = this.api.addField("field:zeek.filetype;db:zeek.filetype;kind:termfield;friendly:File Magic;help:File Magic");

  // conn.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info
  this.conn_durationField = this.api.addField("field:zeek_conn.duration;db:zeek_conn.duration;kind:termfield;friendly:conn duration;help:conn duration");
  this.conn_orig_bytesField = this.api.addField("field:zeek_conn.orig_bytes;db:zeek_conn.orig_bytes;kind:integer;friendly:conn orig_bytes;help:conn orig_bytes");
  this.conn_resp_bytesField = this.api.addField("field:zeek_conn.resp_bytes;db:zeek_conn.resp_bytes;kind:integer;friendly:conn resp_bytes;help:conn resp_bytes");
  this.conn_conn_stateField = this.api.addField("field:zeek_conn.conn_state;db:zeek_conn.conn_state;kind:termfield;friendly:conn conn_state;help:conn conn_state");
  this.conn_conn_state_descriptionField = this.api.addField("field:zeek_conn.conn_state_description;db:zeek_conn.conn_state_description;kind:termfield;friendly:conn conn_state_description;help:conn conn_state_description");
  this.conn_local_origField = this.api.addField("field:zeek_conn.local_orig;db:zeek_conn.local_orig;kind:termfield;friendly:conn local_orig;help:conn local_orig");
  this.conn_local_respField = this.api.addField("field:zeek_conn.local_resp;db:zeek_conn.local_resp;kind:termfield;friendly:conn local_resp;help:conn local_resp");
  this.conn_missed_bytesField = this.api.addField("field:zeek_conn.missed_bytes;db:zeek_conn.missed_bytes;kind:integer;friendly:conn missed_bytes;help:conn missed_bytes");
  this.conn_historyField = this.api.addField("field:zeek_conn.history;db:zeek_conn.history;kind:termfield;friendly:conn history;help:conn history");
  this.conn_orig_pktsField = this.api.addField("field:zeek_conn.orig_pkts;db:zeek_conn.orig_pkts;kind:integer;friendly:conn orig_pkts;help:conn orig_pkts");
  this.conn_orig_ip_bytesField = this.api.addField("field:zeek_conn.orig_ip_bytes;db:zeek_conn.orig_ip_bytes;kind:integer;friendly:conn orig_ip_bytes;help:conn orig_ip_bytes");
  this.conn_resp_pktsField = this.api.addField("field:zeek_conn.resp_pkts;db:zeek_conn.resp_pkts;kind:integer;friendly:conn resp_pkts;help:conn resp_pkts");
  this.conn_resp_ip_bytesField = this.api.addField("field:zeek_conn.resp_ip_bytes;db:zeek_conn.resp_ip_bytes;kind:integer;friendly:conn resp_ip_bytes;help:conn resp_ip_bytes");
  this.conn_tunnel_parentsField = this.api.addField("field:zeek_conn.tunnel_parents;db:zeek_conn.tunnel_parents;kind:termfield;friendly:conn tunnel_parents;help:conn tunnel_parents");
  this.conn_vlanField = this.api.addField("field:zeek_conn.vlan;db:zeek_conn.vlan;kind:integer;friendly:conn vlan;help:conn outer VLAN");
  this.conn_inner_vlanField = this.api.addField("field:zeek_conn.inner_vlan;db:zeek_conn.inner_vlan;kind:integer;friendly:conn inner_vlan;help:conn inner VLAN");

  // bacnet.log
  // https://github.com/amzn/zeek-plugin-bacnet/blob/master/scripts/main.zeek
  this.bacnet_bvlc_functionField = this.api.addField("field:zeek_bacnet.bvlc_function;db:zeek_bacnet.bvlc_function;kind:termfield;friendly:bacnet bvlc_function;help:bacnet bvlc_function");
  this.bacnet_bvlc_lenField = this.api.addField("field:zeek_bacnet.bvlc_len;db:zeek_bacnet.bvlc_len;kind:integer;friendly:bacnet bvlc_len;help:bacnet bvlc_len");
  this.bacnet_apdu_typeField = this.api.addField("field:zeek_bacnet.apdu_type;db:zeek_bacnet.apdu_type;kind:termfield;friendly:bacnet apdu_type;help:bacnet apdu_type");
  this.bacnet_service_choiceField = this.api.addField("field:zeek_bacnet.service_choice;db:zeek_bacnet.service_choice;kind:termfield;friendly:bacnet service_choice;help:bacnet service_choice");
  this.bacnet_dataField = this.api.addField("field:zeek_bacnet.data;db:zeek_bacnet.data;kind:termfield;friendly:bacnet data;help:bacnet data");
  this.bacnet_data_dict_dateField = this.api.addField("field:zeek_bacnet.data_dict.date;db:zeek_bacnet.data_dict.date;kind:termfield;friendly:bacnet data date;help:bacnet data date");
  this.bacnet_data_dict_low_limitField = this.api.addField("field:zeek_bacnet.data_dict.low_limit;db:zeek_bacnet.data_dict.low_limit;kind:termfield;friendly:bacnet data low_limit;help:bacnet data low_limit");
  this.bacnet_data_dict_objectField = this.api.addField("field:zeek_bacnet.data_dict.object;db:zeek_bacnet.data_dict.object;kind:termfield;friendly:bacnet data object;help:bacnet data object");
  this.bacnet_data_dict_propertyField = this.api.addField("field:zeek_bacnet.data_dict.property;db:zeek_bacnet.data_dict.property;kind:termfield;friendly:bacnet data property;help:bacnet data property");
  this.bacnet_data_dict_resultField = this.api.addField("field:zeek_bacnet.data_dict.result;db:zeek_bacnet.data_dict.result;kind:termfield;friendly:bacnet data result;help:bacnet data result");
  this.bacnet_data_dict_timeField = this.api.addField("field:zeek_bacnet.data_dict.time;db:zeek_bacnet.data_dict.time;kind:termfield;friendly:bacnet data time;help:bacnet data time");
  this.bacnet_data_dict_ttlField = this.api.addField("field:zeek_bacnet.data_dict.ttl;db:zeek_bacnet.data_dict.ttl;kind:integer;friendly:bacnet data ttl;help:bacnet data ttl");

  // cip.log
  // https://github.com/amzn/zeek-plugin-enip/blob/master/scripts/main.zeek
  this.cip_serviceField = this.api.addField("field:zeek_cip.cip_service;db:zeek_cip.cip_service;kind:termfield;friendly:cip service;help:cip service");
  this.cip_statusField = this.api.addField("field:zeek_cip.status;db:zeek_cip.status;kind:termfield;friendly:cip status;help:cip status");
  this.cip_tagsField = this.api.addField("field:zeek_cip.cip_tags;db:zeek_cip.cip_tags;kind:termfield;friendly:cip tags;help:cip tags");

  // dce_rpc.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dce-rpc/main.zeek.html#type-DCE_RPC::Info
  this.dce_rpc_rttField = this.api.addField("field:zeek_dce_rpc.rtt;db:zeek_dce_rpc.rtt;kind:termfield;friendly:dce_rpc rtt;help:dce_rpc rtt");
  this.dce_rpc_named_pipeField = this.api.addField("field:zeek_dce_rpc.named_pipe;db:zeek_dce_rpc.named_pipe;kind:termfield;friendly:dce_rpc named_pipe;help:dce_rpc named_pipe");
  this.dce_rpc_endpointField = this.api.addField("field:zeek_dce_rpc.endpoint;db:zeek_dce_rpc.endpoint;kind:termfield;friendly:dce_rpc endpoint;help:dce_rpc endpoint");
  this.dce_rpc_operationField = this.api.addField("field:zeek_dce_rpc.operation;db:zeek_dce_rpc.operation;kind:termfield;friendly:dce_rpc operation;help:dce_rpc operation");

  // dhcp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info
  this.dhcp_macField = this.api.addField("field:zeek_dhcp.mac;db:zeek_dhcp.mac;kind:termfield;friendly:dhcp mac;help:dhcp mac");
  this.dhcp_assigned_ipField = this.api.addField("field:zeek_dhcp.assigned_ip;db:zeek_dhcp.assigned_ip;kind:termfield;friendly:dhcp assigned_ip;help:dhcp assigned_ip");
  this.dhcp_lease_timeField = this.api.addField("field:zeek_dhcp.lease_time;db:zeek_dhcp.lease_time;kind:termfield;friendly:dhcp lease_time;help:dhcp lease_time");
  this.dhcp_trans_idField = this.api.addField("field:zeek_dhcp.trans_id;db:zeek_dhcp.trans_id;kind:integer;friendly:dhcp trans_id;help:dhcp trans_id");

  // dnp3.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dnp3/main.zeek.html#type-DNP3::Info
  this.dnp3_fc_requestField = this.api.addField("field:zeek_dnp3.fc_request;db:zeek_dnp3.fc_request;kind:termfield;friendly:dnp3 fc_request;help:dnp3 fc_request");
  this.dnp3_fc_replyField = this.api.addField("field:zeek_dnp3.fc_reply;db:zeek_dnp3.fc_reply;kind:termfield;friendly:dnp3 fc_reply;help:dnp3 fc_reply");
  this.dnp3_iinField = this.api.addField("field:zeek_dnp3.iin;db:zeek_dnp3.iin;kind:integer;friendly:dnp3 iin;help:dnp3 iin");

  // dns.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info
  this.dns_trans_idField = this.api.addField("field:zeek_dns.trans_id;db:zeek_dns.trans_id;kind:integer;friendly:dns trans_id;help:dns trans_id");
  this.dns_rttField = this.api.addField("field:zeek_dns.rtt;db:zeek_dns.rtt;kind:termfield;friendly:dns rtt;help:dns rtt");
  this.dns_queryField = this.api.addField("field:zeek_dns.query;db:zeek_dns.query;kind:termfield;friendly:dns query;help:dns query");
  this.dns_qclassField = this.api.addField("field:zeek_dns.qclass;db:zeek_dns.qclass;kind:integer;friendly:dns qclass;help:dns qclass");
  this.dns_qclass_nameField = this.api.addField("field:zeek_dns.qclass_name;db:zeek_dns.qclass_name;kind:termfield;friendly:dns qclass_name;help:dns qclass_name");
  this.dns_qtypeField = this.api.addField("field:zeek_dns.qtype;db:zeek_dns.qtype;kind:integer;friendly:dns qtype;help:dns qtype");
  this.dns_qtype_nameField = this.api.addField("field:zeek_dns.qtype_name;db:zeek_dns.qtype_name;kind:termfield;friendly:dns qtype_name;help:dns qtype_name");
  this.dns_rcodeField = this.api.addField("field:zeek_dns.rcode;db:zeek_dns.rcode;kind:integer;friendly:dns rcode;help:dns rcode");
  this.dns_rcode_nameField = this.api.addField("field:zeek_dns.rcode_name;db:zeek_dns.rcode_name;kind:termfield;friendly:dns rcode_name;help:dns rcode_name");
  this.dns_AAField = this.api.addField("field:zeek_dns.AA;db:zeek_dns.AA;kind:termfield;friendly:dns AA;help:dns AA");
  this.dns_TCField = this.api.addField("field:zeek_dns.TC;db:zeek_dns.TC;kind:termfield;friendly:dns TC;help:dns TC");
  this.dns_RDField = this.api.addField("field:zeek_dns.RD;db:zeek_dns.RD;kind:termfield;friendly:dns RD;help:dns RD");
  this.dns_RAField = this.api.addField("field:zeek_dns.RA;db:zeek_dns.RA;kind:termfield;friendly:dns RA;help:dns RA");
  this.dns_ZField = this.api.addField("field:zeek_dns.Z;db:zeek_dns.Z;kind:integer;friendly:dns Z;help:dns Z");
  this.dns_answersField = this.api.addField("field:zeek_dns.answers;db:zeek_dns.answers;kind:termfield;friendly:dns answers;help:dns answers");
  this.dns_TTLsField = this.api.addField("field:zeek_dns.TTLs;db:zeek_dns.TTLs;kind:termfield;friendly:dns TTLs;help:dns TTLs");
  this.dns_rejectedField = this.api.addField("field:zeek_dns.rejected;db:zeek_dns.rejected;kind:termfield;friendly:dns rejected;help:dns rejected");

  // dpd.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/dpd/main.zeek.html#type-DPD::Info
  this.dpd_serviceField = this.api.addField("field:zeek_dpd.service;db:zeek_dpd.service;kind:termfield;friendly:dpd service;help:dpd service");
  this.dpd_failure_reasonField = this.api.addField("field:zeek_dpd.failure_reason;db:zeek_dpd.failure_reason;kind:termfield;friendly:dpd failure_reason;help:dpd failure_reason");

  // enip.log
  // https://github.com/amzn/zeek-plugin-enip/blob/master/scripts/main.zeek
  this.enip_commandField = this.api.addField("field:zeek_enip.command;db:zeek_enip.command;kind:termfield;friendly:enip command;help:enip command");
  this.enip_lengthField = this.api.addField("field:zeek_enip.length;db:zeek_enip.length;kind:integer;friendly:enip length;help:enip length");
  this.enip_session_handleField = this.api.addField("field:zeek_enip.session_handle;db:zeek_enip.session_handle;kind:termfield;friendly:enip session_handle;help:enip session_handle");
  this.enip_statusField = this.api.addField("field:zeek_enip.status;db:zeek_enip.status;kind:termfield;friendly:enip status;help:enip status");
  this.enip_sender_contextField = this.api.addField("field:zeek_enip.sender_context;db:zeek_enip.sender_context;kind:termfield;friendly:enip sender_context;help:enip sender_context");
  this.enip_optionsField = this.api.addField("field:zeek_enip.options;db:zeek_enip.options;kind:termfield;friendly:enip options;help:enip options");

  // enip_list_identity.log
  // https://github.com/amzn/zeek-plugin-enip/blob/master/scripts/main.zeek
  this.enip_list_identity_device_typeField = this.api.addField("field:zeek_enip_list_identity.device_type;db:zeek_enip_list_identity.device_type;kind:termfield;friendly:enip_list_identity device_type;help:enip_list_identity device_type");
  this.enip_list_identity_vendorField = this.api.addField("field:zeek_enip_list_identity.vendor;db:zeek_enip_list_identity.vendor;kind:termfield;friendly:enip_list_identity vendor;help:enip_list_identity vendor");
  this.enip_list_identity_product_nameField = this.api.addField("field:zeek_enip_list_identity.product_name;db:zeek_enip_list_identity.product_name;kind:termfield;friendly:enip_list_identity product_name;help:enip_list_identity product_name");
  this.enip_list_identity_serial_numberField = this.api.addField("field:zeek_enip_list_identity.serial_number;db:zeek_enip_list_identity.serial_number;kind:termfield;friendly:enip_list_identity serial_number;help:enip_list_identity serial_number");
  this.enip_list_identity_product_codeField = this.api.addField("field:zeek_enip_list_identity.product_code;db:zeek_enip_list_identity.product_code;kind:integer;friendly:enip_list_identity product_code;help:enip_list_identity product_code");
  this.enip_list_identity_revisionField = this.api.addField("field:zeek_enip_list_identity.revision;db:zeek_enip_list_identity.revision;kind:termfield;friendly:enip_list_identity revision;help:enip_list_identity revision");
  this.enip_list_identity_statusField = this.api.addField("field:zeek_enip_list_identity.status;db:zeek_enip_list_identity.status;kind:termfield;friendly:enip_list_identity status;help:enip_list_identity status");
  this.enip_list_identity_stateField = this.api.addField("field:zeek_enip_list_identity.state;db:zeek_enip_list_identity.state;kind:termfield;friendly:enip_list_identity state;help:enip_list_identity state");
  this.enip_list_identity_device_ipField = this.api.addField("field:zeek_enip_list_identity.device_ip;db:zeek_enip_list_identity.device_ip;kind:termfield;friendly:enip_list_identity device_ip;help:enip_list_identity device_ip");

  // files.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/files/main.zeek.html#type-Files::Info
  this.files_fuidField = this.api.addField("field:zeek_files.fuid;db:zeek_files.fuid;kind:termfield;friendly:files fuid;help:files fuid");
  this.files_tx_hostsField = this.api.addField("field:zeek_files.tx_hosts;db:zeek_files.tx_hosts;kind:termfield;friendly:files tx_hosts;help:files tx_hosts");
  this.files_rx_hostsField = this.api.addField("field:zeek_files.rx_hosts;db:zeek_files.rx_hosts;kind:termfield;friendly:files rx_hosts;help:files rx_hosts");
  this.files_conn_uidsField = this.api.addField("field:zeek_files.conn_uids;db:zeek_files.conn_uids;kind:termfield;friendly:files conn_uids;help:files conn_uids");
  this.files_sourceField = this.api.addField("field:zeek_files.source;db:zeek_files.source;kind:termfield;friendly:files source;help:files source");
  this.files_depthField = this.api.addField("field:zeek_files.depth;db:zeek_files.depth;kind:integer;friendly:files depth;help:files depth");
  this.files_analyzersField = this.api.addField("field:zeek_files.analyzers;db:zeek_files.analyzers;kind:termfield;friendly:files analyzers;help:files analyzers");
  this.files_mime_typeField = this.api.addField("field:zeek_files.mime_type;db:zeek_files.mime_type;kind:termfield;friendly:files mime_type;help:files mime_type");
  this.files_filenameField = this.api.addField("field:zeek_files.filename;db:zeek_files.filename;kind:termfield;friendly:files filename;help:files filename");
  this.files_durationField = this.api.addField("field:zeek_files.duration;db:zeek_files.duration;kind:termfield;friendly:files duration;help:files duration");
  this.files_local_origField = this.api.addField("field:zeek_files.local_orig;db:zeek_files.local_orig;kind:termfield;friendly:files local_orig;help:files local_orig");
  this.files_is_origField = this.api.addField("field:zeek_files.is_orig;db:zeek_files.is_orig;kind:termfield;friendly:files is_orig;help:files is_orig");
  this.files_seen_bytesField = this.api.addField("field:zeek_files.seen_bytes;db:zeek_files.seen_bytes;kind:integer;friendly:files seen_bytes;help:files seen_bytes");
  this.files_total_bytesField = this.api.addField("field:zeek_files.total_bytes;db:zeek_files.total_bytes;kind:integer;friendly:files total_bytes;help:files total_bytes");
  this.files_missing_bytesField = this.api.addField("field:zeek_files.missing_bytes;db:zeek_files.missing_bytes;kind:integer;friendly:files missing_bytes;help:files missing_bytes");
  this.files_overflow_bytesField = this.api.addField("field:zeek_files.overflow_bytes;db:zeek_files.overflow_bytes;kind:integer;friendly:files overflow_bytes;help:files overflow_bytes");
  this.files_timedoutField = this.api.addField("field:zeek_files.timedout;db:zeek_files.timedout;kind:termfield;friendly:files timedout;help:files timedout");
  this.files_parent_fuidField = this.api.addField("field:zeek_files.parent_fuid;db:zeek_files.parent_fuid;kind:termfield;friendly:files parent_fuid;help:files parent_fuid");
  this.files_md5Field = this.api.addField("field:zeek_files.md5;db:zeek_files.md5;kind:termfield;friendly:files md5;help:files md5");
  this.files_sha1Field = this.api.addField("field:zeek_files.sha1;db:zeek_files.sha1;kind:termfield;friendly:files sha1;help:files sha1");
  this.files_sha256Field = this.api.addField("field:zeek_files.sha256;db:zeek_files.sha256;kind:termfield;friendly:files sha256;help:files sha256");
  this.files_extractedField = this.api.addField("field:zeek_files.extracted;db:zeek_files.extracted;kind:termfield;friendly:files extracted;help:files extracted");
  this.files_extracted_cutoffField = this.api.addField("field:zeek_files.extracted_cutoff;db:zeek_files.extracted_cutoff;kind:integer;friendly:files extracted_cutoff;help:files extracted_cutoff");
  this.files_extracted_sizeField = this.api.addField("field:zeek_files.extracted_size;db:zeek_files.extracted_size;kind:termfield;friendly:files extracted_size;help:files extracted_size");

  // ftp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ftp/info.zeek.html#type-FTP::Info
  this.ftp_passwordField = this.api.addField("field:zeek_ftp.password;db:zeek_ftp.password;kind:termfield;friendly:ftp password;help:ftp password");
  this.ftp_commandField = this.api.addField("field:zeek_ftp.command;db:zeek_ftp.command;kind:termfield;friendly:ftp command;help:ftp command");
  this.ftp_argField = this.api.addField("field:zeek_ftp.arg;db:zeek_ftp.arg;kind:termfield;friendly:ftp arg;help:ftp arg");
  this.ftp_mime_typeField = this.api.addField("field:zeek_ftp.mime_type;db:zeek_ftp.mime_type;kind:termfield;friendly:ftp mime_type;help:ftp mime_type");
  this.ftp_file_sizeField = this.api.addField("field:zeek_ftp.file_size;db:zeek_ftp.file_size;kind:integer;friendly:ftp file_size;help:ftp file_size");
  this.ftp_reply_codeField = this.api.addField("field:zeek_ftp.reply_code;db:zeek_ftp.reply_code;kind:integer;friendly:ftp reply_code;help:ftp reply_code");
  this.ftp_reply_msgField = this.api.addField("field:zeek_ftp.reply_msg;db:zeek_ftp.reply_msg;kind:termfield;friendly:ftp reply_msg;help:ftp reply_msg");
  this.ftp_data_channel_passiveField = this.api.addField("field:zeek_ftp.data_channel_passive;db:zeek_ftp.data_channel_passive;kind:termfield;friendly:ftp data_channel_passive;help:ftp data_channel_passive");
  this.ftp_data_channel_orig_hField = this.api.addField("field:zeek_ftp.data_channel_orig_h;db:zeek_ftp.data_channel_orig_h;kind:termfield;friendly:ftp data_channel_orig_h;help:ftp data_channel_orig_h");
  this.ftp_data_channel_resp_hField = this.api.addField("field:zeek_ftp.data_channel_resp_h;db:zeek_ftp.data_channel_resp_h;kind:termfield;friendly:ftp data_channel_resp_h;help:ftp data_channel_resp_h");
  this.ftp_data_channel_resp_pField = this.api.addField("field:zeek_ftp.data_channel_resp_p;db:zeek_ftp.data_channel_resp_p;kind:integer;friendly:ftp data_channel_resp_p;help:ftp data_channel_resp_p");
  this.ftp_fuidField = this.api.addField("field:zeek_ftp.fuid;db:zeek_ftp.fuid;kind:termfield;friendly:ftp fuid;help:ftp fuid");

  // gquic.log
  // https://github.com/salesforce/GQUIC_Protocol_Analyzer/blob/master/scripts/Salesforce/GQUIC/main.bro
  this.gquic_versionField = this.api.addField("field:zeek_gquic.version;db:zeek_gquic.version;kind:termfield;friendly:gquic version;help:gquic version");
  this.gquic_server_nameField = this.api.addField("field:zeek_gquic.server_name;db:zeek_gquic.server_name;kind:termfield;friendly:gquic server_name;help:gquic server_name");
  this.gquic_user_agentField = this.api.addField("field:zeek_gquic.user_agent;db:zeek_gquic.user_agent;kind:termfield;friendly:gquic user_agent;help:gquic user_agent");
  this.gquic_tag_countField = this.api.addField("field:zeek_gquic.tag_count;db:zeek_gquic.tag_count;kind:integer;friendly:gquic tag_count;help:gquic tag_count");
  this.gquic_cyuField = this.api.addField("field:zeek_gquic.cyu;db:zeek_gquic.cyu;kind:termfield;friendly:gquic cyu;help:gquic cyu");
  this.gquic_cyutagsField = this.api.addField("field:zeek_gquic.cyutags;db:zeek_gquic.cyutags;kind:termfield;friendly:gquic cyutags;help:gquic cyutags");

  // http.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info
  this.http_trans_depthField = this.api.addField("field:zeek_http.trans_depth;db:zeek_http.trans_depth;kind:integer;friendly:http trans_depth;help:http trans_depth");
  this.http_methodField = this.api.addField("field:zeek_http.method;db:zeek_http.method;kind:termfield;friendly:http method;help:http method");
  this.http_hostField = this.api.addField("field:zeek_http.host;db:zeek_http.host;kind:termfield;friendly:http host;help:http host");
  this.http_uriField = this.api.addField("field:zeek_http.uri;db:zeek_http.uri;kind:termfield;friendly:http uri;help:http uri");
  this.http_referrerField = this.api.addField("field:zeek_http.referrer;db:zeek_http.referrer;kind:termfield;friendly:http referrer;help:http referrer");
  this.http_versionField = this.api.addField("field:zeek_http.version;db:zeek_http.version;kind:termfield;friendly:http version;help:http version");
  this.http_user_agentField = this.api.addField("field:zeek_http.user_agent;db:zeek_http.user_agent;kind:termfield;friendly:http user_agent;help:http user_agent");
  this.http_originField = this.api.addField("field:zeek_http.origin;db:zeek_http.origin;kind:termfield;friendly:http origin;help:http origin");
  this.http_request_body_lenField = this.api.addField("field:zeek_http.request_body_len;db:zeek_http.request_body_len;kind:integer;friendly:http request_body_len;help:http request_body_len");
  this.http_response_body_lenField = this.api.addField("field:zeek_http.response_body_len;db:zeek_http.response_body_len;kind:integer;friendly:http response_body_len;help:http response_body_len");
  this.http_status_codeField = this.api.addField("field:zeek_http.status_code;db:zeek_http.status_code;kind:termfield;friendly:http status_code;help:http status_code");
  this.http_status_msgField = this.api.addField("field:zeek_http.status_msg;db:zeek_http.status_msg;kind:termfield;friendly:http status_msg;help:http status_msg");
  this.http_info_codeField = this.api.addField("field:zeek_http.info_code;db:zeek_http.info_code;kind:integer;friendly:http info_code;help:http info_code");
  this.http_info_msgField = this.api.addField("field:zeek_http.info_msg;db:zeek_http.info_msg;kind:termfield;friendly:http info_msg;help:http info_msg");
  this.http_tagsField = this.api.addField("field:zeek_http.tags;db:zeek_http.tags;kind:termfield;friendly:http tags;help:http tags");
  this.http_userField = this.api.addField("field:zeek_http.user;db:zeek_http.user;kind:termfield;friendly:http user;help:http user");
  this.http_passwordField = this.api.addField("field:zeek_http.password;db:zeek_http.password;kind:termfield;friendly:http password;help:http password");
  this.http_proxiedField = this.api.addField("field:zeek_http.proxied;db:zeek_http.proxied;kind:termfield;friendly:http proxied;help:http proxied");
  this.http_orig_fuidsField = this.api.addField("field:zeek_http.orig_fuids;db:zeek_http.orig_fuids;kind:termfield;friendly:http orig_fuids;help:http orig_fuids");
  this.http_orig_filenamesField = this.api.addField("field:zeek_http.orig_filenames;db:zeek_http.orig_filenames;kind:termfield;friendly:http orig_filenames;help:http orig_filenames");
  this.http_orig_mime_typesField = this.api.addField("field:zeek_http.orig_mime_types;db:zeek_http.orig_mime_types;kind:termfield;friendly:http orig_mime_types;help:http orig_mime_types");
  this.http_resp_fuidsField = this.api.addField("field:zeek_http.resp_fuids;db:zeek_http.resp_fuids;kind:termfield;friendly:http resp_fuids;help:http resp_fuids");
  this.http_resp_filenamesField = this.api.addField("field:zeek_http.resp_filenames;db:zeek_http.resp_filenames;kind:termfield;friendly:http resp_filenames;help:http resp_filenames");
  this.http_resp_mime_typesField = this.api.addField("field:zeek_http.resp_mime_types;db:zeek_http.resp_mime_types;kind:termfield;friendly:http resp_mime_types;help:http resp_mime_types");

  // intel.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Info
  this.intel_indicatorField = this.api.addField("field:zeek_intel.indicator;db:zeek_intel.indicator;kind:termfield;friendly:intel indicator;help:intel indicator");
  this.intel_indicator_typeField = this.api.addField("field:zeek_intel.indicator_type;db:zeek_intel.indicator_type;kind:termfield;friendly:intel indicator_type;help:intel indicator_type");
  this.intel_seen_whereField = this.api.addField("field:zeek_intel.seen_where;db:zeek_intel.seen_where;kind:termfield;friendly:intel seen_where;help:intel seen_where");
  this.intel_seen_nodeField = this.api.addField("field:zeek_intel.seen_node;db:zeek_intel.seen_node;kind:termfield;friendly:intel seen_node;help:intel seen_node");
  this.intel_matchedField = this.api.addField("field:zeek_intel.matched;db:zeek_intel.matched;kind:termfield;friendly:intel matched;help:intel matched");
  this.intel_sourcesField = this.api.addField("field:zeek_intel.sources;db:zeek_intel.sources;kind:termfield;friendly:intel sources;help:intel sources");
  this.intel_fuidField = this.api.addField("field:zeek_intel.fuid;db:zeek_intel.fuid;kind:termfield;friendly:intel fuid;help:intel fuid");
  this.intel_mimetypeField = this.api.addField("field:zeek_intel.mimetype;db:zeek_intel.mimetype;kind:termfield;friendly:intel mimetype;help:intel mimetype");
  this.intel_file_descriptionField = this.api.addField("field:zeek_intel.file_description;db:zeek_intel.file_description;kind:termfield;friendly:intel file_description;help:intel file_description");

  // irc.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/irc/main.zeek.html#type-IRC::Info
  this.irc_nickField = this.api.addField("field:zeek_irc.nick;db:zeek_irc.nick;kind:termfield;friendly:irc nick;help:irc nick");
  this.irc_commandField = this.api.addField("field:zeek_irc.command;db:zeek_irc.command;kind:termfield;friendly:irc command;help:irc command");
  this.irc_valueField = this.api.addField("field:zeek_irc.value;db:zeek_irc.value;kind:termfield;friendly:irc value;help:irc value");
  this.irc_addlField = this.api.addField("field:zeek_irc.addl;db:zeek_irc.addl;kind:termfield;friendly:irc addl;help:irc addl");
  this.irc_dcc_file_nameField = this.api.addField("field:zeek_irc.dcc_file_name;db:zeek_irc.dcc_file_name;kind:termfield;friendly:irc dcc_file_name;help:irc dcc_file_name");
  this.irc_dcc_file_sizeField = this.api.addField("field:zeek_irc.dcc_file_size;db:zeek_irc.dcc_file_size;kind:integer;friendly:irc dcc_file_size;help:irc dcc_file_size");
  this.irc_dcc_mime_typeField = this.api.addField("field:zeek_irc.dcc_mime_type;db:zeek_irc.dcc_mime_type;kind:termfield;friendly:irc dcc_mime_type;help:irc dcc_mime_type");
  this.irc_fuidField = this.api.addField("field:zeek_irc.fuid;db:zeek_irc.fuid;kind:termfield;friendly:irc fuid;help:irc fuid");

  // iso_cotp.log
  // https://github.com/amzn/zeek-plugin-s7comm/blob/master/scripts/main.zeek
  this.iso_cotp_pdu_typeField = this.api.addField("field:zeek_iso_cotp.pdu_type;db:zeek_iso_cotp.pdu_type;kind:termfield;friendly:iso_cotp pdu_type;help:iso_cotp pdu_type");

  // kerberos.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/krb/main.zeek.html#type-KRB::Info
  this.kerberos_cnameField = this.api.addField("field:zeek_kerberos.cname;db:zeek_kerberos.cname;kind:termfield;friendly:kerberos cname;help:kerberos cname");
  this.kerberos_snameField = this.api.addField("field:zeek_kerberos.sname;db:zeek_kerberos.sname;kind:termfield;friendly:kerberos sname;help:kerberos sname");
  this.kerberos_successField = this.api.addField("field:zeek_kerberos.success;db:zeek_kerberos.success;kind:termfield;friendly:kerberos success;help:kerberos success");
  this.kerberos_error_msgField = this.api.addField("field:zeek_kerberos.error_msg;db:zeek_kerberos.error_msg;kind:termfield;friendly:kerberos error_msg;help:kerberos error_msg");
  this.kerberos_fromField = this.api.addField("field:zeek_kerberos.from;db:zeek_kerberos.from;kind:termfield;friendly:kerberos from;help:kerberos from");
  this.kerberos_tillField = this.api.addField("field:zeek_kerberos.till;db:zeek_kerberos.till;kind:termfield;friendly:kerberos till;help:kerberos till");
  this.kerberos_cipherField = this.api.addField("field:zeek_kerberos.cipher;db:zeek_kerberos.cipher;kind:termfield;friendly:kerberos cipher;help:kerberos cipher");
  this.kerberos_forwardableField = this.api.addField("field:zeek_kerberos.forwardable;db:zeek_kerberos.forwardable;kind:termfield;friendly:kerberos forwardable;help:kerberos forwardable");
  this.kerberos_renewableField = this.api.addField("field:zeek_kerberos.renewable;db:zeek_kerberos.renewable;kind:termfield;friendly:kerberos renewable;help:kerberos renewable");
  this.kerberos_client_cert_subjectField = this.api.addField("field:zeek_kerberos.client_cert_subject;db:zeek_kerberos.client_cert_subject;kind:termfield;friendly:kerberos client_cert_subject;help:kerberos client_cert_subject");
  this.kerberos_client_cert_fuidField = this.api.addField("field:zeek_kerberos.client_cert_fuid;db:zeek_kerberos.client_cert_fuid;kind:termfield;friendly:kerberos client_cert_fuid;help:kerberos client_cert_fuid");
  this.kerberos_server_cert_subjectField = this.api.addField("field:zeek_kerberos.server_cert_subject;db:zeek_kerberos.server_cert_subject;kind:termfield;friendly:kerberos server_cert_subject;help:kerberos server_cert_subject");
  this.kerberos_server_cert_fuidField = this.api.addField("field:zeek_kerberos.server_cert_fuid;db:zeek_kerberos.server_cert_fuid;kind:termfield;friendly:kerberos server_cert_fuid;help:kerberos server_cert_fuid");

  // known_certs.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/ssl/known-certs.zeek.html#type-Known::CertsInfo
  this.known_certs_subjectField = this.api.addField("field:zeek_known_certs.subject;db:zeek_known_certs.subject;kind:termfield;friendly:known_certs subject;help:known_certs subject");
  this.known_certs_issuer_subjectField = this.api.addField("field:zeek_known_certs.issuer_subject;db:zeek_known_certs.issuer_subject;kind:termfield;friendly:known_certs issuer_subject;help:known_certs issuer_subject");
  this.known_certs_serialField = this.api.addField("field:zeek_known_certs.serial;db:zeek_known_certs.serial;kind:termfield;friendly:known_certs serial;help:known_certs serial");

  // known_modbus.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/known-masters-slaves.zeek.html#type-Known::ModbusInfo
  this.known_modbus_device_typeField = this.api.addField("field:zeek_known_modbus.device_type;db:zeek_known_modbus.device_type;kind:termfield;friendly:known_modbus device_type;help:known_modbus device_type");

  // modbus.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/modbus/main.zeek.html#type-Modbus::Info
  this.modbus_funcField = this.api.addField("field:zeek_modbus.func;db:zeek_modbus.func;kind:termfield;friendly:modbus func;help:modbus func");
  this.modbus_exceptionField = this.api.addField("field:zeek_modbus.exception;db:zeek_modbus.exception;kind:termfield;friendly:modbus exception;help:modbus exception");

  // modbus_register_change.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/track-memmap.zeek.html#type-Modbus::MemmapInfo
  this.modbus_register_change_registerField = this.api.addField("field:zeek_modbus_register_change.register;db:zeek_modbus_register_change.register;kind:integer;friendly:modbus_register_change register;help:modbus_register_change register");
  this.modbus_register_change_old_valField = this.api.addField("field:zeek_modbus_register_change.old_val;db:zeek_modbus_register_change.old_val;kind:integer;friendly:modbus_register_change old_val;help:modbus_register_change old_val");
  this.modbus_register_change_new_valField = this.api.addField("field:zeek_modbus_register_change.new_val;db:zeek_modbus_register_change.new_val;kind:integer;friendly:modbus_register_change new_val;help:modbus_register_change new_val");
  this.modbus_register_change_deltaField = this.api.addField("field:zeek_modbus_register_change.delta;db:zeek_modbus_register_change.delta;kind:termfield;friendly:modbus_register_change delta;help:modbus_register_change delta");

  // mqtt_connect.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::ConnectInfo
  this.mqtt_connect_proto_nameField = this.api.addField("field:zeek_mqtt_connect.proto_name;db:zeek_mqtt_connect.proto_name;kind:termfield;friendly:mqtt_connect proto_name;help:mqtt_connect proto_name");
  this.mqtt_connect_proto_versionField = this.api.addField("field:zeek_mqtt_connect.proto_version;db:zeek_mqtt_connect.proto_version;kind:termfield;friendly:mqtt_connect proto_version;help:mqtt_connect proto_version");
  this.mqtt_connect_client_idField = this.api.addField("field:zeek_mqtt_connect.client_id;db:zeek_mqtt_connect.client_id;kind:termfield;friendly:mqtt_connect client_id;help:mqtt_connect client_id");
  this.mqtt_connect_connect_statusField = this.api.addField("field:zeek_mqtt_connect.connect_status;db:zeek_mqtt_connect.connect_status;kind:termfield;friendly:mqtt_connect connect_status;help:mqtt_connect connect_status");
  this.mqtt_connect_will_topicField = this.api.addField("field:zeek_mqtt_connect.will_topic;db:zeek_mqtt_connect.will_topic;kind:termfield;friendly:mqtt_connect will_topic;help:mqtt_connect will_topic");
  this.mqtt_connect_will_payloadField = this.api.addField("field:zeek_mqtt_connect.will_payload;db:zeek_mqtt_connect.will_payload;kind:termfield;friendly:mqtt_connect will_payload;help:mqtt_connect will_payload");

  // mqtt_publish.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::PublishInfo
  this.mqtt_publish_from_clientField = this.api.addField("field:zeek_mqtt_publish.from_client;db:zeek_mqtt_publish.from_client;kind:termfield;friendly:mqtt_publish from_client;help:mqtt_publish from_client");
  this.mqtt_publish_retainField = this.api.addField("field:zeek_mqtt_publish.retain;db:zeek_mqtt_publish.retain;kind:termfield;friendly:mqtt_publish retain;help:mqtt_publish retain");
  this.mqtt_publish_qosField = this.api.addField("field:zeek_mqtt_publish.qos;db:zeek_mqtt_publish.qos;kind:termfield;friendly:mqtt_publish qos;help:mqtt_publish qos");
  this.mqtt_publish_statusField = this.api.addField("field:zeek_mqtt_publish.status;db:zeek_mqtt_publish.status;kind:termfield;friendly:mqtt_publish status;help:mqtt_publish status");
  this.mqtt_publish_topicField = this.api.addField("field:zeek_mqtt_publish.topic;db:zeek_mqtt_publish.topic;kind:termfield;friendly:mqtt_publish topic;help:mqtt_publish topic");
  this.mqtt_publish_payloadField = this.api.addField("field:zeek_mqtt_publish.payload;db:zeek_mqtt_publish.payload;kind:termfield;friendly:mqtt_publish payload;help:mqtt_publish payload");
  this.mqtt_publish_payload_lenField = this.api.addField("field:zeek_mqtt_publish.payload_len;db:zeek_mqtt_publish.payload_len;kind:integer;friendly:mqtt_publish payload_len;help:mqtt_publish payload_len");

  // mqtt_subscribe.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::SubscribeInfo
  this.mqtt_subscribe_actionField = this.api.addField("field:zeek_mqtt_subscribe.action;db:zeek_mqtt_subscribe.action;kind:termfield;friendly:mqtt_subscribe action;help:mqtt_subscribe action");
  this.mqtt_subscribe_topicsField = this.api.addField("field:zeek_mqtt_subscribe.topics;db:zeek_mqtt_subscribe.topics;kind:termfield;friendly:mqtt_subscribe topics;help:mqtt_subscribe topics");
  this.mqtt_subscribe_qos_levelsField = this.api.addField("field:zeek_mqtt_subscribe.qos_levels;db:zeek_mqtt_subscribe.qos_levels;kind:integer;friendly:mqtt_subscribe qos_levels;help:mqtt_subscribe qos_levels");
  this.mqtt_subscribe_granted_qos_levelField = this.api.addField("field:zeek_mqtt_subscribe.granted_qos_level;db:zeek_mqtt_subscribe.granted_qos_level;kind:integer;friendly:mqtt_subscribe granted_qos_level;help:mqtt_subscribe granted_qos_level");
  this.mqtt_subscribe_ackField = this.api.addField("field:zeek_mqtt_subscribe.ack;db:zeek_mqtt_subscribe.ack;kind:termfield;friendly:mqtt_subscribe ack;help:mqtt_subscribe ack");

  // mysql.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/mysql/main.zeek.html#type-MySQL::Info
  this.mysql_cmdField = this.api.addField("field:zeek_mysql.cmd;db:zeek_mysql.cmd;kind:termfield;friendly:mysql cmd;help:mysql cmd");
  this.mysql_argField = this.api.addField("field:zeek_mysql.arg;db:zeek_mysql.arg;kind:termfield;friendly:mysql arg;help:mysql arg");
  this.mysql_successField = this.api.addField("field:zeek_mysql.success;db:zeek_mysql.success;kind:termfield;friendly:mysql success;help:mysql success");
  this.mysql_rowsField = this.api.addField("field:zeek_mysql.rows;db:zeek_mysql.rows;kind:integer;friendly:mysql rows;help:mysql rows");
  this.mysql_responseField = this.api.addField("field:zeek_mysql.response;db:zeek_mysql.response;kind:termfield;friendly:mysql response;help:mysql response");

  // notice.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/main.zeek.html#type-Notice::Info
  this.notice_fuidField = this.api.addField("field:zeek_notice.fuid;db:zeek_notice.fuid;kind:termfield;friendly:notice fuid;help:notice fuid");
  this.notice_file_mime_typeField = this.api.addField("field:zeek_notice.file_mime_type;db:zeek_notice.file_mime_type;kind:termfield;friendly:notice file_mime_type;help:notice file_mime_type");
  this.notice_file_descField = this.api.addField("field:zeek_notice.file_desc;db:zeek_notice.file_desc;kind:termfield;friendly:notice file_desc;help:notice file_desc");
  this.notice_noteField = this.api.addField("field:zeek_notice.note;db:zeek_notice.note;kind:termfield;friendly:notice note;help:notice note");
  this.notice_msgField = this.api.addField("field:zeek_notice.msg;db:zeek_notice.msg;kind:termfield;friendly:notice msg;help:notice msg");
  this.notice_subField = this.api.addField("field:zeek_notice.sub;db:zeek_notice.sub;kind:termfield;friendly:notice sub;help:notice sub");
  this.notice_srcField = this.api.addField("field:zeek_notice.src;db:zeek_notice.src;kind:termfield;friendly:notice src;help:notice src");
  this.notice_dstField = this.api.addField("field:zeek_notice.dst;db:zeek_notice.dst;kind:termfield;friendly:notice dst;help:notice dst");
  this.notice_pField = this.api.addField("field:zeek_notice.p;db:zeek_notice.p;kind:integer;friendly:notice p;help:notice p");
  this.notice_nField = this.api.addField("field:zeek_notice.n;db:zeek_notice.n;kind:integer;friendly:notice n;help:notice n");
  this.notice_peer_descrField = this.api.addField("field:zeek_notice.peer_descr;db:zeek_notice.peer_descr;kind:termfield;friendly:notice peer_descr;help:notice peer_descr");
  this.notice_actionsField = this.api.addField("field:zeek_notice.actions;db:zeek_notice.actions;kind:termfield;friendly:notice actions;help:notice actions");
  this.notice_suppress_forField = this.api.addField("field:zeek_notice.suppress_for;db:zeek_notice.suppress_for;kind:termfield;friendly:notice suppress_for;help:notice suppress_for");
  this.notice_droppedField = this.api.addField("field:zeek_notice.dropped;db:zeek_notice.dropped;kind:termfield;friendly:notice dropped;help:notice dropped");
  this.notice_remote_location_country_codeField = this.api.addField("field:zeek_notice.remote_location_country_code;db:zeek_notice.remote_location_country_code;kind:termfield;friendly:notice remote_location_country_code;help:notice remote_location_country_code");
  this.notice_remote_location_regionField = this.api.addField("field:zeek_notice.remote_location_region;db:zeek_notice.remote_location_region;kind:termfield;friendly:notice remote_location_region;help:notice remote_location_region");
  this.notice_remote_location_cityField = this.api.addField("field:zeek_notice.remote_location_city;db:zeek_notice.remote_location_city;kind:termfield;friendly:notice remote_location_city;help:notice remote_location_city");
  this.notice_remote_location_latitudeField = this.api.addField("field:zeek_notice.remote_location_latitude;db:zeek_notice.remote_location_latitude;kind:termfield;friendly:notice remote_location_latitude;help:notice remote_location_latitude");
  this.notice_remote_location_longitudeField = this.api.addField("field:zeek_notice.remote_location_longitude;db:zeek_notice.remote_location_longitude;kind:termfield;friendly:notice remote_location_longitude;help:notice remote_location_longitude");

  // ntlm.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ntlm/main.zeek.html#type-NTLM::Info
  this.ntlm_hostField = this.api.addField("field:zeek_ntlm.host;db:zeek_ntlm.host;kind:termfield;friendly:ntlm host;help:ntlm host");
  this.ntlm_domainField = this.api.addField("field:zeek_ntlm.domain;db:zeek_ntlm.domain;kind:termfield;friendly:ntlm domain;help:ntlm domain");
  this.ntlm_successField = this.api.addField("field:zeek_ntlm.success;db:zeek_ntlm.success;kind:termfield;friendly:ntlm success;help:ntlm success");
  this.ntlm_statusField = this.api.addField("field:zeek_ntlm.status;db:zeek_ntlm.status;kind:termfield;friendly:ntlm status;help:ntlm status");

  // ntp.log
  // https://docs.zeek.org/en/latest/scripts/base/protocols/ntp/main.zeek.html#type-NTP::Info
  this.ntp_versionField = this.api.addField("field:zeek_ntp.version;db:zeek_ntp.version;kind:integer;friendly:ntp version;help:ntp version");
  this.ntp_modeField = this.api.addField("field:zeek_ntp.mode;db:zeek_ntp.mode;kind:integer;friendly:ntp mode;help:ntp mode code");
  this.ntp_mode_strField = this.api.addField("field:zeek_ntp.mode_str;db:zeek_ntp.mode_str;kind:termfield;friendly:ntp mode;help:ntp mode");
  this.ntp_stratumField = this.api.addField("field:zeek_ntp.stratum;db:zeek_ntp.stratum;kind:integer;friendly:ntp stratum;help:ntp stratum");
  this.ntp_pollField = this.api.addField("field:zeek_ntp.poll;db:zeek_ntp.poll;kind:termfield;friendly:ntp poll;help:ntp poll");
  this.ntp_precisionField = this.api.addField("field:zeek_ntp.precision;db:zeek_ntp.precision;kind:termfield;friendly:ntp precision;help:ntp precision");
  this.ntp_root_delayField = this.api.addField("field:zeek_ntp.root_delay;db:zeek_ntp.root_delay;kind:termfield;friendly:ntp root_delay;help:ntp root_delay");
  this.ntp_root_dispField = this.api.addField("field:zeek_ntp.root_disp;db:zeek_ntp.root_disp;kind:termfield;friendly:ntp root_disp;help:ntp root_disp");
  this.ntp_ref_idField = this.api.addField("field:zeek_ntp.ref_id;db:zeek_ntp.ref_id;kind:termfield;friendly:ntp ref_id;help:ntp ref_id");
  this.ntp_ref_timeField = this.api.addField("field:zeek_ntp.ref_time;db:zeek_ntp.ref_time;kind:termfield;friendly:ntp ref_time;help:ntp ref_time");
  this.ntp_org_timeField = this.api.addField("field:zeek_ntp.org_time;db:zeek_ntp.org_time;kind:termfield;friendly:ntp org_time;help:ntp org_time");
  this.ntp_rec_timeField = this.api.addField("field:zeek_ntp.rec_time;db:zeek_ntp.rec_time;kind:termfield;friendly:ntp rec_time;help:ntp rec_time");
  this.ntp_xmt_timeField = this.api.addField("field:zeek_ntp.xmt_time;db:zeek_ntp.xmt_time;kind:termfield;friendly:ntp xmt_time;help:ntp xmt_time");
  this.ntp_num_extsField = this.api.addField("field:zeek_ntp.num_exts;db:zeek_ntp.num_exts;kind:integer;friendly:ntp num_exts;help:ntp num_exts");

  // pe.log
  // https://docs.zeek.org/en/stable/scripts/base/files/pe/main.zeek.html#type-PE::Info
  this.pe_fuidField = this.api.addField("field:zeek_pe.fuid;db:zeek_pe.fuid;kind:termfield;friendly:pe fuid;help:pe fuid");
  this.pe_machineField = this.api.addField("field:zeek_pe.machine;db:zeek_pe.machine;kind:termfield;friendly:pe machine;help:pe machine");
  this.pe_compile_tsField = this.api.addField("field:zeek_pe.compile_ts;db:zeek_pe.compile_ts;kind:termfield;friendly:pe compile_ts;help:pe compile_ts");
  this.pe_osField = this.api.addField("field:zeek_pe.os;db:zeek_pe.os;kind:termfield;friendly:pe os;help:pe os");
  this.pe_subsystemField = this.api.addField("field:zeek_pe.subsystem;db:zeek_pe.subsystem;kind:termfield;friendly:pe subsystem;help:pe subsystem");
  this.pe_is_exeField = this.api.addField("field:zeek_pe.is_exe;db:zeek_pe.is_exe;kind:termfield;friendly:pe is_exe;help:pe is_exe");
  this.pe_is_64bitField = this.api.addField("field:zeek_pe.is_64bit;db:zeek_pe.is_64bit;kind:termfield;friendly:pe is_64bit;help:pe is_64bit");
  this.pe_uses_aslrField = this.api.addField("field:zeek_pe.uses_aslr;db:zeek_pe.uses_aslr;kind:termfield;friendly:pe uses_aslr;help:pe uses_aslr");
  this.pe_uses_depField = this.api.addField("field:zeek_pe.uses_dep;db:zeek_pe.uses_dep;kind:termfield;friendly:pe uses_dep;help:pe uses_dep");
  this.pe_uses_code_integrityField = this.api.addField("field:zeek_pe.uses_code_integrity;db:zeek_pe.uses_code_integrity;kind:termfield;friendly:pe uses_code_integrity;help:pe uses_code_integrity");
  this.pe_uses_sehField = this.api.addField("field:zeek_pe.uses_seh;db:zeek_pe.uses_seh;kind:termfield;friendly:pe uses_seh;help:pe uses_seh");
  this.pe_has_import_tableField = this.api.addField("field:zeek_pe.has_import_table;db:zeek_pe.has_import_table;kind:termfield;friendly:pe has_import_table;help:pe has_import_table");
  this.pe_has_export_tableField = this.api.addField("field:zeek_pe.has_export_table;db:zeek_pe.has_export_table;kind:termfield;friendly:pe has_export_table;help:pe has_export_table");
  this.pe_has_cert_tableField = this.api.addField("field:zeek_pe.has_cert_table;db:zeek_pe.has_cert_table;kind:termfield;friendly:pe has_cert_table;help:pe has_cert_table");
  this.pe_has_debug_dataField = this.api.addField("field:zeek_pe.has_debug_data;db:zeek_pe.has_debug_data;kind:termfield;friendly:pe has_debug_data;help:pe has_debug_data");
  this.pe_section_namesField = this.api.addField("field:zeek_pe.section_names;db:zeek_pe.section_names;kind:termfield;friendly:pe section_names;help:pe section_names");

  // profinet.log
  // https://docs.zeek.org/en/stable/scripts/base/files/pe/main.zeek.html#type-PE::Info
  this.profinet_operation_typeField = this.api.addField("field:zeek_profinet.operation_type;db:zeek_profinet.operation_type;kind:termfield;friendly:profinet operation_type;help:profinet operation_type");
  this.profinet_block_versionField = this.api.addField("field:zeek_profinet.block_version;db:zeek_profinet.block_version;kind:termfield;friendly:profinet block_version;help:profinet block_version");
  this.profinet_slot_numberField = this.api.addField("field:zeek_profinet.slot_number;db:zeek_profinet.slot_number;kind:integer;friendly:profinet slot_number;help:profinet slot_number");
  this.profinet_subslot_numberField = this.api.addField("field:zeek_profinet.subslot_number;db:zeek_profinet.subslot_number;kind:integer;friendly:profinet subslot_number;help:profinet subslot_number");
  this.profinet_indexField = this.api.addField("field:zeek_profinet.index;db:zeek_profinet.index;kind:termfield;friendly:profinet index;help:profinet index");

  // profinet_dce_rpc.log
  // https://docs.zeek.org/en/stable/scripts/base/files/pe/main.zeek.html#type-PE::Info
  this.profinet_dce_rpc_versionField = this.api.addField("field:zeek_profinet_dce_rpc.version;db:zeek_profinet_dce_rpc.version;kind:integer;friendly:profinet_dce_rpc version;help:profinet_dce_rpc version");
  this.profinet_dce_rpc_packet_typeField = this.api.addField("field:zeek_profinet_dce_rpc.packet_type;db:zeek_profinet_dce_rpc.packet_type;kind:integer;friendly:profinet_dce_rpc packet_type;help:profinet_dce_rpc packet_type");
  this.profinet_dce_rpc_object_uuidField = this.api.addField("field:zeek_profinet_dce_rpc.object_uuid;db:zeek_profinet_dce_rpc.object_uuid;kind:termfield;friendly:profinet_dce_rpc object_uuid;help:profinet_dce_rpc object_uuid");
  this.profinet_dce_rpc_interface_uuidField = this.api.addField("field:zeek_profinet_dce_rpc.interface_uuid;db:zeek_profinet_dce_rpc.interface_uuid;kind:termfield;friendly:profinet_dce_rpc interface_uuid;help:profinet_dce_rpc interface_uuid");
  this.profinet_dce_rpc_activity_uuidField = this.api.addField("field:zeek_profinet_dce_rpc.activity_uuid;db:zeek_profinet_dce_rpc.activity_uuid;kind:termfield;friendly:profinet_dce_rpc activity_uuid;help:profinet_dce_rpc activity_uuid");
  this.profinet_dce_rpc_server_boot_timeField = this.api.addField("field:zeek_profinet_dce_rpc.server_boot_time;db:zeek_profinet_dce_rpc.server_boot_time;kind:integer;friendly:profinet_dce_rpc server_boot_time;help:profinet_dce_rpc server_boot_time");
  this.profinet_dce_rpc_operationField = this.api.addField("field:zeek_profinet_dce_rpc.operation;db:zeek_profinet_dce_rpc.operation;kind:termfield;friendly:profinet_dce_rpc operation;help:profinet_dce_rpc operation");

  // radius.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/radius/main.zeek.html#type-RADIUS::Info
  this.radius_macField = this.api.addField("field:zeek_radius.mac;db:zeek_radius.mac;kind:termfield;friendly:radius mac;help:radius mac");
  this.radius_framed_addrField = this.api.addField("field:zeek_radius.framed_addr;db:zeek_radius.framed_addr;kind:termfield;friendly:radius framed_addr;help:radius framed_addr");
  this.radius_remote_ipField = this.api.addField("field:zeek_radius.remote_ip;db:zeek_radius.remote_ip;kind:termfield;friendly:radius remote_ip;help:radius remote_ip");
  this.radius_connect_infoField = this.api.addField("field:zeek_radius.connect_info;db:zeek_radius.connect_info;kind:termfield;friendly:radius connect_info;help:radius connect_info");
  this.radius_reply_msgField = this.api.addField("field:zeek_radius.reply_msg;db:zeek_radius.reply_msg;kind:termfield;friendly:radius reply_msg;help:radius reply_msg");
  this.radius_resultField = this.api.addField("field:zeek_radius.result;db:zeek_radius.result;kind:termfield;friendly:radius result;help:radius result");
  this.radius_ttlField = this.api.addField("field:zeek_radius.ttl;db:zeek_radius.ttl;kind:termfield;friendly:radius ttl;help:radius ttl");

  // rdp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/rdp/main.zeek.html#type-RDP::Info
  this.rdp_cookieField = this.api.addField("field:zeek_rdp.cookie;db:zeek_rdp.cookie;kind:termfield;friendly:rdp cookie;help:rdp cookie");
  this.rdp_resultField = this.api.addField("field:zeek_rdp.result;db:zeek_rdp.result;kind:termfield;friendly:rdp result;help:rdp result");
  this.rdp_security_protocolField = this.api.addField("field:zeek_rdp.security_protocol;db:zeek_rdp.security_protocol;kind:termfield;friendly:rdp security_protocol;help:rdp security_protocol");
  this.rdp_client_channelsField = this.api.addField("field:zeek_rdp.client_channels;db:zeek_rdp.client_channels;kind:termfield;friendly:rdp client_channels;help:rdp client_channels");
  this.rdp_keyboard_layoutField = this.api.addField("field:zeek_rdp.keyboard_layout;db:zeek_rdp.keyboard_layout;kind:termfield;friendly:rdp keyboard_layout;help:rdp keyboard_layout");
  this.rdp_client_buildField = this.api.addField("field:zeek_rdp.client_build;db:zeek_rdp.client_build;kind:termfield;friendly:rdp client_build;help:rdp client_build");
  this.rdp_client_nameField = this.api.addField("field:zeek_rdp.client_name;db:zeek_rdp.client_build;kind:termfield;friendly:rdp client_build;help:rdp client_build");
  this.rdp_client_dig_product_idField = this.api.addField("field:zeek_rdp.client_dig_product_id;db:zeek_rdp.client_dig_product_id;kind:termfield;friendly:rdp client_dig_product_id;help:rdp client_dig_product_id");
  this.rdp_desktop_widthField = this.api.addField("field:zeek_rdp.desktop_width;db:zeek_rdp.desktop_width;kind:integer;friendly:rdp desktop_width;help:rdp desktop_width");
  this.rdp_desktop_heightField = this.api.addField("field:zeek_rdp.desktop_height;db:zeek_rdp.desktop_height;kind:integer;friendly:rdp desktop_height;help:rdp desktop_height");
  this.rdp_requested_color_depthField = this.api.addField("field:zeek_rdp.requested_color_depth;db:zeek_rdp.requested_color_depth;kind:termfield;friendly:rdp requested_color_depth;help:rdp requested_color_depth");
  this.rdp_cert_typeField = this.api.addField("field:zeek_rdp.cert_type;db:zeek_rdp.cert_type;kind:termfield;friendly:rdp cert_type;help:rdp cert_type");
  this.rdp_cert_countField = this.api.addField("field:zeek_rdp.cert_count;db:zeek_rdp.cert_count;kind:integer;friendly:rdp cert_count;help:rdp cert_count");
  this.rdp_cert_permanentField = this.api.addField("field:zeek_rdp.cert_permanent;db:zeek_rdp.cert_permanent;kind:termfield;friendly:rdp cert_permanent;help:rdp cert_permanent");
  this.rdp_encryption_levelField = this.api.addField("field:zeek_rdp.encryption_level;db:zeek_rdp.encryption_level;kind:termfield;friendly:rdp encryption_level;help:rdp encryption_level");
  this.rdp_encryption_methodField = this.api.addField("field:zeek_rdp.encryption_method;db:zeek_rdp.encryption_method;kind:termfield;friendly:rdp encryption_method;help:rdp encryption_method");

  // rfb.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/rfb/main.zeek.html#type-RFB::Info
  this.rfb_client_major_versionField = this.api.addField("field:zeek_rfb.client_major_version;db:zeek_rfb.client_major_version;kind:termfield;friendly:rfb client_major_version;help:rfb client_major_version");
  this.rfb_client_minor_versionField = this.api.addField("field:zeek_rfb.client_minor_version;db:zeek_rfb.client_minor_version;kind:termfield;friendly:rfb client_minor_version;help:rfb client_minor_version");
  this.rfb_server_major_versionField = this.api.addField("field:zeek_rfb.server_major_version;db:zeek_rfb.server_major_version;kind:termfield;friendly:rfb server_major_version;help:rfb server_major_version");
  this.rfb_server_minor_versionField = this.api.addField("field:zeek_rfb.server_minor_version;db:zeek_rfb.server_minor_version;kind:termfield;friendly:rfb server_minor_version;help:rfb server_minor_version");
  this.rfb_authentication_methodField = this.api.addField("field:zeek_rfb.authentication_method;db:zeek_rfb.authentication_method;kind:termfield;friendly:rfb authentication_method;help:rfb authentication_method");
  this.rfb_authField = this.api.addField("field:zeek_rfb.auth;db:zeek_rfb.auth;kind:termfield;friendly:rfb auth;help:rfb auth");
  this.rfb_share_flagField = this.api.addField("field:zeek_rfb.share_flag;db:zeek_rfb.share_flag;kind:termfield;friendly:rfb share_flag;help:rfb share_flag");
  this.rfb_desktop_nameField = this.api.addField("field:zeek_rfb.desktop_name;db:zeek_rfb.desktop_name;kind:termfield;friendly:rfb desktop_name;help:rfb desktop_name");
  this.rfb_widthField = this.api.addField("field:zeek_rfb.width;db:zeek_rfb.width;kind:integer;friendly:rfb width;help:rfb width");
  this.rfb_heightField = this.api.addField("field:zeek_rfb.height;db:zeek_rfb.height;kind:integer;friendly:rfb height;help:rfb height");

  // s7comm.log
  // https://github.com/amzn/zeek-plugin-s7comm/blob/master/scripts/main.zeek
  this.s7comm_rosctrField = this.api.addField("field:zeek_s7comm.rosctr;db:zeek_s7comm.rosctr;kind:termfield;friendly:s7comm rosctr;help:s7comm rosctr");
  this.s7comm_parameterField = this.api.addField("field:zeek_s7comm.parameter;db:zeek_s7comm.parameter;kind:termfield;friendly:s7comm parameter;help:s7comm parameter");
  this.s7comm_parameters_classField = this.api.addField("field:zeek_s7comm.parameters.class;db:zeek_s7comm.parameters.class;kind:termfield;friendly:s7comm class parameter;help:s7comm class parameter");
  this.s7comm_parameters_codeField = this.api.addField("field:zeek_s7comm.parameters.code;db:zeek_s7comm.parameters.code;kind:termfield;friendly:s7comm code parameter;help:s7comm code parameter");
  this.s7comm_parameters_groupField = this.api.addField("field:zeek_s7comm.parameters.group;db:zeek_s7comm.parameters.group;kind:termfield;friendly:s7comm group parameter;help:s7comm group parameter");
  this.s7comm_parameters_modeField = this.api.addField("field:zeek_s7comm.parameters.mode;db:zeek_s7comm.parameters.mode;kind:termfield;friendly:s7comm mode parameter;help:s7comm mode parameter");
  this.s7comm_parameters_subField = this.api.addField("field:zeek_s7comm.parameters.sub;db:zeek_s7comm.parameters.sub;kind:termfield;friendly:s7comm sub parameter;help:s7comm sub parameter");
  this.s7comm_parameters_typeField = this.api.addField("field:zeek_s7comm.parameters.type;db:zeek_s7comm.parameters.type;kind:termfield;friendly:s7comm type parameter;help:s7comm type parameter");
  this.s7comm_item_countField = this.api.addField("field:zeek_s7comm.item_count;db:zeek_s7comm.item_count;kind:integer;friendly:s7comm item_count;help:s7comm item_count");
  this.s7comm_data_infoField = this.api.addField("field:zeek_s7comm.data_info;db:zeek_s7comm.data_info;kind:termfield;friendly:s7comm data_info;help:s7comm data_info");

  // signatures.log
  this.signatures_noteField = this.api.addField("field:zeek_signatures.note;db:zeek_signatures.note;kind:termfield;friendly:signatures note;help:signatures note");
  this.signatures_signature_idField = this.api.addField("field:zeek_signatures.signature_id;db:zeek_signatures.signature_id;kind:termfield;friendly:signatures signature_id;help:signatures signature_id");
  this.signatures_event_messageField = this.api.addField("field:zeek_signatures.event_message;db:zeek_signatures.event_message;kind:termfield;friendly:signatures event_message;help:signatures event_message");
  this.signatures_sub_messageField = this.api.addField("field:zeek_signatures.sub_message;db:zeek_signatures.sub_message;kind:termfield;friendly:signatures sub_message;help:signatures sub_message");
  this.signatures_signature_countField = this.api.addField("field:zeek_signatures.signature_count;db:zeek_signatures.signature_count;kind:integer;friendly:signatures signature_count;help:signatures signature_count");
  this.signatures_host_countField = this.api.addField("field:zeek_signatures.host_count;db:zeek_signatures.host_count;kind:integer;friendly:signatures host_count;help:signatures host_count");
  this.signatures_engineField = this.api.addField("field:zeek_signatures.engine;db:zeek_signatures.engine;kind:termfield;friendly:signatures engine;help:signatures engine");
  this.signatures_hitsField = this.api.addField("field:zeek_signatures.hits;db:zeek_signatures.hits;kind:termfield;friendly:signatures hits;help:signatures hits");

  // sip.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/sip/main.zeek.html#type-SIP::Info
  this.sip_trans_depthField = this.api.addField("field:zeek_sip.trans_depth;db:zeek_sip.trans_depth;kind:integer;friendly:sip trans_depth;help:sip trans_depth");
  this.sip_methodField = this.api.addField("field:zeek_sip.method;db:zeek_sip.method;kind:termfield;friendly:sip method;help:sip method");
  this.sip_uriField = this.api.addField("field:zeek_sip.uri;db:zeek_sip.uri;kind:termfield;friendly:sip uri;help:sip uri");
  this.sip_dateField = this.api.addField("field:zeek_sip.date;db:zeek_sip.date;kind:termfield;friendly:sip date;help:sip date");
  this.sip_request_fromField = this.api.addField("field:zeek_sip.request_from;db:zeek_sip.request_from;kind:termfield;friendly:sip request_from;help:sip request_from");
  this.sip_request_toField = this.api.addField("field:zeek_sip.request_to;db:zeek_sip.request_to;kind:termfield;friendly:sip request_to;help:sip request_to");
  this.sip_response_fromField = this.api.addField("field:zeek_sip.response_from;db:zeek_sip.response_from;kind:termfield;friendly:sip response_from;help:sip response_from");
  this.sip_response_toField = this.api.addField("field:zeek_sip.response_to;db:zeek_sip.response_to;kind:termfield;friendly:sip response_to;help:sip response_to");
  this.sip_reply_toField = this.api.addField("field:zeek_sip.reply_to;db:zeek_sip.reply_to;kind:termfield;friendly:sip reply_to;help:sip reply_to");
  this.sip_call_idField = this.api.addField("field:zeek_sip.call_id;db:zeek_sip.call_id;kind:termfield;friendly:sip call_id;help:sip call_id");
  this.sip_seqField = this.api.addField("field:zeek_sip.seq;db:zeek_sip.seq;kind:termfield;friendly:sip seq;help:sip seq");
  this.sip_subjectField = this.api.addField("field:zeek_sip.subject;db:zeek_sip.subject;kind:termfield;friendly:sip subject;help:sip subject");
  this.sip_request_pathField = this.api.addField("field:zeek_sip.request_path;db:zeek_sip.request_path;kind:termfield;friendly:sip request_path;help:sip request_path");
  this.sip_response_pathField = this.api.addField("field:zeek_sip.response_path;db:zeek_sip.response_path;kind:termfield;friendly:sip response_path;help:sip response_path");
  this.sip_user_agentField = this.api.addField("field:zeek_sip.user_agent;db:zeek_sip.user_agent;kind:termfield;friendly:sip user_agent;help:sip user_agent");
  this.sip_status_codeField = this.api.addField("field:zeek_sip.status_code;db:zeek_sip.status_code;kind:termfield;friendly:sip status_code;help:sip status_code");
  this.sip_status_msgField = this.api.addField("field:zeek_sip.status_msg;db:zeek_sip.status_msg;kind:termfield;friendly:sip status_msg;help:sip status_msg");
  this.sip_warningField = this.api.addField("field:zeek_sip.warning;db:zeek_sip.warning;kind:termfield;friendly:sip warning;help:sip warning");
  this.sip_request_body_lenField = this.api.addField("field:zeek_sip.request_body_len;db:zeek_sip.request_body_len;kind:integer;friendly:sip request_body_len;help:sip request_body_len");
  this.sip_response_body_lenField = this.api.addField("field:zeek_sip.response_body_len;db:zeek_sip.response_body_len;kind:integer;friendly:sip response_body_len;help:sip response_body_len");
  this.sip_content_typeField = this.api.addField("field:zeek_sip.content_type;db:zeek_sip.content_type;kind:termfield;friendly:sip content_type;help:sip content_type");

  // smb_files.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::FileInfo
  this.smb_files_fuidField = this.api.addField("field:zeek_smb_files.fuid;db:zeek_smb_files.fuid;kind:termfield;friendly:smb_files fuid;help:smb_files fuid");
  this.smb_files_actionField = this.api.addField("field:zeek_smb_files.action;db:zeek_smb_files.action;kind:termfield;friendly:smb_files action;help:smb_files action");
  this.smb_files_pathField = this.api.addField("field:zeek_smb_files.path;db:zeek_smb_files.path;kind:termfield;friendly:smb_files path;help:smb_files path");
  this.smb_files_nameField = this.api.addField("field:zeek_smb_files.name;db:zeek_smb_files.name;kind:termfield;friendly:smb_files name;help:smb_files name");
  this.smb_files_sizeField = this.api.addField("field:zeek_smb_files.size;db:zeek_smb_files.size;kind:integer;friendly:smb_files size;help:smb_files size");
  this.smb_files_prev_nameField = this.api.addField("field:zeek_smb_files.prev_name;db:zeek_smb_files.prev_name;kind:termfield;friendly:smb_files prev_name;help:smb_files prev_name");
  this.smb_files_times_modifiedField = this.api.addField("field:zeek_smb_files.times_modified;db:zeek_smb_files.times_modified;kind:termfield;friendly:smb_files times_modified;help:smb_files times_modified");
  this.smb_files_times_accessedField = this.api.addField("field:zeek_smb_files.times_accessed;db:zeek_smb_files.times_accessed;kind:termfield;friendly:smb_files times_accessed;help:smb_files times_accessed");
  this.smb_files_times_createdField = this.api.addField("field:zeek_smb_files.times_created;db:zeek_smb_files.times_created;kind:termfield;friendly:smb_files times_created;help:smb_files times_created");
  this.smb_files_times_changedField = this.api.addField("field:zeek_smb_files.times_changed;db:zeek_smb_files.times_changed;kind:termfield;friendly:smb_files times_changed;help:smb_files times_changed");

  // smb_mapping.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::TreeInfo
  this.smb_mapping_pathField = this.api.addField("field:zeek_smb_mapping.path;db:zeek_smb_mapping.path;kind:termfield;friendly:smb_mapping path;help:smb_mapping path");
  this.smb_mapping_resource_typeField = this.api.addField("field:zeek_smb_mapping.resource_type;db:zeek_smb_mapping.resource_type;kind:termfield;friendly:smb_mapping resource_type;help:smb_mapping resource_type");
  this.smb_mapping_native_file_systemField = this.api.addField("field:zeek_smb_mapping.native_file_system;db:zeek_smb_mapping.native_file_system;kind:termfield;friendly:smb_mapping native_file_system;help:smb_mapping native_file_system");
  this.smb_mapping_share_typeField = this.api.addField("field:zeek_smb_mapping.share_type;db:zeek_smb_mapping.share_type;kind:termfield;friendly:smb_mapping share_type;help:smb_mapping share_type");

  // smtp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smtp/main.zeek.html#type-SMTP::Info
  this.smtp_trans_depthField = this.api.addField("field:zeek_smtp.trans_depth;db:zeek_smtp.trans_depth;kind:integer;friendly:smtp trans_depth;help:smtp trans_depth");
  this.smtp_heloField = this.api.addField("field:zeek_smtp.helo;db:zeek_smtp.helo;kind:termfield;friendly:smtp helo;help:smtp helo");
  this.smtp_mailfromField = this.api.addField("field:zeek_smtp.mailfrom;db:zeek_smtp.mailfrom;kind:termfield;friendly:smtp mailfrom;help:smtp mailfrom");
  this.smtp_rcpttoField = this.api.addField("field:zeek_smtp.rcptto;db:zeek_smtp.rcptto;kind:termfield;friendly:smtp rcptto;help:smtp rcptto");
  this.smtp_dateField = this.api.addField("field:zeek_smtp.date;db:zeek_smtp.date;kind:termfield;friendly:smtp date;help:smtp date");
  this.smtp_fromField = this.api.addField("field:zeek_smtp.from;db:zeek_smtp.from;kind:termfield;friendly:smtp from;help:smtp from");
  this.smtp_toField = this.api.addField("field:zeek_smtp.to;db:zeek_smtp.to;kind:termfield;friendly:smtp to;help:smtp to");
  this.smtp_ccField = this.api.addField("field:zeek_smtp.cc;db:zeek_smtp.cc;kind:termfield;friendly:smtp cc;help:smtp cc");
  this.smtp_reply_toField = this.api.addField("field:zeek_smtp.reply_to;db:zeek_smtp.reply_to;kind:termfield;friendly:smtp reply_to;help:smtp reply_to");
  this.smtp_msg_idField = this.api.addField("field:zeek_smtp.msg_id;db:zeek_smtp.msg_id;kind:termfield;friendly:smtp msg_id;help:smtp msg_id");
  this.smtp_in_reply_toField = this.api.addField("field:zeek_smtp.in_reply_to;db:zeek_smtp.in_reply_to;kind:termfield;friendly:smtp in_reply_to;help:smtp in_reply_to");
  this.smtp_subjectField = this.api.addField("field:zeek_smtp.subject;db:zeek_smtp.subject;kind:termfield;friendly:smtp subject;help:smtp subject");
  this.smtp_x_originating_ipField = this.api.addField("field:zeek_smtp.x_originating_ip;db:zeek_smtp.x_originating_ip;kind:termfield;friendly:smtp x_originating_ip;help:smtp x_originating_ip");
  this.smtp_first_receivedField = this.api.addField("field:zeek_smtp.first_received;db:zeek_smtp.first_received;kind:termfield;friendly:smtp first_received;help:smtp first_received");
  this.smtp_second_receivedField = this.api.addField("field:zeek_smtp.second_received;db:zeek_smtp.second_received;kind:termfield;friendly:smtp second_received;help:smtp second_received");
  this.smtp_last_replyField = this.api.addField("field:zeek_smtp.last_reply;db:zeek_smtp.last_reply;kind:termfield;friendly:smtp last_reply;help:smtp last_reply");
  this.smtp_pathField = this.api.addField("field:zeek_smtp.path;db:zeek_smtp.path;kind:termfield;friendly:smtp path;help:smtp path");
  this.smtp_user_agentField = this.api.addField("field:zeek_smtp.user_agent;db:zeek_smtp.user_agent;kind:termfield;friendly:smtp user_agent;help:smtp user_agent");
  this.smtp_tlsField = this.api.addField("field:zeek_smtp.tls;db:zeek_smtp.tls;kind:termfield;friendly:smtp tls;help:smtp tls");
  this.smtp_fuidsField = this.api.addField("field:zeek_smtp.fuids;db:zeek_smtp.fuids;kind:termfield;friendly:smtp fuids;help:smtp fuids");
  this.smtp_is_webmailField = this.api.addField("field:zeek_smtp.is_webmail;db:zeek_smtp.is_webmail;kind:termfield;friendly:smtp is_webmail;help:smtp is_webmail");

  // snmp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/snmp/main.zeek.html#type-SNMP::Info
  this.snmp_durationField = this.api.addField("field:zeek_snmp.duration;db:zeek_snmp.duration;kind:termfield;friendly:snmp duration;help:snmp duration");
  this.snmp_versionField = this.api.addField("field:zeek_snmp.version;db:zeek_snmp.version;kind:termfield;friendly:snmp version;help:snmp version");
  this.snmp_communityField = this.api.addField("field:zeek_snmp.community;db:zeek_snmp.community;kind:termfield;friendly:snmp community;help:snmp community");
  this.snmp_get_requestsField = this.api.addField("field:zeek_snmp.get_requests;db:zeek_snmp.get_requests;kind:termfield;friendly:snmp get_requests;help:snmp get_requests");
  this.snmp_get_bulk_requestsField = this.api.addField("field:zeek_snmp.get_bulk_requests;db:zeek_snmp.get_bulk_requests;kind:integer;friendly:snmp get_bulk_requests;help:snmp get_bulk_requests");
  this.snmp_get_responsesField = this.api.addField("field:zeek_snmp.get_responses;db:zeek_snmp.get_responses;kind:integer;friendly:snmp get_responses;help:snmp get_responses");
  this.snmp_set_requestsField = this.api.addField("field:zeek_snmp.set_requests;db:zeek_snmp.set_requests;kind:integer;friendly:snmp set_requests;help:snmp set_requests");
  this.snmp_display_stringField = this.api.addField("field:zeek_snmp.display_string;db:zeek_snmp.display_string;kind:termfield;friendly:snmp display_string;help:snmp display_string");
  this.snmp_up_sinceField = this.api.addField("field:zeek_snmp.up_since;db:zeek_snmp.up_since;kind:termfield;friendly:snmp up_since;help:snmp up_since");

  // socks.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/socks/main.zeek.html#type-SOCKS::Info
  this.socks_versionField = this.api.addField("field:zeek_socks.version;db:zeek_socks.version;kind:integer;friendly:socks version;help:socks version");
  this.socks_passwordField = this.api.addField("field:zeek_socks.password;db:zeek_socks.password;kind:termfield;friendly:socks password;help:socks password");
  this.socks_server_statusField = this.api.addField("field:zeek_socks.server_status;db:zeek_socks.server_status;kind:termfield;friendly:socks server_status;help:socks server_status");
  this.socks_request_hostField = this.api.addField("field:zeek_socks.request_host;db:zeek_socks.request_host;kind:termfield;friendly:socks request_host;help:socks request_host");
  this.socks_request_nameField = this.api.addField("field:zeek_socks.request_name;db:zeek_socks.request_name;kind:termfield;friendly:socks request_name;help:socks request_name");
  this.socks_request_portField = this.api.addField("field:zeek_socks.request_port;db:zeek_socks.request_port;kind:integer;friendly:socks request_port;help:socks request_port");
  this.socks_bound_hostField = this.api.addField("field:zeek_socks.bound_host;db:zeek_socks.bound_host;kind:termfield;friendly:socks bound_host;help:socks bound_host");
  this.socks_bound_nameField = this.api.addField("field:zeek_socks.bound_name;db:zeek_socks.bound_name;kind:termfield;friendly:socks bound_name;help:socks bound_name");
  this.socks_bound_portField = this.api.addField("field:zeek_socks.bound_port;db:zeek_socks.bound_port;kind:integer;friendly:socks bound_port;help:socks bound_port");

  // software.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/software/main.zeek.html#type-Software::Info
  this.software_software_typeField = this.api.addField("field:zeek_software.software_type;db:zeek_software.software_type;kind:termfield;friendly:software software_type;help:software software_type");
  this.software_nameField = this.api.addField("field:zeek_software.name;db:zeek_software.name;kind:termfield;friendly:software name;help:software name");
  this.software_version_majorField = this.api.addField("field:zeek_software.version_major;db:zeek_software.version_major;kind:integer;friendly:software version_major;help:software version_major");
  this.software_version_minorField = this.api.addField("field:zeek_software.version_minor;db:zeek_software.version_minor;kind:integer;friendly:software version_minor;help:software version_minor");
  this.software_version_minor2Field = this.api.addField("field:zeek_software.version_minor2;db:zeek_software.version_minor2;kind:integer;friendly:software version_minor2;help:software version_minor2");
  this.software_version_minor3Field = this.api.addField("field:zeek_software.version_minor3;db:zeek_software.version_minor3;kind:integer;friendly:software version_minor3;help:software version_minor3");
  this.software_version_addlField = this.api.addField("field:zeek_software.version_addl;db:zeek_software.version_addl;kind:termfield;friendly:software version_addl;help:software version_addl");
  this.software_unparsed_versionField = this.api.addField("field:zeek_software.unparsed_version;db:zeek_software.unparsed_version;kind:termfield;friendly:software unparsed_version;help:software unparsed_version");

  // ssh.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ssh/main.zeek.html#type-SSH::Info
  this.ssh_versionField = this.api.addField("field:zeek_ssh.version;db:zeek_ssh.version;kind:integer;friendly:ssh version;help:ssh version");
  this.ssh_auth_successField = this.api.addField("field:zeek_ssh.auth_success;db:zeek_ssh.auth_success;kind:termfield;friendly:ssh auth_success;help:ssh auth_success");
  this.ssh_auth_attemptsField = this.api.addField("field:zeek_ssh.auth_attempts;db:zeek_ssh.auth_attempts;kind:integer;friendly:ssh auth_attempts;help:ssh auth_attempts");
  this.ssh_directionField = this.api.addField("field:zeek_ssh.direction;db:zeek_ssh.direction;kind:termfield;friendly:ssh direction;help:ssh direction");
  this.ssh_clientField = this.api.addField("field:zeek_ssh.client;db:zeek_ssh.client;kind:termfield;friendly:ssh client;help:ssh client");
  this.ssh_serverField = this.api.addField("field:zeek_ssh.server;db:zeek_ssh.server;kind:termfield;friendly:ssh server;help:ssh server");
  this.ssh_cipher_algField = this.api.addField("field:zeek_ssh.cipher_alg;db:zeek_ssh.cipher_alg;kind:termfield;friendly:ssh cipher_alg;help:ssh cipher_alg");
  this.ssh_mac_algField = this.api.addField("field:zeek_ssh.mac_alg;db:zeek_ssh.mac_alg;kind:termfield;friendly:ssh mac_alg;help:ssh mac_alg");
  this.ssh_compression_algField = this.api.addField("field:zeek_ssh.compression_alg;db:zeek_ssh.compression_alg;kind:termfield;friendly:ssh compression_alg;help:ssh compression_alg");
  this.ssh_kex_algField = this.api.addField("field:zeek_ssh.kex_alg;db:zeek_ssh.kex_alg;kind:termfield;friendly:ssh kex_alg;help:ssh kex_alg");
  this.ssh_host_key_algField = this.api.addField("field:zeek_ssh.host_key_alg;db:zeek_ssh.host_key_alg;kind:termfield;friendly:ssh host_key_alg;help:ssh host_key_alg");
  this.ssh_host_keyField = this.api.addField("field:zeek_ssh.host_key;db:zeek_ssh.host_key;kind:termfield;friendly:ssh host_key;help:ssh host_key");
  this.ssh_remote_location_country_codeField = this.api.addField("field:zeek_ssh.remote_location_country_code;db:zeek_ssh.remote_location_country_code;kind:termfield;friendly:ssh remote_location_country_code;help:ssh remote_location_country_code");
  this.ssh_remote_location_regionField = this.api.addField("field:zeek_ssh.remote_location_region;db:zeek_ssh.remote_location_region;kind:termfield;friendly:ssh remote_location_region;help:ssh remote_location_region");
  this.ssh_remote_location_cityField = this.api.addField("field:zeek_ssh.remote_location_city;db:zeek_ssh.remote_location_city;kind:termfield;friendly:ssh remote_location_city;help:ssh remote_location_city");
  this.ssh_remote_location_latitudeField = this.api.addField("field:zeek_ssh.remote_location_latitude;db:zeek_ssh.remote_location_latitude;kind:termfield;friendly:ssh remote_location_latitude;help:ssh remote_location_latitude");
  this.ssh_remote_location_longitudeField = this.api.addField("field:zeek_ssh.remote_location_longitude;db:zeek_ssh.remote_location_longitude;kind:termfield;friendly:ssh remote_location_longitude;help:ssh remote_location_longitude");
  this.ssh_hasshVersionField = this.api.addField("field:zeek_ssh.hasshVersion;db:zeek_ssh.hasshVersion;kind:termfield;friendly:HASSH Version;help:HASSH Version");
  this.ssh_hasshField = this.api.addField("field:zeek_ssh.hassh;db:zeek_ssh.hassh;kind:termfield;friendly:HASSH Client Fingerprint;help:HASSH Client Fingerprint");
  this.ssh_hasshServerField = this.api.addField("field:zeek_ssh.hasshServer;db:zeek_ssh.hasshServer;kind:termfield;friendly:HASSH Server Fingerprint;help:HASSH Server Fingerprint");
  this.ssh_hasshAlgorithmsField = this.api.addField("field:zeek_ssh.hasshAlgorithms;db:zeek_ssh.hasshAlgorithms;kind:termfield;friendly:HASSH Client Algorithms;help:HASSH Client Algorithms");
  this.ssh_hasshServerAlgorithmsField = this.api.addField("field:zeek_ssh.hasshServerAlgorithms;db:zeek_ssh.hasshServerAlgorithms;kind:termfield;friendly:HASSH Server Algorithms;help:HASSH Server Algorithms");
  this.ssh_cshkaField = this.api.addField("field:zeek_ssh.cshka;db:zeek_ssh.cshka;kind:termfield;friendly:HASSH Client Host Key Algorithms;help:HASSH Client Host Key Algorithms");
  this.ssh_sshkaField = this.api.addField("field:zeek_ssh.sshka;db:zeek_ssh.sshka;kind:termfield;friendly:HASSH Server Host Key Algorithms;help:HASSH Server Host Key Algorithms");

  // ssl.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info
  this.ssl_ssl_versionField = this.api.addField("field:zeek_ssl.ssl_version;db:zeek_ssl.ssl_version;kind:termfield;friendly:ssl ssl_version;help:ssl ssl_version");
  this.ssl_cipherField = this.api.addField("field:zeek_ssl.cipher;db:zeek_ssl.cipher;kind:termfield;friendly:ssl cipher;help:ssl cipher");
  this.ssl_curveField = this.api.addField("field:zeek_ssl.curve;db:zeek_ssl.curve;kind:termfield;friendly:ssl curve;help:ssl curve");
  this.ssl_server_nameField = this.api.addField("field:zeek_ssl.server_name;db:zeek_ssl.server_name;kind:termfield;friendly:ssl server_name;help:ssl server_name");
  this.ssl_resumedField = this.api.addField("field:zeek_ssl.resumed;db:zeek_ssl.resumed;kind:termfield;friendly:ssl resumed;help:ssl resumed");
  this.ssl_last_alertField = this.api.addField("field:zeek_ssl.last_alert;db:zeek_ssl.last_alert;kind:termfield;friendly:ssl last_alert;help:ssl last_alert");
  this.ssl_next_protocolField = this.api.addField("field:zeek_ssl.next_protocol;db:zeek_ssl.next_protocol;kind:termfield;friendly:ssl next_protocol;help:ssl next_protocol");
  this.ssl_establishedField = this.api.addField("field:zeek_ssl.established;db:zeek_ssl.established;kind:termfield;friendly:ssl established;help:ssl established");
  this.ssl_cert_chain_fuidsField = this.api.addField("field:zeek_ssl.cert_chain_fuids;db:zeek_ssl.cert_chain_fuids;kind:termfield;friendly:ssl cert_chain_fuids;help:ssl cert_chain_fuids");
  this.ssl_client_cert_chain_fuidsField = this.api.addField("field:zeek_ssl.client_cert_chain_fuids;db:zeek_ssl.client_cert_chain_fuids;kind:termfield;friendly:ssl client_cert_chain_fuids;help:ssl client_cert_chain_fuids");
  this.ssl_subject_fullField = this.api.addField("field:zeek_ssl.subject_full;db:zeek_ssl.subject_full;kind:termfield;friendly:ssl subject;help:ssl subject");
  this.ssl_subject_CNField = this.api.addField("field:zeek_ssl.subject.CN;db:zeek_ssl.subject.CN;kind:termfield;friendly:ssl subject common name;help:ssl subject common name");
  this.ssl_subject_CField = this.api.addField("field:zeek_ssl.subject.C;db:zeek_ssl.subject.C;kind:termfield;friendly:ssl subject country;help:ssl subject country");
  this.ssl_subject_OField = this.api.addField("field:zeek_ssl.subject.O;db:zeek_ssl.subject.O;kind:termfield;friendly:ssl subject organization;help:ssl subject organization");
  this.ssl_subject_OUField = this.api.addField("field:zeek_ssl.subject.OU;db:zeek_ssl.subject.OU;kind:termfield;friendly:ssl subject organization unit;help:ssl subject organization unit");
  this.ssl_subject_STField = this.api.addField("field:zeek_ssl.subject.ST;db:zeek_ssl.subject.ST;kind:termfield;friendly:ssl subject state;help:ssl subject state");
  this.ssl_subject_SNField = this.api.addField("field:zeek_ssl.subject.SN;db:zeek_ssl.subject.SN;kind:termfield;friendly:ssl subject surname;help:ssl subject surname");
  this.ssl_subject_LField = this.api.addField("field:zeek_ssl.subject.L;db:zeek_ssl.subject.L;kind:termfield;friendly:ssl subject locality;help:ssl subject locality");
  this.ssl_subject_GNField = this.api.addField("field:zeek_ssl.subject.GN;db:zeek_ssl.subject.GN;kind:termfield;friendly:ssl subject given name;help:ssl subject given name");
  this.ssl_subject_pseudonymField = this.api.addField("field:zeek_ssl.subject.pseudonym;db:zeek_ssl.subject.pseudonym;kind:termfield;friendly:ssl subject pseudonym;help:ssl subject pseudonym");
  this.ssl_subject_serialNumberField = this.api.addField("field:zeek_ssl.subject.serialNumber;db:zeek_ssl.subject.serialNumber;kind:termfield;friendly:ssl subject serial number;help:ssl subject serial number");
  this.ssl_subject_titleField = this.api.addField("field:zeek_ssl.subject.title;db:zeek_ssl.subject.title;kind:termfield;friendly:ssl subject title;help:ssl subject title");
  this.ssl_subject_initialsField = this.api.addField("field:zeek_ssl.subject.initials;db:zeek_ssl.subject.initials;kind:termfield;friendly:ssl subject initials;help:ssl subject initials");
  this.ssl_subject_emailAddressField = this.api.addField("field:zeek_ssl.subject.emailAddress;db:zeek_ssl.subject.emailAddress;kind:termfield;friendly:ssl subject email address;help:ssl subject email address");
  this.ssl_issuer_fullField = this.api.addField("field:zeek_ssl.issuer_full;db:zeek_ssl.issuer_full;kind:termfield;friendly:ssl issuer;help:ssl issuer");
  this.ssl_issuer_CNField = this.api.addField("field:zeek_ssl.issuer.CN;db:zeek_ssl.issuer.CN;kind:termfield;friendly:ssl issuer common name;help:ssl issuer common name");
  this.ssl_issuer_CField = this.api.addField("field:zeek_ssl.issuer.C;db:zeek_ssl.issuer.C;kind:termfield;friendly:ssl issuer country;help:ssl issuer country");
  this.ssl_issuer_OField = this.api.addField("field:zeek_ssl.issuer.O;db:zeek_ssl.issuer.O;kind:termfield;friendly:ssl issuer organization;help:ssl issuer organization");
  this.ssl_issuer_OUField = this.api.addField("field:zeek_ssl.issuer.OU;db:zeek_ssl.issuer.OU;kind:termfield;friendly:ssl issuer organization unit;help:ssl issuer organization unit");
  this.ssl_issuer_STField = this.api.addField("field:zeek_ssl.issuer.ST;db:zeek_ssl.issuer.ST;kind:termfield;friendly:ssl issuer state;help:ssl issuer state");
  this.ssl_issuer_SNField = this.api.addField("field:zeek_ssl.issuer.SN;db:zeek_ssl.issuer.SN;kind:termfield;friendly:ssl issuer surname;help:ssl issuer surname");
  this.ssl_issuer_LField = this.api.addField("field:zeek_ssl.issuer.L;db:zeek_ssl.issuer.L;kind:termfield;friendly:ssl issuer locality;help:ssl issuer locality");
  this.ssl_issuer_DCField = this.api.addField("field:zeek_ssl.issuer.DC;db:zeek_ssl.issuer.DC;kind:termfield;friendly:ssl issuer distinguished name;help:ssl issuer distinguished name");
  this.ssl_issuer_GNField = this.api.addField("field:zeek_ssl.issuer.GN;db:zeek_ssl.issuer.GN;kind:termfield;friendly:ssl issuer given name;help:ssl issuer given name");
  this.ssl_issuer_pseudonymField = this.api.addField("field:zeek_ssl.issuer.pseudonym;db:zeek_ssl.issuer.pseudonym;kind:termfield;friendly:ssl issuer pseudonym;help:ssl issuer pseudonym");
  this.ssl_issuer_serialNumberField = this.api.addField("field:zeek_ssl.issuer.serialNumber;db:zeek_ssl.issuer.serialNumber;kind:termfield;friendly:ssl issuer serial number;help:ssl issuer serial number");
  this.ssl_issuer_titleField = this.api.addField("field:zeek_ssl.issuer.title;db:zeek_ssl.issuer.title;kind:termfield;friendly:ssl issuer title;help:ssl issuer title");
  this.ssl_issuer_initialsField = this.api.addField("field:zeek_ssl.issuer.initials;db:zeek_ssl.issuer.initials;kind:termfield;friendly:ssl issuer initials;help:ssl issuer initials");
  this.ssl_issuer_emailAddressField = this.api.addField("field:zeek_ssl.issuer.emailAddress;db:zeek_ssl.issuer.emailAddress;kind:termfield;friendly:ssl issuer email address;help:ssl issuer email address");
  this.ssl_client_subject_fullField = this.api.addField("field:zeek_ssl.client_subject_full;db:zeek_ssl.client_subject_full;kind:termfield;friendly:ssl client subject;help:ssl client subject");
  this.ssl_client_subject_CNField = this.api.addField("field:zeek_ssl.client_subject.CN;db:zeek_ssl.client_subject.CN;kind:termfield;friendly:ssl client subject common name;help:ssl client subject common name");
  this.ssl_client_subject_CField = this.api.addField("field:zeek_ssl.client_subject.C;db:zeek_ssl.client_subject.C;kind:termfield;friendly:ssl client subject country;help:ssl client subject country");
  this.ssl_client_subject_OField = this.api.addField("field:zeek_ssl.client_subject.O;db:zeek_ssl.client_subject.O;kind:termfield;friendly:ssl client subject organization;help:ssl client subject organization");
  this.ssl_client_subject_OUField = this.api.addField("field:zeek_ssl.client_subject.OU;db:zeek_ssl.client_subject.OU;kind:termfield;friendly:ssl client subject organization unit;help:ssl client subject organization unit");
  this.ssl_client_subject_STField = this.api.addField("field:zeek_ssl.client_subject.ST;db:zeek_ssl.client_subject.ST;kind:termfield;friendly:ssl client subject state;help:ssl client subject state");
  this.ssl_client_subject_SNField = this.api.addField("field:zeek_ssl.client_subject.SN;db:zeek_ssl.client_subject.SN;kind:termfield;friendly:ssl client subject surname;help:ssl client subject surname");
  this.ssl_client_subject_LField = this.api.addField("field:zeek_ssl.client_subject.L;db:zeek_ssl.client_subject.L;kind:termfield;friendly:ssl client subject locality;help:ssl client subject locality");
  this.ssl_client_subject_GNField = this.api.addField("field:zeek_ssl.client_subject.GN;db:zeek_ssl.client_subject.GN;kind:termfield;friendly:ssl client subject given name;help:ssl client subject given name");
  this.ssl_client_subject_pseudonymField = this.api.addField("field:zeek_ssl.client_subject.pseudonym;db:zeek_ssl.client_subject.pseudonym;kind:termfield;friendly:ssl client subject pseudonym;help:ssl client subject pseudonym");
  this.ssl_client_subject_serialNumberField = this.api.addField("field:zeek_ssl.client_subject.serialNumber;db:zeek_ssl.client_subject.serialNumber;kind:termfield;friendly:ssl client subject serial number;help:ssl client subject serial number");
  this.ssl_client_subject_titleField = this.api.addField("field:zeek_ssl.client_subject.title;db:zeek_ssl.client_subject.title;kind:termfield;friendly:ssl client subject title;help:ssl client subject title");
  this.ssl_client_subject_initialsField = this.api.addField("field:zeek_ssl.client_subject.initials;db:zeek_ssl.client_subject.initials;kind:termfield;friendly:ssl client subject initials;help:ssl client subject initials");
  this.ssl_client_subject_emailAddressField = this.api.addField("field:zeek_ssl.client_subject.emailAddress;db:zeek_ssl.client_subject.emailAddress;kind:termfield;friendly:ssl client subject email address;help:ssl client subject email address");
  this.ssl_client_issuer_fullField = this.api.addField("field:zeek_ssl.client_issuer_full;db:zeek_ssl.client_issuer_full;kind:termfield;friendly:ssl client issuer;help:ssl client issuer");
  this.ssl_client_issuer_CNField = this.api.addField("field:zeek_ssl.client_issuer.CN;db:zeek_ssl.client_issuer.CN;kind:termfield;friendly:ssl client issuer common name;help:ssl client issuer common name");
  this.ssl_client_issuer_CField = this.api.addField("field:zeek_ssl.client_issuer.C;db:zeek_ssl.client_issuer.C;kind:termfield;friendly:ssl client issuer country;help:ssl client issuer country");
  this.ssl_client_issuer_OField = this.api.addField("field:zeek_ssl.client_issuer.O;db:zeek_ssl.client_issuer.O;kind:termfield;friendly:ssl client issuer organization;help:ssl client issuer organization");
  this.ssl_client_issuer_OUField = this.api.addField("field:zeek_ssl.client_issuer.OU;db:zeek_ssl.client_issuer.OU;kind:termfield;friendly:ssl client issuer organization unit;help:ssl client issuer organization unit");
  this.ssl_client_issuer_STField = this.api.addField("field:zeek_ssl.client_issuer.ST;db:zeek_ssl.client_issuer.ST;kind:termfield;friendly:ssl client issuer state;help:ssl client issuer state");
  this.ssl_client_issuer_SNField = this.api.addField("field:zeek_ssl.client_issuer.SN;db:zeek_ssl.client_issuer.SN;kind:termfield;friendly:ssl client issuer surname;help:ssl client issuer surname");
  this.ssl_client_issuer_LField = this.api.addField("field:zeek_ssl.client_issuer.L;db:zeek_ssl.client_issuer.L;kind:termfield;friendly:ssl client issuer locality;help:ssl client issuer locality");
  this.ssl_client_issuer_DCField = this.api.addField("field:zeek_ssl.client_issuer.DC;db:zeek_ssl.client_issuer.DC;kind:termfield;friendly:ssl client issuer distinguished name;help:ssl client issuer distinguished name");
  this.ssl_client_issuer_GNField = this.api.addField("field:zeek_ssl.client_issuer.GN;db:zeek_ssl.client_issuer.GN;kind:termfield;friendly:ssl client issuer given name;help:ssl client issuer given name");
  this.ssl_client_issuer_pseudonymField = this.api.addField("field:zeek_ssl.client_issuer.pseudonym;db:zeek_ssl.client_issuer.pseudonym;kind:termfield;friendly:ssl client issuer pseudonym;help:ssl client issuer pseudonym");
  this.ssl_client_issuer_serialNumberField = this.api.addField("field:zeek_ssl.client_issuer.serialNumber;db:zeek_ssl.client_issuer.serialNumber;kind:termfield;friendly:ssl client issuer serial number;help:ssl client issuer serial number");
  this.ssl_client_issuer_titleField = this.api.addField("field:zeek_ssl.client_issuer.title;db:zeek_ssl.client_issuer.title;kind:termfield;friendly:ssl client issuer title;help:ssl client issuer title");
  this.ssl_client_issuer_initialsField = this.api.addField("field:zeek_ssl.client_issuer.initials;db:zeek_ssl.client_issuer.initials;kind:termfield;friendly:ssl client issuer initials;help:ssl client issuer initials");
  this.ssl_client_issuer_emailAddressField = this.api.addField("field:zeek_ssl.client_issuer.emailAddress;db:zeek_ssl.client_issuer.emailAddress;kind:termfield;friendly:ssl client issuer email address;help:ssl client issuer email address");
  this.ssl_validation_statusField = this.api.addField("field:zeek_ssl.validation_status;db:zeek_ssl.validation_status;kind:termfield;friendly:ssl validation_status;help:ssl validation_status");
  this.ssl_ja3Field = this.api.addField("field:zeek_ssl.ja3;db:zeek_ssl.ja3;kind:termfield;friendly:JA3 Fingerprint;help:JA3 Fingerprint");
  this.ssl_ja3sField = this.api.addField("field:zeek_ssl.ja3s;db:zeek_ssl.ja3s;kind:termfield;friendly:JA3S Fingerprint;help:JA3S Fingerprint");
  this.ssl_ja3_descField = this.api.addField("field:zeek_ssl.ja3_desc;db:zeek_ssl.ja3_desc;kind:termfield;friendly:JA3 Fingerprint Lookup;help:JA3 Fingerprint Lookup");
  this.ssl_ja3s_descField = this.api.addField("field:zeek_ssl.ja3s_desc;db:zeek_ssl.ja3s_desc;kind:termfield;friendly:JA3S Fingerprint Lookup;help:JA3S Fingerprint Lookup");

  // syslog.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/syslog/main.zeek.html#type-Syslog::Info
  this.syslog_facilityField = this.api.addField("field:zeek_syslog.facility;db:zeek_syslog.facility;kind:termfield;friendly:syslog facility;help:syslog facility");
  this.syslog_severityField = this.api.addField("field:zeek_syslog.severity;db:zeek_syslog.severity;kind:termfield;friendly:syslog severity;help:syslog severity");
  this.syslog_messageField = this.api.addField("field:zeek_syslog.message;db:zeek_syslog.message;kind:termfield;friendly:syslog message;help:syslog message");

  // tds.log - https://github.com/amzn/zeek-plugin-tds
  // https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek
  this.tds_commandField = this.api.addField("field:zeek_tds.command;db:zeek_tds.command;kind:termfield;friendly:tds command;help:tds command");

  // tds_rpc.log - https://github.com/amzn/zeek-plugin-tds
  // https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek
  this.tds_rpc_procedure_nameField = this.api.addField("field:zeek_tds_rpc.procedure_name;db:zeek_tds_rpc.procedure_name;kind:termfield;friendly:tds_rpc procedure_name;help:tds_rpc procedure_name");
  this.tds_rpc_parametersField = this.api.addField("field:zeek_tds_rpc.parameters;db:zeek_tds_rpc.parameters;kind:termfield;friendly:tds_rpc parameters;help:tds_rpc parameters");

  // tds_sql_batch.log - https://github.com/amzn/zeek-plugin-tds
  // https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek
  this.tds_sql_batch_header_typeField = this.api.addField("field:zeek_tds_sql_batch.header_type;db:zeek_tds_sql_batch.header_type;kind:termfield;friendly:tds_sql_batch header_type;help:tds_sql_batch header_type");
  this.tds_sql_batch_queryField = this.api.addField("field:zeek_tds_sql_batch.query;db:zeek_tds_sql_batch.query;kind:termfield;friendly:tds_sql_batch query;help:tds_sql_batch query");

  // tunnel.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/tunnels/main.zeek.html#type-Tunnel::Info
  this.tunnel_tunnel_typeField = this.api.addField("field:zeek_tunnel.tunnel_type;db:zeek_tunnel.tunnel_type;kind:termfield;friendly:tunnel tunnel_type;help:tunnel tunnel_type");
  this.tunnel_actionField = this.api.addField("field:zeek_tunnel.action;db:zeek_tunnel.action;kind:termfield;friendly:tunnel action;help:tunnel action");

  // weird.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/weird.zeek.html#type-Weird::Info
  this.weird_nameField = this.api.addField("field:zeek_weird.name;db:zeek_weird.name;kind:termfield;friendly:weird name;help:weird name");
  this.weird_addlField = this.api.addField("field:zeek_weird.addl;db:zeek_weird.addl;kind:termfield;friendly:weird addl;help:weird addl");
  this.weird_noticeField = this.api.addField("field:zeek_weird.notice;db:zeek_weird.notice;kind:termfield;friendly:weird notice;help:weird notice");
  this.weird_peerField = this.api.addField("field:zeek_weird.peer;db:zeek_weird.peer;kind:termfield;friendly:weird peer;help:weird peer");

  // x509.log
  // https://docs.zeek.org/en/stable/scripts/base/files/x509/main.zeek.html#type-X509::Info
  this.x509_fuidField = this.api.addField("field:zeek_x509.fuid;db:zeek_x509.fuid;kind:termfield;friendly:x509 fuid;help:x509 fuid");
  this.x509_certificate_versionField = this.api.addField("field:zeek_x509.certificate_version;db:zeek_x509.certificate_version;kind:integer;friendly:x509 certificate_version;help:x509 certificate_version");
  this.x509_certificate_serialField = this.api.addField("field:zeek_x509.certificate_serial;db:zeek_x509.certificate_serial;kind:termfield;friendly:x509 certificate_serial;help:x509 certificate_serial");
  this.x509_certificate_subject_fullField = this.api.addField("field:zeek_x509.certificate_subject_full;db:zeek_x509.certificate_subject_full;kind:termfield;friendly:x509 certificate subject;help:x509 certificate subject");
  this.x509_certificate_subject_CNField = this.api.addField("field:zeek_x509.certificate_subject.CN;db:zeek_x509.certificate_subject.CN;kind:termfield;friendly:x509 certificate subject common name;help:x509 certificate subject common name");
  this.x509_certificate_subject_CField = this.api.addField("field:zeek_x509.certificate_subject.C;db:zeek_x509.certificate_subject.C;kind:termfield;friendly:x509 certificate subject country;help:x509 certificate subject country");
  this.x509_certificate_subject_OField = this.api.addField("field:zeek_x509.certificate_subject.O;db:zeek_x509.certificate_subject.O;kind:termfield;friendly:x509 certificate subject organization;help:x509 certificate subject organization");
  this.x509_certificate_subject_OUField = this.api.addField("field:zeek_x509.certificate_subject.OU;db:zeek_x509.certificate_subject.OU;kind:termfield;friendly:x509 certificate subject organization unit;help:x509 certificate subject organization unit");
  this.x509_certificate_subject_STField = this.api.addField("field:zeek_x509.certificate_subject.ST;db:zeek_x509.certificate_subject.ST;kind:termfield;friendly:x509 certificate subject state;help:x509 certificate subject state");
  this.x509_certificate_subject_SNField = this.api.addField("field:zeek_x509.certificate_subject.SN;db:zeek_x509.certificate_subject.SN;kind:termfield;friendly:x509 certificate subject surname;help:x509 certificate subject surname");
  this.x509_certificate_subject_LField = this.api.addField("field:zeek_x509.certificate_subject.L;db:zeek_x509.certificate_subject.L;kind:termfield;friendly:x509 certificate subject locality;help:x509 certificate subject locality");
  this.x509_certificate_subject_DCField = this.api.addField("field:zeek_x509.certificate_subject.DC;db:zeek_x509.certificate_subject.DC;kind:termfield;friendly:x509 certificate subject distinguished name;help:x509 certificate subject distinguished name");
  this.x509_certificate_subject_GNField = this.api.addField("field:zeek_x509.certificate_subject.GN;db:zeek_x509.certificate_subject.GN;kind:termfield;friendly:x509 certificate subject given name;help:x509 certificate subject given name");
  this.x509_certificate_subject_pseudonymField = this.api.addField("field:zeek_x509.certificate_subject.pseudonym;db:zeek_x509.certificate_subject.pseudonym;kind:termfield;friendly:x509 certificate subject pseudonym;help:x509 certificate subject pseudonym");
  this.x509_certificate_subject_serialNumberField = this.api.addField("field:zeek_x509.certificate_subject.serialNumber;db:zeek_x509.certificate_subject.serialNumber;kind:termfield;friendly:x509 certificate subject serial number;help:x509 certificate subject serial number");
  this.x509_certificate_subject_titleField = this.api.addField("field:zeek_x509.certificate_subject.title;db:zeek_x509.certificate_subject.title;kind:termfield;friendly:x509 certificate subject title;help:x509 certificate subject title");
  this.x509_certificate_subject_initialsField = this.api.addField("field:zeek_x509.certificate_subject.initials;db:zeek_x509.certificate_subject.initials;kind:termfield;friendly:x509 certificate subject initials;help:x509 certificate subject initials");
  this.x509_certificate_subject_emailAddressField = this.api.addField("field:zeek_x509.certificate_subject.emailAddress;db:zeek_x509.certificate_subject.emailAddress;kind:termfield;friendly:x509 certificate subject email address;help:x509 certificate subject email address");
  this.x509_certificate_issuer_fullField = this.api.addField("field:zeek_x509.certificate_issuer_full;db:zeek_x509.certificate_issuer_full;kind:termfield;friendly:x509 certificate issuer;help:x509 certificate issuer");
  this.x509_certificate_issuer_CNField = this.api.addField("field:zeek_x509.certificate_issuer.CN;db:zeek_x509.certificate_issuer.CN;kind:termfield;friendly:x509 certificate issuer common name;help:x509 certificate issuer common name");
  this.x509_certificate_issuer_CField = this.api.addField("field:zeek_x509.certificate_issuer.C;db:zeek_x509.certificate_issuer.C;kind:termfield;friendly:x509 certificate issuer country;help:x509 certificate issuer country");
  this.x509_certificate_issuer_OField = this.api.addField("field:zeek_x509.certificate_issuer.O;db:zeek_x509.certificate_issuer.O;kind:termfield;friendly:x509 certificate issuer organization;help:x509 certificate issuer organization");
  this.x509_certificate_issuer_OUField = this.api.addField("field:zeek_x509.certificate_issuer.OU;db:zeek_x509.certificate_issuer.OU;kind:termfield;friendly:x509 certificate issuer organization unit;help:x509 certificate issuer organization unit");
  this.x509_certificate_issuer_STField = this.api.addField("field:zeek_x509.certificate_issuer.ST;db:zeek_x509.certificate_issuer.ST;kind:termfield;friendly:x509 certificate issuer state;help:x509 certificate issuer state");
  this.x509_certificate_issuer_SNField = this.api.addField("field:zeek_x509.certificate_issuer.SN;db:zeek_x509.certificate_issuer.SN;kind:termfield;friendly:x509 certificate issuer surname;help:x509 certificate issuer surname");
  this.x509_certificate_issuer_LField = this.api.addField("field:zeek_x509.certificate_issuer.L;db:zeek_x509.certificate_issuer.L;kind:termfield;friendly:x509 certificate issuer locality;help:x509 certificate issuer locality");
  this.x509_certificate_issuer_GNField = this.api.addField("field:zeek_x509.certificate_issuer.GN;db:zeek_x509.certificate_issuer.GN;kind:termfield;friendly:x509 certificate issuer given name;help:x509 certificate issuer given name");
  this.x509_certificate_issuer_pseudonymField = this.api.addField("field:zeek_x509.certificate_issuer.pseudonym;db:zeek_x509.certificate_issuer.pseudonym;kind:termfield;friendly:x509 certificate issuer pseudonym;help:x509 certificate issuer pseudonym");
  this.x509_certificate_issuer_serialNumberField = this.api.addField("field:zeek_x509.certificate_issuer.serialNumber;db:zeek_x509.certificate_issuer.serialNumber;kind:termfield;friendly:x509 certificate issuer serial number;help:x509 certificate issuer serial number");
  this.x509_certificate_issuer_titleField = this.api.addField("field:zeek_x509.certificate_issuer.title;db:zeek_x509.certificate_issuer.title;kind:termfield;friendly:x509 certificate issuer title;help:x509 certificate issuer title");
  this.x509_certificate_issuer_initialsField = this.api.addField("field:zeek_x509.certificate_issuer.initials;db:zeek_x509.certificate_issuer.initials;kind:termfield;friendly:x509 certificate issuer initials;help:x509 certificate issuer initials");
  this.x509_certificate_issuer_emailAddressField = this.api.addField("field:zeek_x509.certificate_issuer.emailAddress;db:zeek_x509.certificate_issuer.emailAddress;kind:termfield;friendly:x509 certificate issuer email address;help:x509 certificate issuer email address");
  this.x509_certificate_not_valid_beforeField = this.api.addField("field:zeek_x509.certificate_not_valid_before;db:zeek_x509.certificate_not_valid_before;kind:termfield;friendly:x509 certificate_not_valid_before;help:x509 certificate_not_valid_before");
  this.x509_certificate_not_valid_afterField = this.api.addField("field:zeek_x509.certificate_not_valid_after;db:zeek_x509.certificate_not_valid_after;kind:termfield;friendly:x509 certificate_not_valid_after;help:x509 certificate_not_valid_after");
  this.x509_certificate_key_algField = this.api.addField("field:zeek_x509.certificate_key_alg;db:zeek_x509.certificate_key_alg;kind:termfield;friendly:x509 certificate_key_alg;help:x509 certificate_key_alg");
  this.x509_certificate_sig_algField = this.api.addField("field:zeek_x509.certificate_sig_alg;db:zeek_x509.certificate_sig_alg;kind:termfield;friendly:x509 certificate_sig_alg;help:x509 certificate_sig_alg");
  this.x509_certificate_key_typeField = this.api.addField("field:zeek_x509.certificate_key_type;db:zeek_x509.certificate_key_type;kind:termfield;friendly:x509 certificate_key_type;help:x509 certificate_key_type");
  this.x509_certificate_key_lengthField = this.api.addField("field:zeek_x509.certificate_key_length;db:zeek_x509.certificate_key_length;kind:integer;friendly:x509 certificate_key_length;help:x509 certificate_key_length");
  this.x509_certificate_exponentField = this.api.addField("field:zeek_x509.certificate_exponent;db:zeek_x509.certificate_exponent;kind:termfield;friendly:x509 certificate_exponent;help:x509 certificate_exponent");
  this.x509_certificate_curveField = this.api.addField("field:zeek_x509.certificate_curve;db:zeek_x509.certificate_curve;kind:termfield;friendly:x509 certificate_curve;help:x509 certificate_curve");
  this.x509_san_dnsField = this.api.addField("field:zeek_x509.san_dns;db:zeek_x509.san_dns;kind:termfield;friendly:x509 san_dns;help:x509 san_dns");
  this.x509_san_uriField = this.api.addField("field:zeek_x509.san_uri;db:zeek_x509.san_uri;kind:termfield;friendly:x509 san_uri;help:x509 san_uri");
  this.x509_san_emailField = this.api.addField("field:zeek_x509.san_email;db:zeek_x509.san_email;kind:termfield;friendly:x509 san_email;help:x509 san_email");
  this.x509_san_ipField = this.api.addField("field:zeek_x509.san_ip;db:zeek_x509.san_ip;kind:termfield;friendly:x509 san_ip;help:x509 san_ip");
  this.x509_basic_constraints_caField = this.api.addField("field:zeek_x509.basic_constraints_ca;db:zeek_x509.basic_constraints_ca;kind:termfield;friendly:x509 basic_constraints_ca;help:x509 basic_constraints_ca");
  this.x509_basic_constraints_path_lenField = this.api.addField("field:zeek_x509.basic_constraints_path_len;db:zeek_x509.basic_constraints_path_len;kind:integer;friendly:x509 basic_constraints_path_len;help:x509 basic_constraints_path_len");

  // todo: look at expressions for things that have parents (tunnelling, parent files, etc.)
  // todo: look at IP types and use ipPrint?

  // add right-clicks for pivoting into Kibana from Moloch (see nginx.conf)
  var filterLabel = "Filter %DBFIELD% in Kibana";
  var filterUrl = "idmol2kib/filter?start=%ISOSTART%&stop=%ISOSTOP%&field=%DBFIELD%&value=%TEXT%";
  var allFieldsStr = "communityId,host.name,ip.protocol,mac.dst,mac.src,node,oui.dst,oui.src,protocols,rootId,tags,zeek.community_id,zeek.destination_geo.city_name,zeek.destination_geo.country_name,zeek.destination_ip_reverse_dns,zeek.filename,zeek.filetype,zeek.fuid,zeek.logType,zeek.orig_h,zeek.orig_hostname,zeek.orig_l2_addr,zeek.orig_l2_oui,zeek.orig_p,zeek.orig_segment,zeek.proto,zeek.resp_h,zeek.resp_hostname,zeek.resp_l2_addr,zeek.resp_l2_oui,zeek.resp_p,zeek.resp_segment,zeek.service,zeek.source_geo.city_name,zeek.source_geo.country_name,zeek.source_ip_reverse_dns,zeek.ts,zeek.uid,zeek.user,zeek_bacnet.apdu_type,zeek_bacnet.bvlc_function,zeek_bacnet.bvlc_len,zeek_bacnet.data,zeek_bacnet.data_dict.date,zeek_bacnet.data_dict.low_limit,zeek_bacnet.data_dict.object,zeek_bacnet.data_dict.property,zeek_bacnet.data_dict.result,zeek_bacnet.data_dict.time,zeek_bacnet.data_dict.ttl,zeek_bacnet.service_choice,zeek_cip.cip_service,zeek_cip.cip_tags,zeek_cip.status,zeek_conn.conn_state,zeek_conn.conn_state_description,zeek_conn.duration,zeek_conn.history,zeek_conn.inner_vlan,zeek_conn.local_orig,zeek_conn.local_resp,zeek_conn.missed_bytes,zeek_conn.orig_bytes,zeek_conn.orig_ip_bytes,zeek_conn.orig_pkts,zeek_conn.resp_bytes,zeek_conn.resp_ip_bytes,zeek_conn.resp_pkts,zeek_conn.tunnel_parents,zeek_conn.vlan,zeek_dce_rpc.endpoint,zeek_dce_rpc.named_pipe,zeek_dce_rpc.operation,zeek_dce_rpc.rtt,zeek_dhcp.assigned_ip,zeek_dhcp.lease_time,zeek_dhcp.mac,zeek_dhcp.trans_id,zeek_dnp3.fc_reply,zeek_dnp3.fc_request,zeek_dnp3.iin,zeek_dns.AA,zeek_dns.answers,zeek_dns.qclass,zeek_dns.qclass_name,zeek_dns.qtype,zeek_dns.qtype_name,zeek_dns.query,zeek_dns.RA,zeek_dns.rcode,zeek_dns.rcode_name,zeek_dns.RD,zeek_dns.rejected,zeek_dns.rtt,zeek_dns.TC,zeek_dns.trans_id,zeek_dns.TTLs,zeek_dns.Z,zeek_dpd.failure_reason,zeek_dpd.service,zeek_enip.command,zeek_enip.length,zeek_enip.options,zeek_enip.sender_context,zeek_enip.session_handle,zeek_enip.status,zeek_enip_list_identity.device_ip,zeek_enip_list_identity.device_type,zeek_enip_list_identity.product_code,zeek_enip_list_identity.product_name,zeek_enip_list_identity.revision,zeek_enip_list_identity.serial_number,zeek_enip_list_identity.state,zeek_enip_list_identity.status,zeek_enip_list_identity.vendor,zeek_files.analyzers,zeek_files.conn_uids,zeek_files.depth,zeek_files.duration,zeek_files.extracted,zeek_files.extracted_cutoff,zeek_files.extracted_size,zeek_files.filename,zeek_files.fuid,zeek_files.is_orig,zeek_files.local_orig,zeek_files.md5,zeek_files.mime_type,zeek_files.missing_bytes,zeek_files.overflow_bytes,zeek_files.parent_fuid,zeek_files.rx_hosts,zeek_files.seen_bytes,zeek_files.sha1,zeek_files.sha256,zeek_files.source,zeek_files.timedout,zeek_files.total_bytes,zeek_files.tx_hosts,zeek_ftp.arg,zeek_ftp.command,zeek_ftp.data_channel_orig_h,zeek_ftp.data_channel_passive,zeek_ftp.data_channel_resp_h,zeek_ftp.data_channel_resp_p,zeek_ftp.file_size,zeek_ftp.fuid,zeek_ftp.mime_type,zeek_ftp.password,zeek_ftp.reply_code,zeek_ftp.reply_msg,zeek_gquic.cyu,zeek_gquic.cyutags,zeek_gquic.server_name,zeek_gquic.tag_count,zeek_gquic.user_agent,zeek_gquic.version,zeek_http.host,zeek_http.info_code,zeek_http.info_msg,zeek_http.method,zeek_http.orig_filenames,zeek_http.orig_fuids,zeek_http.orig_mime_types,zeek_http.origin,zeek_http.password,zeek_http.proxied,zeek_http.referrer,zeek_http.request_body_len,zeek_http.resp_filenames,zeek_http.resp_fuids,zeek_http.resp_mime_types,zeek_http.response_body_len,zeek_http.status_code,zeek_http.status_msg,zeek_http.tags,zeek_http.trans_depth,zeek_http.uri,zeek_http.user,zeek_http.user_agent,zeek_http.version,zeek_intel.file_description,zeek_intel.fuid,zeek_intel.indicator,zeek_intel.indicator_type,zeek_intel.matched,zeek_intel.mimetype,zeek_intel.seen_node,zeek_intel.seen_where,zeek_intel.sources,zeek_irc.addl,zeek_irc.command,zeek_irc.dcc_file_name,zeek_irc.dcc_file_size,zeek_irc.dcc_mime_type,zeek_irc.fuid,zeek_irc.nick,zeek_irc.value,zeek_iso_cotp.pdu_type,zeek_kerberos.cipher,zeek_kerberos.client_cert_fuid,zeek_kerberos.client_cert_subject,zeek_kerberos.cname,zeek_kerberos.error_msg,zeek_kerberos.forwardable,zeek_kerberos.from,zeek_kerberos.renewable,zeek_kerberos.server_cert_fuid,zeek_kerberos.server_cert_subject,zeek_kerberos.sname,zeek_kerberos.success,zeek_kerberos.till,zeek_known_certs.issuer_subject,zeek_known_certs.serial,zeek_known_certs.subject,zeek_known_modbus.device_type,zeek_modbus.exception,zeek_modbus.func,modbus_register_change.register,modbus_register_change.old_val,modbus_register_change.new_val,modbus_register_change.delta,zeek_mqtt_connect.client_id,zeek_mqtt_connect.connect_status,zeek_mqtt_connect.proto_name,zeek_mqtt_connect.proto_version,zeek_mqtt_connect.will_payload,zeek_mqtt_connect.will_topic,zeek_mqtt_publish.from_client,zeek_mqtt_publish.retain,zeek_mqtt_publish.qos,zeek_mqtt_publish.status,zeek_mqtt_publish.topic,zeek_mqtt_publish.payload,zeek_mqtt_publish.payload_len,zeek_mqtt_subscribe.action,zeek_mqtt_subscribe.topics,zeek_mqtt_subscribe.qos_levels,zeek_mqtt_subscribe.granted_qos_level,zeek_mqtt_subscribe.ack,zeek_mysql.arg,zeek_mysql.cmd,zeek_mysql.response,zeek_mysql.rows,zeek_mysql.success,zeek_notice.actions,zeek_notice.dropped,zeek_notice.dst,zeek_notice.file_desc,zeek_notice.file_mime_type,zeek_notice.fuid,zeek_notice.msg,zeek_notice.n,zeek_notice.note,zeek_notice.p,zeek_notice.peer_descr,zeek_notice.remote_location_city,zeek_notice.remote_location_cityremote_location_latitude,zeek_notice.remote_location_country_code,zeek_notice.remote_location_latitude,zeek_notice.remote_location_longitude,zeek_notice.remote_location_region,zeek_notice.src,zeek_notice.sub,zeek_notice.suppress_for,zeek_ntlm.domain,zeek_ntlm.host,zeek_ntlm.status,zeek_ntlm.success,zeek_ntp.mode,zeek_ntp.mode_str,zeek_ntp.num_exts,zeek_ntp.org_time,zeek_ntp.poll,zeek_ntp.precision,zeek_ntp.rec_time,zeek_ntp.ref_id,zeek_ntp.ref_time,zeek_ntp.root_delay,zeek_ntp.root_disp,zeek_ntp.stratum,zeek_ntp.version,zeek_ntp.xmt_time,zeek_pe.compile_ts,zeek_pe.fuid,zeek_pe.has_cert_table,zeek_pe.has_debug_data,zeek_pe.has_export_table,zeek_pe.has_import_table,zeek_pe.is_64bit,zeek_pe.is_exe,zeek_pe.machine,zeek_pe.os,zeek_pe.section_names,zeek_pe.subsystem,zeek_pe.uses_aslr,zeek_pe.uses_code_integrity,zeek_pe.uses_dep,zeek_pe.uses_seh,zeek_profinet.block_version,zeek_profinet.index,zeek_profinet.operation_type,zeek_profinet.slot_number,zeek_profinet.subslot_number,zeek_profinet_dce_rpc.activity_uuid,zeek_profinet_dce_rpc.interface_uuid,zeek_profinet_dce_rpc.object_uuid,zeek_profinet_dce_rpc.operation,zeek_profinet_dce_rpc.packet_type,zeek_profinet_dce_rpc.server_boot_time,zeek_profinet_dce_rpc.version,zeek_radius.connect_info,zeek_radius.framed_addr,zeek_radius.mac,zeek_radius.remote_ip,zeek_radius.reply_msg,zeek_radius.result,zeek_radius.ttl,zeek_rdp.cert_count,zeek_rdp.cert_permanent,zeek_rdp.cert_type,zeek_rdp.client_build,zeek_rdp.client_channels,zeek_rdp.client_dig_product_id,zeek_rdp.client_name,zeek_rdp.cookie,zeek_rdp.desktop_height,zeek_rdp.desktop_width,zeek_rdp.encryption_level,zeek_rdp.encryption_method,zeek_rdp.keyboard_layout,zeek_rdp.requested_color_depth,zeek_rdp.result,zeek_rdp.security_protocol,zeek_rfb.auth,zeek_rfb.authentication_method,zeek_rfb.client_major_version,zeek_rfb.client_minor_version,zeek_rfb.desktop_name,zeek_rfb.height,zeek_rfb.server_major_version,zeek_rfb.server_minor_version,zeek_rfb.share_flag,zeek_rfb.width,zeek_s7comm.data_info,zeek_s7comm.item_count,zeek_s7comm.parameter,zeek_s7comm.parameters.class,zeek_s7comm.parameters.code,zeek_s7comm.parameters.group,zeek_s7comm.parameters.mode,zeek_s7comm.parameters.sub,zeek_s7comm.parameters.type,zeek_s7comm.rosctr,zeek_signatures.engine,zeek_signatures.event_message,zeek_signatures.hits,zeek_signatures.host_count,zeek_signatures.note,zeek_signatures.signature_count,zeek_signatures.signature_id,zeek_signatures.sub_message,zeek_sip.call_id,zeek_sip.content_type,zeek_sip.date,zeek_sip.method,zeek_sip.reply_to,zeek_sip.request_body_len,zeek_sip.request_from,zeek_sip.request_path,zeek_sip.request_to,zeek_sip.response_body_len,zeek_sip.response_from,zeek_sip.response_path,zeek_sip.response_to,zeek_sip.seq,zeek_sip.status_code,zeek_sip.status_msg,zeek_sip.subject,zeek_sip.trans_depth,zeek_sip.uri,zeek_sip.user_agent,zeek_sip.warning,zeek_smb_files.action,zeek_smb_files.fuid,zeek_smb_files.name,zeek_smb_files.path,zeek_smb_files.prev_name,zeek_smb_files.size,zeek_smb_files.times_accessed,zeek_smb_files.times_changed,zeek_smb_files.times_created,zeek_smb_files.times_modified,zeek_smb_mapping.native_file_system,zeek_smb_mapping.path,zeek_smb_mapping.resource_type,zeek_smb_mapping.share_type,zeek_smtp.cc,zeek_smtp.date,zeek_smtp.first_received,zeek_smtp.from,zeek_smtp.fuids,zeek_smtp.helo,zeek_smtp.in_reply_to,zeek_smtp.is_webmail,zeek_smtp.last_reply,zeek_smtp.mailfrom,zeek_smtp.msg_id,zeek_smtp.path,zeek_smtp.rcptto,zeek_smtp.reply_to,zeek_smtp.second_received,zeek_smtp.subject,zeek_smtp.tls,zeek_smtp.to,zeek_smtp.trans_depth,zeek_smtp.user_agent,zeek_smtp.x_originating_ip,zeek_snmp.community,zeek_snmp.display_string,zeek_snmp.duration,zeek_snmp.get_bulk_requests,zeek_snmp.get_requests,zeek_snmp.get_responses,zeek_snmp.set_requests,zeek_snmp.up_since,zeek_snmp.version,zeek_socks.bound_host,zeek_socks.bound_name,zeek_socks.bound_port,zeek_socks.password,zeek_socks.request_host,zeek_socks.request_name,zeek_socks.request_port,zeek_socks.server_status,zeek_socks.version,zeek_software.name,zeek_software.software_type,zeek_software.unparsed_version,zeek_software.version_addl,zeek_software.version_major,zeek_software.version_minor,zeek_software.version_minor2,zeek_software.version_minor3,zeek_ssh.auth_attempts,zeek_ssh.auth_success,zeek_ssh.cipher_alg,zeek_ssh.client,zeek_ssh.compression_alg,zeek_ssh.cshka,zeek_ssh.direction,zeek_ssh.hassh,zeek_ssh.hasshAlgorithms,zeek_ssh.hasshServer,zeek_ssh.hasshServerAlgorithms,zeek_ssh.hasshVersion,zeek_ssh.host_key,zeek_ssh.host_key_alg,zeek_ssh.kex_alg,zeek_ssh.mac_alg,zeek_ssh.remote_location_city,zeek_ssh.remote_location_country_code,zeek_ssh.remote_location_latitude,zeek_ssh.remote_location_longitude,zeek_ssh.remote_location_region,zeek_ssh.server,zeek_ssh.sshka,zeek_ssh.version,zeek_ssl.cert_chain_fuids,zeek_ssl.cipher,zeek_ssl.client_cert_chain_fuids,zeek_ssl.client_issuer.C,zeek_ssl.client_issuer.CN,zeek_ssl.client_issuer.DC,zeek_ssl.client_issuer.emailAddress,zeek_ssl.client_issuer.GN,zeek_ssl.client_issuer.initials,zeek_ssl.client_issuer.L,zeek_ssl.client_issuer.O,zeek_ssl.client_issuer.OU,zeek_ssl.client_issuer.pseudonym,zeek_ssl.client_issuer.serialNumber,zeek_ssl.client_issuer.SN,zeek_ssl.client_issuer.ST,zeek_ssl.client_issuer.title,zeek_ssl.client_issuer_full,zeek_ssl.client_subject.C,zeek_ssl.client_subject.CN,zeek_ssl.client_subject.emailAddress,zeek_ssl.client_subject.GN,zeek_ssl.client_subject.initials,zeek_ssl.client_subject.L,zeek_ssl.client_subject.O,zeek_ssl.client_subject.OU,zeek_ssl.client_subject.pseudonym,zeek_ssl.client_subject.serialNumber,zeek_ssl.client_subject.SN,zeek_ssl.client_subject.ST,zeek_ssl.client_subject.title,zeek_ssl.client_subject_full,zeek_ssl.curve,zeek_ssl.established,zeek_ssl.issuer.C,zeek_ssl.issuer.CN,zeek_ssl.issuer.DC,zeek_ssl.issuer.emailAddress,zeek_ssl.issuer.GN,zeek_ssl.issuer.initials,zeek_ssl.issuer.L,zeek_ssl.issuer.O,zeek_ssl.issuer.OU,zeek_ssl.issuer.pseudonym,zeek_ssl.issuer.serialNumber,zeek_ssl.issuer.SN,zeek_ssl.issuer.ST,zeek_ssl.issuer.title,zeek_ssl.issuer_full,zeek_ssl.ja3,zeek_ssl.ja3_desc,zeek_ssl.ja3s,zeek_ssl.ja3s_desc,zeek_ssl.last_alert,zeek_ssl.next_protocol,zeek_ssl.resumed,zeek_ssl.server_name,zeek_ssl.ssl_version,zeek_ssl.subject.C,zeek_ssl.subject.CN,zeek_ssl.subject.emailAddress,zeek_ssl.subject.GN,zeek_ssl.subject.initials,zeek_ssl.subject.L,zeek_ssl.subject.O,zeek_ssl.subject.OU,zeek_ssl.subject.pseudonym,zeek_ssl.subject.serialNumber,zeek_ssl.subject.SN,zeek_ssl.subject.ST,zeek_ssl.subject.title,zeek_ssl.subject_full,zeek_ssl.validation_status,zeek_syslog.facility,zeek_syslog.message,zeek_syslog.severity,zeek_tds.command,zeek_tds_rpc.parameters,zeek_tds_rpc.procedure_name,zeek_tds_sql_batch.header_type,zeek_tds_sql_batch.query,zeek_tunnel.action,zeek_tunnel.tunnel_type,zeek_weird.addl,zeek_weird.name,zeek_weird.notice,zeek_weird.peer,zeek_x509.basic_constraints_ca,zeek_x509.basic_constraints_path_len,zeek_x509.certificate_curve,zeek_x509.certificate_exponent,zeek_x509.certificate_issuer.C,zeek_x509.certificate_issuer.CN,zeek_x509.certificate_issuer.emailAddress,zeek_x509.certificate_issuer.GN,zeek_x509.certificate_issuer.initials,zeek_x509.certificate_issuer.L,zeek_x509.certificate_issuer.O,zeek_x509.certificate_issuer.OU,zeek_x509.certificate_issuer.pseudonym,zeek_x509.certificate_issuer.serialNumber,zeek_x509.certificate_issuer.SN,zeek_x509.certificate_issuer.ST,zeek_x509.certificate_issuer.title,zeek_x509.certificate_issuer_full,zeek_x509.certificate_key_alg,zeek_x509.certificate_key_length,zeek_x509.certificate_key_type,zeek_x509.certificate_not_valid_after,zeek_x509.certificate_not_valid_before,zeek_x509.certificate_serial,zeek_x509.certificate_sig_alg,zeek_x509.certificate_subject.C,zeek_x509.certificate_subject.CN,zeek_x509.certificate_subject.DC,zeek_x509.certificate_subject.emailAddress,zeek_x509.certificate_subject.GN,zeek_x509.certificate_subject.initials,zeek_x509.certificate_subject.L,zeek_x509.certificate_subject.O,zeek_x509.certificate_subject.OU,zeek_x509.certificate_subject.pseudonym,zeek_x509.certificate_subject.serialNumber,zeek_x509.certificate_subject.SN,zeek_x509.certificate_subject.ST,zeek_x509.certificate_subject.title,zeek_x509.certificate_subject_full,zeek_x509.certificate_version,zeek_x509.fuid,zeek_x509.san_dns,zeek_x509.san_email,zeek_x509.san_ip,zeek_x509.san_uri";
  this.api.addRightClick("malcolm_kibana_cat_ip",       {name:filterLabel, url:"idmol2kib/filter?start=%ISOSTART%&stop=%ISOSTOP%&field=%DBFIELD%&value=%TEXT%", category:"ip"});
  this.api.addRightClick("malcolm_kibana_cat_port",     {name:filterLabel, url:filterUrl, category:"port"});
  this.api.addRightClick("malcolm_kibana_cat_country",  {name:filterLabel, url:filterUrl, category:"country"});
  this.api.addRightClick("malcolm_kibana_cat_host",     {name:filterLabel, url:filterUrl, category:"host"});
  this.api.addRightClick("malcolm_kibana_cat_md5",      {name:filterLabel, url:filterUrl, category:"md5"});
  this.api.addRightClick("malcolm_kibana_cat_user",     {name:filterLabel, url:filterUrl, category:"user"});
  this.api.addRightClick("malcolm_kibana_fields_zeek",  {name:filterLabel, url:filterUrl, fields:allFieldsStr});
  // add right-click for viewing original JSON document
  this.api.addRightClick("malcolm_session_json_source", {name:"View JSON Document", url:"sessions.json?expression=id=%TEXT%&fields=*&%DATE%", fields:"id"});

  this.api.addView("zeek_common",
    "if (session.zeek)\n" +

    // id information
    "  div.sessionDetailMeta.bold Zeek Common Fields\n" +
    "  dl.sessionDetailMeta(suffix=\"IDs\")\n" +
    "    +arrayList(session.zeek, 'uid', 'Zeek Connection ID', 'zeek.uid')\n" +
    "    +arrayList(session.zeek, 'community_id', 'Zeek Connection Community ID', 'zeek.community_id')\n" +
    "    +arrayList(session.zeek, 'logType', 'Zeek Log Type', 'zeek.logType')\n" +
    "    +arrayList(session.host, 'name', 'Zeek Node', 'host.name')\n" +

    // basic connection information
    "  if (session.zeek.orig_h || session.zeek.orig_p || session.zeek.orig_l2_addr || session.zeek.resp_h || " +
    "      session.zeek.resp_p || session.zeek.resp_l2_addr || session.zeek.proto || session.zeek.service || " +
    "      session.zeek.user)\n" +
    "    dl.sessionDetailMeta(suffix=\"Basic Connection Info\")\n" +
    "      +arrayList(session.zeek, 'orig_h', 'Originating Host', 'zeek.orig_h')\n" +
    "      +arrayList(session.zeek, 'orig_l2_addr', 'Originating MAC', 'zeek.orig_l2_addr')\n" +
    "      +arrayList(session.zeek, 'orig_l2_oui', 'Originating OUI', 'zeek.orig_l2_oui')\n" +
    "      +arrayList(session.zeek, 'orig_hostname', 'Originating Host Name', 'zeek.orig_hostname')\n" +
    "      +arrayList(session.zeek, 'source_ip_reverse_dns', 'Originating Host rDNS', 'zeek.source_ip_reverse_dns')\n" +
    "      +arrayList(session.zeek, 'orig_segment', 'Originating Network Segment', 'zeek.orig_segment')\n" +
    "      +arrayList(session.zeek.source_geo, 'country_name', 'Originating GeoIP Country', 'zeek.source_geo.country_name')\n" +
    "      +arrayList(session.zeek.source_geo, 'city_name', 'Originating GeoIP City', 'zeek.source_geo.city_name')\n" +
    "      +arrayList(session.zeek, 'resp_h', 'Responding Host', 'zeek.resp_h')\n" +
    "      +arrayList(session.zeek, 'resp_l2_addr', 'Responding MAC', 'zeek.resp_l2_addr')\n" +
    "      +arrayList(session.zeek, 'resp_l2_oui', 'Responding OUI', 'zeek.resp_l2_oui')\n" +
    "      +arrayList(session.zeek, 'resp_hostname', 'Responding Host Name', 'zeek.resp_hostname')\n" +
    "      +arrayList(session.zeek, 'destination_ip_reverse_dns', 'Responding Host rDNS', 'zeek.destination_ip_reverse_dns')\n" +
    "      +arrayList(session.zeek, 'resp_segment', 'Responding Network Segment', 'zeek.resp_segment')\n" +
    "      +arrayList(session.zeek.destination_geo, 'country_name', 'Responding GeoIP Country', 'zeek.destination_geo.country_name')\n" +
    "      +arrayList(session.zeek.destination_geo, 'city_name', 'Responding GeoIP City', 'zeek.destination_geo.city_name')\n" +
    "      +arrayList(session.zeek, 'orig_p', 'Originating Port', 'zeek.orig_p')\n" +
    "      +arrayList(session.zeek, 'resp_p', 'Responding Port', 'zeek.resp_p')\n" +
    "      +arrayList(session.zeek, 'proto', 'Protocol', 'zeek.proto')\n" +
    "      +arrayList(session.zeek, 'service', 'Service', 'zeek.service')\n" +
    "      +arrayList(session.zeek, 'user', 'User', 'zeek.user')\n" +

    // file information
    "  if (session.zeek.fuid || session.zeek.filename || session.zeek.filetype)\n" +
    "    dl.sessionDetailMeta(suffix=\"File IDs\")\n" +
    "      +arrayList(session.zeek, 'fuid', 'File ID', 'zeek.fuid')\n" +
    "      +arrayList(session.zeek, 'filename', 'File Name', 'zeek.filename')\n" +
    "      +arrayList(session.zeek, 'filetype', 'File Magic', 'zeek.filetype')\n" +

    // ####################################################################
    "  br\n");

  this.api.addView("zeek_bacnet", "require:zeek_bacnet;title:Zeek bacnet.log;fields:zeek_bacnet.bvlc_function,zeek_bacnet.bvlc_len,zeek_bacnet.apdu_type,zeek_bacnet.service_choice,zeek_bacnet.data,zeek_bacnet.data_dict.date,zeek_bacnet.data_dict.low_limit,zeek_bacnet.data_dict.object,zeek_bacnet.data_dict.property,zeek_bacnet.data_dict.result,zeek_bacnet.data_dict.time,zeek_bacnet.data_dict.ttl")
  this.api.addView("zeek_cip", "require:zeek_cip;title:Zeek cip.log;fields:zeek_cip.cip_service,zeek_cip.status,zeek_cip.cip_tags")
  this.api.addView("zeek_conn", "require:zeek_conn;title:Zeek conn.log;fields:zeek_conn.duration,zeek_conn.orig_bytes,zeek_conn.resp_bytes,zeek_conn.conn_state,zeek_conn.conn_state_description,zeek_conn.local_orig,zeek_conn.local_resp,zeek_conn.missed_bytes,zeek_conn.history,zeek_conn.orig_pkts,zeek_conn.orig_ip_bytes,zeek_conn.resp_pkts,zeek_conn.resp_ip_bytes,zeek_conn.tunnel_parents,zeek_conn.vlan,zeek_conn.inner_vlan")
  this.api.addView("zeek_dce_rpc", "require:zeek_dce_rpc;title:Zeek dce_rpc.log;fields:zeek_dce_rpc.rtt,zeek_dce_rpc.named_pipe,zeek_dce_rpc.endpoint,zeek_dce_rpc.operation")
  this.api.addView("zeek_dhcp", "require:zeek_dhcp;title:Zeek dhcp.log;fields:zeek_dhcp.mac,zeek_dhcp.assigned_ip,zeek_dhcp.lease_time,zeek_dhcp.trans_id")
  this.api.addView("zeek_dnp3", "require:zeek_dnp3;title:Zeek dnp3.log;fields:zeek_dnp3.fc_request,zeek_dnp3.fc_reply,zeek_dnp3.iin")
  this.api.addView("zeek_dns", "require:zeek_dns;title:Zeek dns.log;fields:zeek_dns.trans_id,zeek_dns.rtt,zeek_dns.query,zeek_dns.qclass,zeek_dns.qclass_name,zeek_dns.qtype,zeek_dns.qtype_name,zeek_dns.rcode,zeek_dns.rcode_name,zeek_dns.AA,zeek_dns.TC,zeek_dns.RD,zeek_dns.RA,zeek_dns.Z,zeek_dns.answers,zeek_dns.TTLs,zeek_dns.rejected")
  this.api.addView("zeek_dpd", "require:zeek_dpd;title:Zeek dpd.log;fields:zeek_dpd.service,zeek_dpd.failure_reason")
  this.api.addView("zeek_enip", "require:zeek_enip;title:Zeek enip.log;fields:zeek_enip.command,zeek_enip.length,zeek_enip.session_handle,zeek_enip.status,zeek_enip.sender_context,zeek_enip.options")
  this.api.addView("zeek_enip_list_identity", "require:zeek_enip_list_identity;title:Zeek enip_list_identity.log;fields:zeek_enip_list_identity.device_type,zeek_enip_list_identity.vendor,zeek_enip_list_identity.product_name,zeek_enip_list_identity.serial_number,zeek_enip_list_identity.product_code,zeek_enip_list_identity.revision,zeek_enip_list_identity.status,zeek_enip_list_identity.state,zeek_enip_list_identity.device_ip")
  this.api.addView("zeek_files", "require:zeek_files;title:Zeek files.log;fields:zeek_files.fuid,zeek_files.tx_hosts,zeek_files.rx_hosts,zeek_files.conn_uids,zeek_files.source,zeek_files.depth,zeek_files.analyzers,zeek_files.mime_type,zeek_files.filename,zeek_files.duration,zeek_files.local_orig,zeek_files.is_orig,zeek_files.seen_bytes,zeek_files.total_bytes,zeek_files.missing_bytes,zeek_files.overflow_bytes,zeek_files.timedout,zeek_files.parent_fuid,zeek_files.md5,zeek_files.sha1,zeek_files.sha256,zeek_files.extracted,zeek_files.extracted_cutoff,zeek_files.extracted_size")
  this.api.addView("zeek_ftp", "require:zeek_ftp;title:Zeek ftp.log;fields:zeek_ftp.password,zeek_ftp.command,zeek_ftp.arg,zeek_ftp.mime_type,zeek_ftp.file_size,zeek_ftp.reply_code,zeek_ftp.reply_msg,zeek_ftp.data_channel_passive,zeek_ftp.data_channel_orig_h,zeek_ftp.data_channel_resp_h,zeek_ftp.data_channel_resp_p,zeek_ftp.fuid")
  this.api.addView("zeek_gquic", "require:zeek_gquic;title:Zeek gquic.log;fields:zeek_gquic.version,zeek_gquic.server_name,zeek_gquic.user_agent,zeek_gquic.tag_count,zeek_gquic.cyu,zeek_gquic.cyutags")
  this.api.addView("zeek_http", "require:zeek_http;title:Zeek http.log;fields:zeek_http.trans_depth,zeek_http.method,zeek_http.host,zeek_http.uri,zeek_http.origin,zeek_http.referrer,zeek_http.version,zeek_http.user_agent,zeek_http.request_body_len,zeek_http.response_body_len,zeek_http.status_code,zeek_http.status_msg,zeek_http.info_code,zeek_http.info_msg,zeek_http.tags,zeek_http.user,zeek_http.password,zeek_http.proxied,zeek_http.orig_fuids,zeek_http.orig_filenames,zeek_http.orig_mime_types,zeek_http.resp_fuids,zeek_http.resp_filenames,zeek_http.resp_mime_types")
  this.api.addView("zeek_intel", "require:zeek_intel;title:Zeek intel.log;fields:zeek_intel.indicator,zeek_intel.indicator_type,zeek_intel.seen_where,zeek_intel.seen_node,zeek_intel.matched,zeek_intel.sources,zeek_intel.fuid,zeek_intel.mimetype,zeek_intel.file_description")
  this.api.addView("zeek_irc", "require:zeek_irc;title:Zeek irc.log;fields:zeek_irc.nick,zeek_irc.command,zeek_irc.value,zeek_irc.addl,zeek_irc.dcc_file_name,zeek_irc.dcc_file_size,zeek_irc.dcc_mime_type,zeek_irc.fuid")
  this.api.addView("zeek_iso_cotp", "require:zeek_iso_cotp;title:Zeek iso_cotp.log;fields:zeek_iso_cotp.pdu_type")
  this.api.addView("zeek_kerberos", "require:zeek_kerberos;title:Zeek kerberos.log;fields:zeek_kerberos.cname,zeek_kerberos.sname,zeek_kerberos.success,zeek_kerberos.error_msg,zeek_kerberos.from,zeek_kerberos.till,zeek_kerberos.cipher,zeek_kerberos.forwardable,zeek_kerberos.renewable,zeek_kerberos.client_cert_subject,zeek_kerberos.client_cert_fuid,zeek_kerberos.server_cert_subject,zeek_kerberos.server_cert_fuid")
  this.api.addView("zeek_known_certs", "require:zeek_known_certs;title:Zeek known_certs.log;fields:zeek_known_certs.subject,zeek_known_certs.issuer_subject,zeek_known_certs.serial")
  this.api.addView("zeek_known_modbus", "require:zeek_known_modbus;title:Zeek zeek_known_modbus.log;fields:zeek_known_modbus.device_type")
  this.api.addView("zeek_modbus", "require:zeek_modbus;title:Zeek modbus.log;fields:zeek_modbus.func,zeek_modbus.exception")
  this.api.addView("zeek_modbus_register_change", "require:zeek_modbus_register_change;title:Zeek modbus_register_change.log;fields:modbus_register_change.register,modbus_register_change.old_val,modbus_register_change.new_val,modbus_register_change.delta")
  this.api.addView("zeek_mqtt_connect", "require:zeek_mqtt_connect;title:Zeek mqtt_connect.log;fields:zeek_mqtt_connect.proto_name,zeek_mqtt_connect.proto_version,zeek_mqtt_connect.client_id,zeek_mqtt_connect.connect_status,zeek_mqtt_connect.will_topic,zeek_mqtt_connect.will_payload")
  this.api.addView("zeek_mqtt_publish", "require:zeek_mqtt_publish;title:Zeek mqtt_publish.log;fields:zeek_mqtt_publish.from_client,zeek_mqtt_publish.retain,zeek_mqtt_publish.qos,zeek_mqtt_publish.status,zeek_mqtt_publish.topic,zeek_mqtt_publish.payload,zeek_mqtt_publish.payload_len")
  this.api.addView("zeek_mqtt_subscribe", "require:zeek_mqtt_subscribe;title:Zeek mqtt_subscribe.log;fields:zeek_mqtt_subscribe.action,zeek_mqtt_subscribe.topics,zeek_mqtt_subscribe.qos_levels,zeek_mqtt_subscribe.granted_qos_level,zeek_mqtt_subscribe.ack")
  this.api.addView("zeek_mysql", "require:zeek_mysql;title:Zeek mysql.log;fields:zeek_mysql.cmd,zeek_mysql.arg,zeek_mysql.success,zeek_mysql.rows,zeek_mysql.response")
  this.api.addView("zeek_notice", "require:zeek_notice;title:Zeek notice.log;fields:zeek_notice.fuid,zeek_notice.file_mime_type,zeek_notice.file_desc,zeek_notice.note,zeek_notice.msg,zeek_notice.sub,zeek_notice.src,zeek_notice.dst,zeek_notice.p,zeek_notice.n,zeek_notice.peer_descr,zeek_notice.actions,zeek_notice.suppress_for,zeek_notice.dropped,zeek_notice.remote_location_country_code,zeek_notice.remote_location_region,zeek_notice.remote_location_cityremote_location_latitude,zeek_notice.remote_location_longitude")
  this.api.addView("zeek_ntlm", "require:zeek_ntlm;title:Zeek ntlm.log;fields:zeek_ntlm.host,zeek_ntlm.domain,zeek_ntlm.success,zeek_ntlm.status")
  this.api.addView("zeek_ntp", "require:zeek_ntp;title:Zeek ntp.log;fields:zeek_ntp.version,zeek_ntp.mode,zeek_ntp.mode_str,zeek_ntp.stratum,zeek_ntp.poll,zeek_ntp.precision,zeek_ntp.root_delay,zeek_ntp.root_disp,zeek_ntp.ref_id,zeek_ntp.ref_time,zeek_ntp.org_time,zeek_ntp.rec_time,zeek_ntp.xmt_time,zeek_ntp.num_exts")
  this.api.addView("zeek_pe", "require:zeek_pe;title:Zeek pe.log;fields:zeek_pe.fuid,zeek_pe.machine,zeek_pe.compile_ts,zeek_pe.os,zeek_pe.subsystem,zeek_pe.is_exe,zeek_pe.is_64bit,zeek_pe.uses_aslr,zeek_pe.uses_dep,zeek_pe.uses_code_integrity,zeek_pe.uses_seh,zeek_pe.has_import_table,zeek_pe.has_export_table,zeek_pe.has_cert_table,zeek_pe.has_debug_data,zeek_pe.section_names")
  this.api.addView("zeek_profinet", "require:zeek_profinet;title:Zeek profinet.log;fields:zeek_profinet.operation_type,zeek_profinet.block_version,zeek_profinet.slot_number,zeek_profinet.subslot_number,zeek_profinet.index")
  this.api.addView("zeek_profinet_dce_rpc", "require:zeek_profinet_dce_rpc;title:Zeek profinet_dce_rpc.log;fields:zeek_profinet_dce_rpc.version,zeek_profinet_dce_rpc.packet_type,zeek_profinet_dce_rpc.object_uuid,zeek_profinet_dce_rpc.interface_uuid,zeek_profinet_dce_rpc.activity_uuid,zeek_profinet_dce_rpc.server_boot_time,zeek_profinet_dce_rpc.operation")
  this.api.addView("zeek_radius", "require:zeek_radius;title:Zeek radius.log;fields:zeek_radius.mac,zeek_radius.framed_addr,zeek_radius.remote_ip,zeek_radius.connect_info,zeek_radius.reply_msg,zeek_radius.result,zeek_radius.ttl")
  this.api.addView("zeek_rdp", "require:zeek_rdp;title:Zeek rdp.log;fields:zeek_rdp.cookie,zeek_rdp.result,zeek_rdp.security_protocol,zeek_rdp.client_channels,zeek_rdp.keyboard_layout,zeek_rdp.client_build,zeek_rdp.client_name,zeek_rdp.client_dig_product_id,zeek_rdp.desktop_width,zeek_rdp.desktop_height,zeek_rdp.requested_color_depth,zeek_rdp.cert_type,zeek_rdp.cert_count,zeek_rdp.cert_permanent,zeek_rdp.encryption_level,zeek_rdp.encryption_method")
  this.api.addView("zeek_rfb", "require:zeek_rfb;title:Zeek rfb.log;fields:zeek_rfb.client_major_version,zeek_rfb.client_minor_version,zeek_rfb.server_major_version,zeek_rfb.server_minor_version,zeek_rfb.authentication_method,zeek_rfb.auth,zeek_rfb.share_flag,zeek_rfb.desktop_name,zeek_rfb.width,zeek_rfb.height")
  this.api.addView("zeek_s7comm", "require:zeek_s7comm;title:Zeek s7comm.log;fields:zeek_s7comm.rosctr,zeek_s7comm.parameter,zeek_s7comm.parameters.class,zeek_s7comm.parameters.code,zeek_s7comm.parameters.group,zeek_s7comm.parameters.mode,zeek_s7comm.parameters.sub,zeek_s7comm.parameters.type,zeek_s7comm.item_count,zeek_s7comm.data_info")
  this.api.addView("zeek_signatures", "require:zeek_signatures;title:Zeek signatures.log;fields:zeek_signatures.note,zeek_signatures.signature_id,zeek_signatures.engine,zeek_signatures.event_message,zeek_signatures.sub_message,zeek_signatures.signature_count,zeek_signatures.host_count")
  this.api.addView("zeek_sip", "require:zeek_sip;title:Zeek sip.log;fields:zeek_sip.trans_depth,zeek_sip.method,zeek_sip.uri,zeek_sip.date,zeek_sip.request_from,zeek_sip.request_to,zeek_sip.response_from,zeek_sip.response_to,zeek_sip.reply_to,zeek_sip.call_id,zeek_sip.seq,zeek_sip.subject,zeek_sip.request_path,zeek_sip.response_path,zeek_sip.user_agent,zeek_sip.status_code,zeek_sip.status_msg,zeek_sip.warning,zeek_sip.request_body_len,zeek_sip.response_body_len,zeek_sip.content_type")
  this.api.addView("zeek_smb_files", "require:zeek_smb_files;title:Zeek smb_files.log;fields:zeek_smb_files.fuid,zeek_smb_files.action,zeek_smb_files.path,zeek_smb_files.name,zeek_smb_files.size,zeek_smb_files.prev_name,zeek_smb_files.times_modified,zeek_smb_files.times_accessed,zeek_smb_files.times_created,zeek_smb_files.times_changed")
  this.api.addView("zeek_smb_mapping", "require:zeek_smb_mapping;title:Zeek smb_mapping.log;fields:zeek_smb_mapping.path,zeek_smb_mapping.resource_type,zeek_smb_mapping.native_file_system,zeek_smb_mapping.share_type")
  this.api.addView("zeek_smtp", "require:zeek_smtp;title:Zeek smtp.log;fields:zeek_smtp.trans_depth,zeek_smtp.helo,zeek_smtp.mailfrom,zeek_smtp.rcptto,zeek_smtp.date,zeek_smtp.from,zeek_smtp.to,zeek_smtp.cc,zeek_smtp.reply_to,zeek_smtp.msg_id,zeek_smtp.in_reply_to,zeek_smtp.subject,zeek_smtp.x_originating_ip,zeek_smtp.first_received,zeek_smtp.second_received,zeek_smtp.last_reply,zeek_smtp.path,zeek_smtp.user_agent,zeek_smtp.tls,zeek_smtp.fuids,zeek_smtp.is_webmail")
  this.api.addView("zeek_snmp", "require:zeek_snmp;title:Zeek snmp.log;fields:zeek_snmp.duration,zeek_snmp.version,zeek_snmp.community,zeek_snmp.get_requests,zeek_snmp.get_bulk_requests,zeek_snmp.get_responses,zeek_snmp.set_requests,zeek_snmp.display_string,zeek_snmp.up_since")
  this.api.addView("zeek_socks", "require:zeek_socks;title:Zeek socks.log;fields:zeek_socks.version,zeek_socks.password,zeek_socks.server_status,zeek_socks.request_host,zeek_socks.request_name,zeek_socks.request_port,zeek_socks.bound_host,zeek_socks.bound_name,zeek_socks.bound_port")
  this.api.addView("zeek_software", "require:zeek_software;title:Zeek software.log;fields:zeek_software.software_type,zeek_software.name,zeek_software.version_major,zeek_software.version_minor,zeek_software.version_minor2,zeek_software.version_minor3,zeek_software.version_addl,zeek_software.unparsed_version")
  this.api.addView("zeek_ssh", "require:zeek_ssh;title:Zeek ssh.log;fields:zeek_ssh.version,zeek_ssh.auth_success,zeek_ssh.auth_attempts,zeek_ssh.direction,zeek_ssh.client,zeek_ssh.server,zeek_ssh.cipher_alg,zeek_ssh.mac_alg,zeek_ssh.compression_alg,zeek_ssh.kex_alg,zeek_ssh.host_key_alg,zeek_ssh.host_key,zeek_ssh.remote_location_country_code,zeek_ssh.remote_location_region,zeek_ssh.remote_location_city,zeek_ssh.remote_location_latitude,zeek_ssh.remote_location_longitude,zeek_ssh.hassh,zeek_ssh.hasshServer,zeek_ssh.hasshAlgorithms,zeek_ssh.hasshServerAlgorithms,zeek_ssh.cshka,zeek_ssh.sshka")
  this.api.addView("zeek_ssl", "require:zeek_ssl;title:Zeek ssl.log;fields:zeek_ssl.ssl_version,zeek_ssl.cipher,zeek_ssl.curve,zeek_ssl.server_name,zeek_ssl.resumed,zeek_ssl.last_alert,zeek_ssl.next_protocol,zeek_ssl.established,zeek_ssl.ja3,zeek_ssl.ja3_desc,zeek_ssl.ja3s,zeek_ssl.ja3s_desc,zeek_ssl.cert_chain_fuids,zeek_ssl.client_cert_chain_fuids,zeek_ssl.subject.CN,zeek_ssl.subject.C,zeek_ssl.subject.O,zeek_ssl.subject.OU,zeek_ssl.subject.ST,zeek_ssl.subject.SN,zeek_ssl.subject.L,zeek_ssl.subject.GN,zeek_ssl.subject.pseudonym,zeek_ssl.subject.serialNumber,zeek_ssl.subject.title,zeek_ssl.subject.initials,zeek_ssl.subject.emailAddress,zeek_ssl.client_subject.CN,zeek_ssl.client_subject.C,zeek_ssl.client_subject.O,zeek_ssl.client_subject.OU,zeek_ssl.client_subject.ST,zeek_ssl.client_subject.SN,zeek_ssl.client_subject.L,zeek_ssl.client_subject.GN,zeek_ssl.client_subject.pseudonym,zeek_ssl.client_subject.serialNumber,zeek_ssl.client_subject.title,zeek_ssl.client_subject.initials,zeek_ssl.client_subject.emailAddress,zeek_ssl.issuer.CN,zeek_ssl.issuer.C,zeek_ssl.issuer.O,zeek_ssl.issuer.OU,zeek_ssl.issuer.ST,zeek_ssl.issuer.SN,zeek_ssl.issuer.L,zeek_ssl.issuer.DC,zeek_ssl.issuer.GN,zeek_ssl.issuer.pseudonym,zeek_ssl.issuer.serialNumber,zeek_ssl.issuer.title,zeek_ssl.issuer.initials,zeek_ssl.issuer.emailAddress,zeek_ssl.client_issuer.CN,zeek_ssl.client_issuer.C,zeek_ssl.client_issuer.O,zeek_ssl.client_issuer.OU,zeek_ssl.client_issuer.ST,zeek_ssl.client_issuer.SN,zeek_ssl.client_issuer.L,zeek_ssl.client_issuer.DC,zeek_ssl.client_issuer.GN,zeek_ssl.client_issuer.pseudonym,zeek_ssl.client_issuer.serialNumber,zeek_ssl.client_issuer.title,zeek_ssl.client_issuer.initials,zeek_ssl.client_issuer.emailAddress,zeek_ssl.validation_status")
  this.api.addView("zeek_syslog", "require:zeek_syslog;title:Zeek syslog.log;fields:zeek_syslog.facility,zeek_syslog.severity,zeek_syslog.message")
  this.api.addView("zeek_tds", "require:zeek_tds;title:Zeek tds.log;fields:zeek_tds.command")
  this.api.addView("zeek_tds_rpc", "require:zeek_tds_rpc;title:Zeek tds_rpc.log;fields:zeek_tds_rpc.procedure_name,zeek_tds_rpc.parameters")
  this.api.addView("zeek_tds_sql_batch", "require:zeek_tds_sql_batch;title:Zeek tds_sql_batch.log;fields:zeek_tds_sql_batch.header_type,zeek_tds_sql_batch.query")
  this.api.addView("zeek_tunnel", "require:zeek_tunnel;title:Zeek tunnel.log;fields:zeek_tunnel.tunnel_type,zeek_tunnel.action")
  this.api.addView("zeek_weird", "require:zeek_weird;title:Zeek weird.log;fields:zeek_weird.name,zeek_weird.addl,zeek_weird.notice,zeek_weird.peer")
  this.api.addView("zeek_x509", "require:zeek_x509;title:Zeek x509.log;fields:zeek_x509.fuid,zeek_x509.certificate_version,zeek_x509.certificate_serial,zeek_x509.certificate_subject.CN,zeek_x509.certificate_subject.C,zeek_x509.certificate_subject.O,zeek_x509.certificate_subject.OU,zeek_x509.certificate_subject.ST,zeek_x509.certificate_subject.SN,zeek_x509.certificate_subject.L,zeek_x509.certificate_subject.DC,zeek_x509.certificate_subject.GN,zeek_x509.certificate_subject.pseudonym,zeek_x509.certificate_subject.serialNumber,zeek_x509.certificate_subject.title,zeek_x509.certificate_subject.initials,zeek_x509.certificate_subject.emailAddress,zeek_x509.certificate_issuer.CN,zeek_x509.certificate_issuer.C,zeek_x509.certificate_issuer.O,zeek_x509.certificate_issuer.OU,zeek_x509.certificate_issuer.ST,zeek_x509.certificate_issuer.SN,zeek_x509.certificate_issuer.L,zeek_x509.certificate_issuer.GN,zeek_x509.certificate_issuer.pseudonym,zeek_x509.certificate_issuer.serialNumber,zeek_x509.certificate_issuer.title,zeek_x509.certificate_issuer.initials,zeek_x509.certificate_issuer.emailAddress,zeek_x509.certificate_not_valid_before,zeek_x509.certificate_not_valid_after,zeek_x509.certificate_key_alg,zeek_x509.certificate_sig_alg,zeek_x509.certificate_key_type,zeek_x509.certificate_key_length,zeek_x509.certificate_exponent,zeek_x509.certificate_curve,zeek_x509.san_dns,zeek_x509.san_uri,zeek_x509.san_email,zeek_x509.san_ip,zeek_x509.basic_constraints_ca,zeek_x509.basic_constraints_path_len")

  // Add the source as available
  this.api.addSource("zeek", this);
}
util.inherits(ZeekLogs, wiseSource);

ZeekLogs.prototype.load = function() {
  var self = this;
  this.data.clear();
}

ZeekLogs.prototype.getDomain = function(domain, cb) {
};

ZeekLogs.prototype.getIp = function(ip, cb) {
};

ZeekLogs.prototype.getMd5 = function(md5, cb) {
};

ZeekLogs.prototype.getEmail = function(email, cb) {
};

exports.initSource = function(api) {
  var source = new ZeekLogs(api, "zeek");
};
