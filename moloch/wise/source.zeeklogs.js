var wiseSource     = require('./wiseSource.js')
  , util           = require('util')
  ;

//////////////////////////////////////////////////////////////////////////////////
// Arkime WISE Data Source definition for Zeek logs.
//
// Part of Malcolm (https://github.com/idaholab/malcolm)
//
// Data may be populated with Malcolm's Zeek Logstash filters:
//   (particularly https://raw.githubusercontent.com/idaholab/Malcolm/master/logstash/pipeline-main/11_zeek_logs.conf)
//
// Copyright (c) 2021 Battelle Energy Alliance, LLC.  All rights reserved.
// see https://raw.githubusercontent.com/idaholab/Malcolm/master/License.txt
//////////////////////////////////////////////////////////////////////////////////
function ZeekLogs (api, section) {
  ZeekLogs.super_.call(this, api, section);

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
  this.service_versionField = this.api.addField("field:zeek.service_version;db:zeek.service_version;kind:termfield;friendly:Service Version;help:Service Version");
  this.actionField = this.api.addField("field:zeek.action;db:zeek.action;kind:termfield;friendly:Action;help:Action");
  this.resultField = this.api.addField("field:zeek.result;db:zeek.result;kind:termfield;friendly:Result;help:Result");
  this.userField = this.api.addField("field:zeek.user;db:zeek.user;kind:termfield;friendly:User;help:User");
  this.passwordField = this.api.addField("field:zeek.password;db:zeek.password;kind:termfield;friendly:Password;help:Password");
  this.freq_score_v1 = this.api.addField("field:zeek.freq_score_v1;db:zeek_dns.freq_score_v1;kind:termfield;friendly:Freq Score v1;help:Freq Score v1");
  this.freq_score_v2 = this.api.addField("field:zeek.freq_score_v2;db:zeek_dns.freq_score_v2;kind:termfield;friendly:Freq Score v2;help:Freq Score v2");

  // file information
  this.fuidField = this.api.addField("field:zeek.fuid;db:zeek.fuid;kind:termfield;friendly:File ID;help:File ID");
  this.filenameField = this.api.addField("field:zeek.filename;db:zeek.filename;kind:termfield;friendly:File Name;help:File Name");
  this.filetypeField = this.api.addField("field:zeek.filetype;db:zeek.filetype;kind:termfield;friendly:File Magic;help:File Magic");

  // conn.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/conn/main.zeek.html#type-Conn::Info
  this.conn_durationField = this.api.addField("field:zeek_conn.duration;db:zeek_conn.duration;kind:termfield;friendly:Duration;help:Duration");
  this.conn_orig_bytesField = this.api.addField("field:zeek_conn.orig_bytes;db:zeek_conn.orig_bytes;kind:integer;friendly:Originating Bytes;help:Originating Bytes");
  this.conn_resp_bytesField = this.api.addField("field:zeek_conn.resp_bytes;db:zeek_conn.resp_bytes;kind:integer;friendly:Responding Bytes;help:Responding Bytes");
  this.conn_conn_stateField = this.api.addField("field:zeek_conn.conn_state;db:zeek_conn.conn_state;kind:termfield;friendly:Connection State Code;help:Connection State Code");
  this.conn_conn_state_descriptionField = this.api.addField("field:zeek_conn.conn_state_description;db:zeek_conn.conn_state_description;kind:termfield;friendly:conn Connection State;help:conn Connection State");
  this.conn_local_origField = this.api.addField("field:zeek_conn.local_orig;db:zeek_conn.local_orig;kind:termfield;friendly:Local Originator;help:Local Originator");
  this.conn_local_respField = this.api.addField("field:zeek_conn.local_resp;db:zeek_conn.local_resp;kind:termfield;friendly:Local Responder;help:Local Responder");
  this.conn_missed_bytesField = this.api.addField("field:zeek_conn.missed_bytes;db:zeek_conn.missed_bytes;kind:integer;friendly:Missed Bytes;help:Missed Bytes");
  this.conn_historyField = this.api.addField("field:zeek_conn.history;db:zeek_conn.history;kind:termfield;friendly:Connection Flags History;help:Connection Flags History");
  this.conn_orig_pktsField = this.api.addField("field:zeek_conn.orig_pkts;db:zeek_conn.orig_pkts;kind:integer;friendly:Originating Packets;help:Originating Packets");
  this.conn_orig_ip_bytesField = this.api.addField("field:zeek_conn.orig_ip_bytes;db:zeek_conn.orig_ip_bytes;kind:integer;friendly:Originating IP Bytes;help:Originating IP Bytes");
  this.conn_resp_pktsField = this.api.addField("field:zeek_conn.resp_pkts;db:zeek_conn.resp_pkts;kind:integer;friendly:Responding Packets;help:Responding Packets");
  this.conn_resp_ip_bytesField = this.api.addField("field:zeek_conn.resp_ip_bytes;db:zeek_conn.resp_ip_bytes;kind:integer;friendly:Responding IP Bytes;help:Responding IP Bytes");
  this.conn_tunnel_parentsField = this.api.addField("field:zeek_conn.tunnel_parents;db:zeek_conn.tunnel_parents;kind:termfield;friendly:Tunnel Connection ID;help:Tunnel Connection ID");
  this.conn_vlanField = this.api.addField("field:zeek_conn.vlan;db:zeek_conn.vlan;kind:integer;friendly:Outer VLAN;help:Outer VLAN");
  this.conn_inner_vlanField = this.api.addField("field:zeek_conn.inner_vlan;db:zeek_conn.inner_vlan;kind:integer;friendly:Inner VLAN;help:Inner VLAN");

  // bacnet.log
  // https://github.com/cisagov/ICSNPP
  this.bacnet_bvlc_functionField = this.api.addField("field:zeek_bacnet.bvlc_function;db:zeek_bacnet.bvlc_function;kind:termfield;friendly:BVLC Function;help:BVLC Function");
  this.bacnet_pdu_typeField = this.api.addField("field:zeek_bacnet.pdu_type;db:zeek_bacnet.pdu_type;kind:termfield;friendly:APDU Service Type;help:APDU Service Type");
  this.bacnet_pdu_serviceField = this.api.addField("field:zeek_bacnet.pdu_service;db:zeek_bacnet.pdu_service;kind:termfield;friendly:APDU Service Choice;help:APDU Service Choice");
  this.bacnet_invoke_idField = this.api.addField("field:zeek_bacnet.invoke_id;db:zeek_bacnet.invoke_id;kind:integer;friendly:Invoke ID;help:Invoke ID");
  this.bacnet_result_codeField = this.api.addField("field:zeek_bacnet.result_code;db:zeek_bacnet.result_code;kind:termfield;friendly:Result Code;help:Result Code");

  // bacnet_discovery.log
  // https://github.com/cisagov/ICSNPP
  this.bacnet_dicovery_pdu_serviceField = this.api.addField("field:zeek_bacnet_discovery.pdu_service;db:zeek_bacnet_discovery.pdu_service;kind:termfield;friendly:APDU Service;help:APDU Service");
  this.bacnet_dicovery_object_typeField = this.api.addField("field:zeek_bacnet_discovery.object_type;db:zeek_bacnet_discovery.object_type;kind:termfield;friendly:Object Type;help:Object Type");
  this.bacnet_dicovery_instance_numberField = this.api.addField("field:zeek_bacnet_discovery.instance_number;db:zeek_bacnet_discovery.instance_number;kind:integer;friendly:Instance Number;help:Instance Number");
  this.bacnet_dicovery_vendorField = this.api.addField("field:zeek_bacnet_discovery.vendor;db:zeek_bacnet_discovery.vendor;kind:termfield;friendly:Vendor Name;help:Vendor Name");
  this.bacnet_dicovery_rangeField = this.api.addField("field:zeek_bacnet_discovery.range;db:zeek_bacnet_discovery.range;kind:termfield;friendly:Range;help:Range");
  this.bacnet_dicovery_rangeLowField = this.api.addField("field:zeek_bacnet_discovery.range_low;db:zeek_bacnet_discovery.range_low;kind:integer;friendly:Range Low;help:Range Low");
  this.bacnet_dicovery_rangeHighField = this.api.addField("field:zeek_bacnet_discovery.range_high;db:zeek_bacnet_discovery.range_high;kind:integer;friendly:Range High;help:Range High");
  this.bacnet_dicovery_object_nameField = this.api.addField("field:zeek_bacnet_discovery.object_name;db:zeek_bacnet_discovery.object_name;kind:termfield;friendly:Object Name;help:Object Name");

  // bacnet_property.log
  // https://github.com/cisagov/ICSNPP
  this.bacnet_dicovery_pdu_serviceField = this.api.addField("field:zeek_bacnet_property.pdu_service;db:zeek_bacnet_property.pdu_service;kind:termfield;friendly:APDU Service;help:APDU Service");
  this.bacnet_dicovery_object_typeField = this.api.addField("field:zeek_bacnet_property.object_type;db:zeek_bacnet_property.object_type;kind:termfield;friendly:Object Type;help:Object Type");
  this.bacnet_dicovery_instance_numberField = this.api.addField("field:zeek_bacnet_property.instance_number;db:zeek_bacnet_property.instance_number;kind:integer;friendly:Instance Number;help:Instance Number");
  this.bacnet_dicovery_propertyField = this.api.addField("field:zeek_bacnet_property.property;db:zeek_bacnet_property.property;kind:termfield;friendly:Property Type;help:Property Type");
  this.bacnet_dicovery_array_indexField = this.api.addField("field:zeek_bacnet_property.array_index;db:zeek_bacnet_property.array_index;kind:integer;friendly:Array Index;help:Array Index");
  this.bacnet_dicovery_valueField = this.api.addField("field:zeek_bacnet_property.value;db:zeek_bacnet_property.value;kind:termfield;friendly:Value;help:Value");

  // bsap_ip_header.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_ip_parser
  this.bsap_ip_header_num_msgField = this.api.addField("field:zeek_bsap_ip_header.num_msg;db:zeek_bsap_ip_header.num_msg;kind:termfield;friendly:Functions per Message;help:Functions per Message");
  this.bsap_ip_header_type_nameField = this.api.addField("field:zeek_bsap_ip_header.type_name;db:zeek_bsap_ip_header.type_name;kind:integer;friendly:Message Type;help:Message Type");

  // bsap_ip_rdb.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_ip_parser
  this.bsap_ip_rdb_app_func_codeField = this.api.addField("field:zeek_bsap_ip_rdb.app_func_code;db:zeek_bsap_ip_rdb.app_func_code;kind:termfield;friendly:Application Function;help:Application Function");
  this.bsap_ip_rdb_data_lenField = this.api.addField("field:zeek_bsap_ip_rdb.data_len;db:zeek_bsap_ip_rdb.data_len;kind:integer;friendly:Data Length;help:Data Length");
  this.bsap_ip_rdb_dataField = this.api.addField("field:zeek_bsap_ip_rdb.data;db:zeek_bsap_ip_rdb.data;kind:termfield;friendly:Subfunction Data;help:Subfunction Data");
  this.bsap_ip_rdb_func_codeField = this.api.addField("field:zeek_bsap_ip_rdb.func_code;db:zeek_bsap_ip_rdb.func_code;kind:termfield;friendly:Application Subfunction;help:Application Subfunction");
  this.bsap_ip_rdb_header_sizeField = this.api.addField("field:zeek_bsap_ip_rdb.header_size;db:zeek_bsap_ip_rdb.header_size;kind:integer;friendly:Header Length;help:Header Length");
  this.bsap_ip_rdb_mes_seqField = this.api.addField("field:zeek_bsap_ip_rdb.mes_seq;db:zeek_bsap_ip_rdb.mes_seq;kind:integer;friendly:Message Sequence;help:Message Sequence");
  this.bsap_ip_rdb_node_statusField = this.api.addField("field:zeek_bsap_ip_rdb.node_status;db:zeek_bsap_ip_rdb.node_status;kind:integer;friendly:Node Status;help:friendly:Node Status");
  this.bsap_ip_rdb_res_seqField = this.api.addField("field:zeek_bsap_ip_rdb.res_seq;db:zeek_bsap_ip_rdb.res_seq;kind:integer;friendly:Response Sequence;help:Response Sequence");
  this.bsap_ip_rdb_sequenceField = this.api.addField("field:zeek_bsap_ip_rdb.sequence;db:zeek_bsap_ip_rdb.sequence;kind:integer;friendly:Function Sequence;help:Function Sequence");

  // bsap_ip_unknown.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_ip_parser
  this.bsap_ip_unknown_dataField = this.api.addField("field:zeek_bsap_ip_unknown.data;db:zeek_bsap_ip_unknown.data;kind:termfield;friendly:Unknown Data;help:Unknown Data");

  // bsap_serial_header.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_serial_parser
  this.bsap_serial_header_ctlField = this.api.addField("field:zeek_bsap_serial_header.ctl;db:zeek_bsap_serial_header.ctl;kind:integer;friendly:Control Byte;help:Control Byte");
  this.bsap_serial_header_daddField = this.api.addField("field:zeek_bsap_serial_header.dadd;db:zeek_bsap_serial_header.dadd;kind:integer;friendly:Destination Address;help:Destination Address");
  this.bsap_serial_header_dfunField = this.api.addField("field:zeek_bsap_serial_header.dfun;db:zeek_bsap_serial_header.dfun;kind:termfield;friendly:Destination Function;help:Destination Function");
  this.bsap_serial_header_nsbField = this.api.addField("field:zeek_bsap_serial_header.nsb;db:zeek_bsap_serial_header.nsb;kind:integer;friendly:Node Status;help:Node Statussb");
  this.bsap_serial_header_saddField = this.api.addField("field:zeek_bsap_serial_header.sadd;db:zeek_bsap_serial_header.sadd;kind:integer;friendly:Source Address;help:Source Address");
  this.bsap_serial_header_seqField = this.api.addField("field:zeek_bsap_serial_header.seq;db:zeek_bsap_serial_header.seq;kind:integer;friendly:Message Sequence;help:Message Sequence");
  this.bsap_serial_header_serField = this.api.addField("field:zeek_bsap_serial_header.ser;db:zeek_bsap_serial_header.ser;kind:termfield;friendly:Message Serial Number;help:Message Serial Number");
  this.bsap_serial_header_sfunField = this.api.addField("field:zeek_bsap_serial_header.sfun;db:zeek_bsap_serial_header.sfun;kind:termfield;friendly:Source Function;help:Source Function");
  this.bsap_serial_header_type_nameField = this.api.addField("field:zeek_bsap_serial_header.type_name;db:zeek_bsap_serial_header.type_name;kind:termfield;friendly:Message Type;help:Message Type");

  // bsap_serial_rdb.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_serial_parser
  this.bsap_serial_rdb_dataField = this.api.addField("field:zeek_bsap_serial_rdb.data;db:zeek_bsap_serial_rdb.data;kind:termfield;friendly:RDB Function Data;help:RDB Function Data");
  this.bsap_serial_rdb_func_codeField = this.api.addField("field:zeek_bsap_serial_rdb.func_code;db:zeek_bsap_serial_rdb.func_code;kind:termfield;friendly:RDB Function;help:RDB Function");

  // bsap_serial_rdb_ext.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_serial_parser
  this.bsap_serial_rdb_ext_dataField = this.api.addField("field:zeek_bsap_serial_rdb_ext.data;db:zeek_bsap_serial_rdb_ext.data;kind:termfield;friendly:RDB Ext Function Data;help:RDB Ext Function Data");
  this.bsap_serial_rdb_ext_dfunField = this.api.addField("field:zeek_bsap_serial_rdb_ext.dfun;db:zeek_bsap_serial_rdb_ext.dfun;kind:termfield;friendly:Destination Function;help:Destination Function");
  this.bsap_serial_rdb_ext_extfunField = this.api.addField("field:zeek_bsap_serial_rdb_ext.extfun;db:zeek_bsap_serial_rdb_ext.extfun;kind:termfield;friendly:RDB Ext Function;help:RDB Ext Function");
  this.bsap_serial_rdb_ext_nsbField = this.api.addField("field:zeek_bsap_serial_rdb_ext.nsb;db:zeek_bsap_serial_rdb_ext.nsb;kind:integer;friendly:Node Status;help:Node Status");
  this.bsap_serial_rdb_ext_seqField = this.api.addField("field:zeek_bsap_serial_rdb_ext.seq;db:zeek_bsap_serial_rdb_ext.seq;kind:integer;friendly:Message Sequence;help:Message Sequence");
  this.bsap_serial_rdb_ext_sfunField = this.api.addField("field:zeek_bsap_serial_rdb_ext.sfun;db:zeek_bsap_serial_rdb_ext.sfun;kind:termfield;friendly:Source Function;help:Source Function");

  // bsap_serial_unknown.log
  // https://github.com/cisagov/ICSNPP/tree/master/zeek_bsap_serial_parser
  this.bsap_serial_unknown_dataField = this.api.addField("field:zeek_bsap_serial_unknown.data;db:zeek_bsap_serial_unknown.data;kind:termfield;friendly:Unknown Data;help:Unknown Data");

  // cip.log
  // https://github.com/cisagov/ICSNPP
  this.cip_cip_sequence_countField = this.api.addField("field:zeek_cip.cip_sequence_count;db:zeek_cip.cip_sequence_count;kind:integer;friendly:CIP Sequence Number;help:CIP Sequence Number");
  this.cip_directionField = this.api.addField("field:zeek_cip.direction;db:zeek_cip.direction;kind:termfield;friendly:Direction;help:Direction");
  this.cip_cip_serviceField = this.api.addField("field:zeek_cip.cip_service;db:zeek_cip.cip_service;kind:termfield;friendly:CIP Service;help:CIP Service");
  this.cip_cip_statusField = this.api.addField("field:zeek_cip.cip_status;db:zeek_cip.cip_status;kind:termfield;friendly:CIP Status;help:CIP Status");
  this.cip_class_idField = this.api.addField("field:zeek_cip.class_id;db:zeek_cip.class_id;kind:termfield;friendly:Class ID;help:Class ID");
  this.cip_class_nameField = this.api.addField("field:zeek_cip.class_name;db:zeek_cip.class_name;kind:termfield;friendly:Class Name;help:Class Name");
  this.cip_instance_idField = this.api.addField("field:zeek_cip.instance_id;db:zeek_cip.instance_id;kind:termfield;friendly:Instance ID;help:Instance ID");
  this.cip_attribute_idField = this.api.addField("field:zeek_cip.attribute_id;db:zeek_cip.attribute_id;kind:termfield;friendly:Attribute ID;help:Attribute ID");
  this.cip_data_idField = this.api.addField("field:zeek_cip.data_id;db:zeek_cip.data_id;kind:termfield;friendly:Data ID;help:Data ID");
  this.cip_other_idField = this.api.addField("field:zeek_cip.other_id;db:zeek_cip.other_id;kind:termfield;friendly:Other ID;help:Other ID");

  // cip_identity.log
  // https://github.com/cisagov/ICSNPP
  this.cip_identity_encapsulation_versionField = this.api.addField("field:zeek_cip_identity.encapsulation_version;db:zeek_cip_identity.encapsulation_version;kind:integer;friendly:Encapsulation Version;help:Encapsulation Version");
  this.cip_identity_socket_addressField = this.api.addField("field:zeek_cip_identity.socket_address;db:zeek_cip_identity.socket_address;kind:termfield;friendly:Socket Address;help:Socket Address");
  this.cip_identity_socket_address_geo_cityField = this.api.addField("field:zeek_cip_identity.socket_address_geo.city_name;db:zeek_cip_identity.socket_address_geo.city_name;kind:termfield;friendly:Socket Address GeoIP City;help:Socket Address GeoIP City");
  this.cip_identity_socket_address_geo_countryField = this.api.addField("field:zeek_cip_identity.socket_address_geo.country_name;db:zeek_cip_identity.socket_address_geo.country_name;kind:termfield;friendly:Socket Address GeoIP Country;help:Socket Address GeoIP Country");
  this.cip_identity_socket_address_ASNField = this.api.addField("field:zeek_cip_identity.socket_address_asn;db:zeek_cip_identity.socket_address_asn;kind:termfield;friendly:Socket Address ASN;help:Socket Address ASN");
  this.cip_identity_socket_portField = this.api.addField("field:zeek_cip_identity.socket_port;db:zeek_cip_identity.socket_port;kind:integer;friendly:Socket Port;help:Socket Port");
  this.cip_identity_vendor_idField = this.api.addField("field:zeek_cip_identity.vendor_id;db:zeek_cip_identity.vendor_id;kind:integer;friendly:Vendor ID;help:Vendor ID");
  this.cip_identity_vendor_nameField = this.api.addField("field:zeek_cip_identity.vendor_name;db:zeek_cip_identity.vendor_name;kind:termfield;friendly:Vendor Name;help:Vendor Name");
  this.cip_identity_device_type_idField = this.api.addField("field:zeek_cip_identity.device_type_id;db:zeek_cip_identity.device_type_id;kind:integer;friendly:Device Type ID;help:Device Type ID");
  this.cip_identity_device_type_nameField = this.api.addField("field:zeek_cip_identity.device_type_name;db:zeek_cip_identity.device_type_name;kind:termfield;friendly:Device Type Name;help:Device Type Name");
  this.cip_identity_product_codeField = this.api.addField("field:zeek_cip_identity.product_code;db:zeek_cip_identity.product_code;kind:integer;friendly:Product Code;help:Product Code");
  this.cip_identity_revisionField = this.api.addField("field:zeek_cip_identity.revision;db:zeek_cip_identity.revision;kind:termfield;friendly:Device Revision;help:Device Revision");
  this.cip_identity_device_statusField = this.api.addField("field:zeek_cip_identity.device_status;db:zeek_cip_identity.device_status;kind:termfield;friendly:Device Status;help:Device Status");
  this.cip_identity_serial_numberField = this.api.addField("field:zeek_cip_identity.serial_number;db:zeek_cip_identity.serial_number;kind:termfield;friendly:Serial Number;help:Serial Number");
  this.cip_identity_product_nameField = this.api.addField("field:zeek_cip_identity.product_name;db:zeek_cip_identity.product_name;kind:termfield;friendly:Product Name;help:Product Name");
  this.cip_identity_device_stateField = this.api.addField("field:zeek_cip_identity.device_state;db:zeek_cip_identity.device_state;kind:termfield;friendly:Device State;help:Device State");

  // cip_io.log
  // https://github.com/cisagov/ICSNPP
  this.cip_io_connection_idField = this.api.addField("field:zeek_cip_io.connection_id;db:zeek_cip_io.connection_id;kind:termfield;friendly:Connection ID;help:Connection ID");
  this.cip_io_sequence_numberField = this.api.addField("field:zeek_cip_io.sequence_number;db:zeek_cip_io.sequence_number;kind:integer;friendly:Sequence Number;help:Sequence Number");
  this.cip_io_data_lengthField = this.api.addField("field:zeek_cip_io.data_length;db:zeek_cip_io.data_length;kind:integer;friendly:Data Length;help:Data Length");
  this.cip_io_io_dataField = this.api.addField("field:zeek_cip_io.io_data;db:zeek_cip_io.io_data;kind:termfield;friendly:Transport Data;help:Transport Data");

  // dce_rpc.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dce-rpc/main.zeek.html#type-DCE_RPC::Info
  this.dce_rpc_rttField = this.api.addField("field:zeek_dce_rpc.rtt;db:zeek_dce_rpc.rtt;kind:termfield;friendly:Round Trip Time;help:Round Trip Time");
  this.dce_rpc_named_pipeField = this.api.addField("field:zeek_dce_rpc.named_pipe;db:zeek_dce_rpc.named_pipe;kind:termfield;friendly:Remote Pipe;help:Remote Pipe");
  this.dce_rpc_endpointField = this.api.addField("field:zeek_dce_rpc.endpoint;db:zeek_dce_rpc.endpoint;kind:termfield;friendly:Endpoint;help:Endpoint");
  this.dce_rpc_operationField = this.api.addField("field:zeek_dce_rpc.operation;db:zeek_dce_rpc.operation;kind:termfield;friendly:Operation;help:Operation");

  // dhcp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dhcp/main.zeek.html#type-DHCP::Info
  this.dhcp_macField = this.api.addField("field:zeek_dhcp.mac;db:zeek_dhcp.mac;kind:termfield;friendly:Client MAC;help:Client MAC");
  this.dhcp_assigned_ipField = this.api.addField("field:zeek_dhcp.assigned_ip;db:zeek_dhcp.assigned_ip;kind:termfield;friendly:Assigned IP;help:Assigned IP");
  this.dhcp_lease_timeField = this.api.addField("field:zeek_dhcp.lease_time;db:zeek_dhcp.lease_time;kind:termfield;friendly:Lease Time;help:Lease Time");
  this.dhcp_trans_idField = this.api.addField("field:zeek_dhcp.trans_id;db:zeek_dhcp.trans_id;kind:termfield;friendly:dhcp Transaction ID;help:dhcp Transaction ID");
  this.dhcp_client_fqdnField = this.api.addField("field:zeek_dhcp.client_fqdn;db:zeek_dhcp.client_fqdn;kind:termfield;friendly:Client FQDN;help:Client FQDN");
  this.dhcp_client_messageField = this.api.addField("field:zeek_dhcp.client_message;db:zeek_dhcp.client_message;kind:termfield;friendly:Client Message;help:Client Message");
  this.dhcp_domainField = this.api.addField("field:zeek_dhcp.domain;db:zeek_dhcp.domain;kind:termfield;friendly:Domain;help:Domain");
  this.dhcp_durationField = this.api.addField("field:zeek_dhcp.duration;db:zeek_dhcp.duration;kind:termfield;friendly:Duration;help:Duration");
  this.dhcp_host_nameField = this.api.addField("field:zeek_dhcp.host_name;db:zeek_dhcp.host_name;kind:termfield;friendly:Hostname;help:Hostname");
  this.dhcp_msg_typesField = this.api.addField("field:zeek_dhcp.msg_types;db:zeek_dhcp.msg_types;kind:termfield;friendly:Message Types;help:Message Types");
  this.dhcp_requested_ipField = this.api.addField("field:zeek_dhcp.requested_ip;db:zeek_dhcp.requested_ip;kind:termfield;friendly:Requested IP;help:Requested IP");
  this.dhcp_server_messageField = this.api.addField("field:zeek_dhcp.server_message;db:zeek_dhcp.server_message;kind:termfield;friendly:Server Message;help:Server Message");
  this.dhcp_client_softwareField = this.api.addField("field:zeek_dhcp.client_software;db:zeek_dhcp.client_software;kind:termfield;friendly:Client Software;help:Client Software");
  this.dhcp_server_softwareField = this.api.addField("field:zeek_dhcp.server_software;db:zeek_dhcp.server_software;kind:termfield;friendly:Server Software;help:Server Software");

  // dnp3.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dnp3/main.zeek.html#type-DNP3::Info
  this.dnp3_fc_requestField = this.api.addField("field:zeek_dnp3.fc_request;db:zeek_dnp3.fc_request;kind:termfield;friendly:Request Function Message;help:Request Function Message");
  this.dnp3_fc_replyField = this.api.addField("field:zeek_dnp3.fc_reply;db:zeek_dnp3.fc_reply;kind:termfield;friendly:Reply Function Message;help:Reply Function Message");
  this.dnp3_iinField = this.api.addField("field:zeek_dnp3.iin;db:zeek_dnp3.iin;kind:termfield;friendly:Internal Indication Number;help:Internal Indication Number");
  this.dnp3_iin_flagsField = this.api.addField("field:zeek_dnp3.iin_flags;db:zeek_dnp3.iin_flags;kind:termfield;friendly:Internal Indicators;help:Internal Indicators");

  // dnp3_control.log
  // https://github.com/cisagov/ICSNPP
  this.dnp3_control_block_typeField = this.api.addField("field:zeek_dnp3_control.block_type;db:zeek_dnp3_control.block_type;kind:termfield;friendly:Control Block Type;help:Control Block Type");
  this.dnp3_control_function_codeField = this.api.addField("field:zeek_dnp3_control.function_code;db:zeek_dnp3_control.function_code;kind:termfield;friendly:DNP3 Function Code;help:DNP3 Function Code");
  this.dnp3_control_index_numberField = this.api.addField("field:zeek_dnp3_control.index_number;db:zeek_dnp3_control.index_number;kind:integer;friendly:Object Index Number;help:Object Index Number");
  this.dnp3_control_trip_control_codeField = this.api.addField("field:zeek_dnp3_control.trip_control_code;db:zeek_dnp3_control.trip_control_code;kind:termfield;friendly:Trip Control Code;help:Trip Control Code");
  this.dnp3_control_operation_typeField = this.api.addField("field:zeek_dnp3_control.operation_type;db:zeek_dnp3_control.operation_type;kind:termfield;friendly:Operation Type;help:Operation Type");
  this.dnp3_control_execute_countField = this.api.addField("field:zeek_dnp3_control.execute_count;db:zeek_dnp3_control.execute_count;kind:integer;friendly:Execute Count;help:Execute Count");
  this.dnp3_control_on_timeField = this.api.addField("field:zeek_dnp3_control.on_time;db:zeek_dnp3_control.on_time;kind:integer;friendly:On Time;help:On Time");
  this.dnp3_control_off_timeField = this.api.addField("field:zeek_dnp3_control.off_time;db:zeek_dnp3_control.off_time;kind:integer;friendly:Off Time;help:Off Time");
  this.dnp3_control_status_codeField = this.api.addField("field:zeek_dnp3_control.status_code;db:zeek_dnp3_control.status_code;kind:termfield;friendly:Status Code;help:Status Code");

  // dnp3_objects.log
  // https://github.com/cisagov/ICSNPP
  this.dnp3_objects_function_codeField = this.api.addField("field:zeek_dnp3_objects.function_code;db:zeek_dnp3_objects.function_code;kind:termfield;friendly:Function Code;help:Function Code");
  this.dnp3_objects_object_typeField = this.api.addField("field:zeek_dnp3_objects.object_type;db:zeek_dnp3_objects.object_type;kind:termfield;friendly:Object Type;help:Object Type");
  this.dnp3_objects_object_countField = this.api.addField("field:zeek_dnp3_objects.object_count;db:zeek_dnp3_objects.object_count;kind:integer;friendly:Object Count;help:Object Count");
  this.dnp3_objects_range_lowField = this.api.addField("field:zeek_dnp3_objects.range_low;db:zeek_dnp3_objects.range_low;kind:integer;friendly:Range Low;help:Range Low");
  this.dnp3_objects_range_highField = this.api.addField("field:zeek_dnp3_objects.range_high;db:zeek_dnp3_objects.range_high;kind:integer;friendly:Range High;help:Range High");

  // dns.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/dns/main.zeek.html#type-DNS::Info
  this.dns_trans_idField = this.api.addField("field:zeek_dns.trans_id;db:zeek_dns.trans_id;kind:termfield;friendly:Transaction ID;help:Transaction ID");
  this.dns_rttField = this.api.addField("field:zeek_dns.rtt;db:zeek_dns.rtt;kind:termfield;friendly:Round Trip Time;help:Round Trip Time");
  this.dns_queryField = this.api.addField("field:zeek_dns.query;db:zeek_dns.query;kind:termfield;friendly:Query;help:Query");
  this.dns_qclassField = this.api.addField("field:zeek_dns.qclass;db:zeek_dns.qclass;kind:termfield;friendly:Query Class Code;help:Query Class Code");
  this.dns_qclass_nameField = this.api.addField("field:zeek_dns.qclass_name;db:zeek_dns.qclass_name;kind:termfield;friendly:Query Class;help:Query Class");
  this.dns_qtypeField = this.api.addField("field:zeek_dns.qtype;db:zeek_dns.qtype;kind:termfield;friendly:Query Type Code;help:Query Type Code");
  this.dns_qtype_nameField = this.api.addField("field:zeek_dns.qtype_name;db:zeek_dns.qtype_name;kind:termfield;friendly:Query Type;help:Query Type");
  this.dns_rcodeField = this.api.addField("field:zeek_dns.rcode;db:zeek_dns.rcode;kind:integer;friendly:Response Code;help:Response Code");
  this.dns_rcode_nameField = this.api.addField("field:zeek_dns.rcode_name;db:zeek_dns.rcode_name;kind:termfield;friendly:Response;help:Response");
  this.dns_AAField = this.api.addField("field:zeek_dns.AA;db:zeek_dns.AA;kind:termfield;friendly:Authoritative Answer Bit;help:Authoritative Answer Bit");
  this.dns_TCField = this.api.addField("field:zeek_dns.TC;db:zeek_dns.TC;kind:termfield;friendly:Truncation Bit;help:Truncation Bit");
  this.dns_RDField = this.api.addField("field:zeek_dns.RD;db:zeek_dns.RD;kind:termfield;friendly:Recursion Desired Bit;help:Recursion Desired Bit");
  this.dns_RAField = this.api.addField("field:zeek_dns.RA;db:zeek_dns.RA;kind:termfield;friendly:Recursion Available Bit;help:Recursion Available Bit");
  this.dns_ZField = this.api.addField("field:zeek_dns.Z;db:zeek_dns.Z;kind:termfield;friendly:Z Bit;help:Z Bit");
  this.dns_answersField = this.api.addField("field:zeek_dns.answers;db:zeek_dns.answers;kind:termfield;friendly:Answer;help:Answer");
  this.dns_TTLsField = this.api.addField("field:zeek_dns.TTLs;db:zeek_dns.TTLs;kind:termfield;friendly:TTL;help:TTL");
  this.dns_rejectedField = this.api.addField("field:zeek_dns.rejected;db:zeek_dns.rejected;kind:termfield;friendly:Rejected;help:Rejected");

  // dpd.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/dpd/main.zeek.html#type-DPD::Info
  this.dpd_serviceField = this.api.addField("field:zeek_dpd.service;db:zeek_dpd.service;kind:termfield;friendly:Protocol;help:Protocol");
  this.dpd_failure_reasonField = this.api.addField("field:zeek_dpd.failure_reason;db:zeek_dpd.failure_reason;kind:termfield;friendly:Failure Reason;help:Failure Reason");

  // enip.log
  // https://github.com/cisagov/ICSNPP
  this.enip_enip_commandField = this.api.addField("field:zeek_enip.enip_command;db:zeek_enip.enip_command;kind:termfield;friendly:EthernetIP Command;help:EthernetIP Command");
  this.enip_lengthField = this.api.addField("field:zeek_enip.length;db:zeek_enip.length;kind:integer;friendly:Packet Length;help:Packet Length");
  this.enip_session_handleField = this.api.addField("field:zeek_enip.session_handle;db:zeek_enip.session_handle;kind:termfield;friendly:Session Number;help:Session Number");
  this.enip_enip_statusField = this.api.addField("field:zeek_enip.enip_status;db:zeek_enip.enipstatus;kind:termfield;friendly:EthernetIP Status;help:EthernetIP Status");
  this.enip_sender_contextField = this.api.addField("field:zeek_enip.sender_context;db:zeek_enip.sender_context;kind:termfield;friendly:Sender Context;help:Sender Context");
  this.enip_optionsField = this.api.addField("field:zeek_enip.options;db:zeek_enip.options;kind:termfield;friendly:Options;help:Options");

  // files.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/files/main.zeek.html#type-Files::Info
  this.files_tx_hostsField = this.api.addField("field:zeek_files.tx_hosts;db:zeek_files.tx_hosts;kind:termfield;friendly:Transmitter;help:Transmitter");
  this.files_rx_hostsField = this.api.addField("field:zeek_files.rx_hosts;db:zeek_files.rx_hosts;kind:termfield;friendly:Receiver;help:Receiver");
  this.files_conn_uidsField = this.api.addField("field:zeek_files.conn_uids;db:zeek_files.conn_uids;kind:termfield;friendly:Connection ID;help:Connection ID");
  this.files_sourceField = this.api.addField("field:zeek_files.source;db:zeek_files.source;kind:termfield;friendly:Source;help:Source");
  this.files_depthField = this.api.addField("field:zeek_files.depth;db:zeek_files.depth;kind:integer;friendly:Source Depth;help:Source Depth");
  this.files_analyzersField = this.api.addField("field:zeek_files.analyzers;db:zeek_files.analyzers;kind:termfield;friendly:Analyzer;help:Analyzer");
  this.files_mime_typeField = this.api.addField("field:zeek_files.mime_type;db:zeek_files.mime_type;kind:termfield;friendly:File Magic;help:File Magic");
  this.files_filenameField = this.api.addField("field:zeek_files.filename;db:zeek_files.filename;kind:termfield;friendly:Filename;help:Filename");
  this.files_durationField = this.api.addField("field:zeek_files.duration;db:zeek_files.duration;kind:termfield;friendly:Analysis Duration;help:Analysis Duration");
  this.files_local_origField = this.api.addField("field:zeek_files.local_orig;db:zeek_files.local_orig;kind:termfield;friendly:Local Originator;help:Local Originator");
  this.files_is_origField = this.api.addField("field:zeek_files.is_orig;db:zeek_files.is_orig;kind:termfield;friendly:Originator is Transmitter;help:Originator is Transmitter");
  this.files_seen_bytesField = this.api.addField("field:zeek_files.seen_bytes;db:zeek_files.seen_bytes;kind:integer;friendly:Bytes Analyzed;help:Bytes Analyzed");
  this.files_total_bytesField = this.api.addField("field:zeek_files.total_bytes;db:zeek_files.total_bytes;kind:integer;friendly:Total Bytes;help:Total Bytes");
  this.files_missing_bytesField = this.api.addField("field:zeek_files.missing_bytes;db:zeek_files.missing_bytes;kind:integer;friendly:Missed Bytes;help:Missed Bytes");
  this.files_overflow_bytesField = this.api.addField("field:zeek_files.overflow_bytes;db:zeek_files.overflow_bytes;kind:integer;friendly:Overflow Bytes;help:Overflow Bytes");
  this.files_timedoutField = this.api.addField("field:zeek_files.timedout;db:zeek_files.timedout;kind:termfield;friendly:Analysis Timed Out;help:Analysis Timed Out");
  this.files_parent_fuidField = this.api.addField("field:zeek_files.parent_fuid;db:zeek_files.parent_fuid;kind:termfield;friendly:Parent File ID;help:Parent File ID");
  this.files_md5Field = this.api.addField("field:zeek_files.md5;db:zeek_files.md5;kind:termfield;friendly:MD5 Digest;help:MD5 Digest");
  this.files_sha1Field = this.api.addField("field:zeek_files.sha1;db:zeek_files.sha1;kind:termfield;friendly:SHA1 Digest;help:SHA1 Digest");
  this.files_sha256Field = this.api.addField("field:zeek_files.sha256;db:zeek_files.sha256;kind:termfield;friendly:SHA256 Digest;help:SHA256 Digest");
  this.files_extractedField = this.api.addField("field:zeek_files.extracted;db:zeek_files.extracted;kind:termfield;friendly:Extracted Filename;help:Extracted Filename");
  this.files_extracted_cutoffField = this.api.addField("field:zeek_files.extracted_cutoff;db:zeek_files.extracted_cutoff;kind:termfield;friendly:Truncated;help:Truncated");
  this.files_extracted_sizeField = this.api.addField("field:zeek_files.extracted_size;db:zeek_files.extracted_size;kind:integer;friendly:Extracted Bytes;help:Extracted Bytes");

  // ftp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ftp/info.zeek.html#type-FTP::Info
  this.ftp_commandField = this.api.addField("field:zeek_ftp.command;db:zeek_ftp.command;kind:termfield;friendly:Command;help:Command");
  this.ftp_argField = this.api.addField("field:zeek_ftp.arg;db:zeek_ftp.arg;kind:termfield;friendly:Argument;help:Argument");
  this.ftp_mime_typeField = this.api.addField("field:zeek_ftp.mime_type;db:zeek_ftp.mime_type;kind:termfield;friendly:File Magic;help:File Magic");
  this.ftp_file_sizeField = this.api.addField("field:zeek_ftp.file_size;db:zeek_ftp.file_size;kind:integer;friendly:File Size;help:File Size");
  this.ftp_reply_codeField = this.api.addField("field:zeek_ftp.reply_code;db:zeek_ftp.reply_code;kind:integer;friendly:Reply Code;help:Reply Code");
  this.ftp_reply_msgField = this.api.addField("field:zeek_ftp.reply_msg;db:zeek_ftp.reply_msg;kind:termfield;friendly:Reply;help:Reply");
  this.ftp_data_channel_passiveField = this.api.addField("field:zeek_ftp.data_channel_passive;db:zeek_ftp.data_channel_passive;kind:termfield;friendly:Passive;help:Passive");
  this.ftp_data_channel_orig_hField = this.api.addField("field:zeek_ftp.data_channel_orig_h;db:zeek_ftp.data_channel_orig_h;kind:termfield;friendly:Data Originating Host;help:Data Originating Host");
  this.ftp_data_channel_resp_hField = this.api.addField("field:zeek_ftp.data_channel_resp_h;db:zeek_ftp.data_channel_resp_h;kind:termfield;friendly:Data Responding Host;help:Data Responding Host");
  this.ftp_data_channel_resp_pField = this.api.addField("field:zeek_ftp.data_channel_resp_p;db:zeek_ftp.data_channel_resp_p;kind:integer;friendly:Data Responding Port;help:Data Responding Port");

  // gquic.log
  // https://github.com/salesforce/GQUIC_Protocol_Analyzer/blob/master/scripts/Salesforce/GQUIC/main.bro
  this.gquic_versionField = this.api.addField("field:zeek_gquic.version;db:zeek_gquic.version;kind:termfield;friendly:QUIC version;help:gquic version");
  this.gquic_server_nameField = this.api.addField("field:zeek_gquic.server_name;db:zeek_gquic.server_name;kind:termfield;friendly:Server Name;help:gquic server_name");
  this.gquic_user_agentField = this.api.addField("field:zeek_gquic.user_agent;db:zeek_gquic.user_agent;kind:termfield;friendly:User Agent;help:gquic user_agent");
  this.gquic_tag_countField = this.api.addField("field:zeek_gquic.tag_count;db:zeek_gquic.tag_count;kind:integer;friendly:Tag Count;help:gquic tag_count");
  this.gquic_cyuField = this.api.addField("field:zeek_gquic.cyu;db:zeek_gquic.cyu;kind:termfield;friendly:CYU Fingerprint;help:gquic cyu");
  this.gquic_cyutagsField = this.api.addField("field:zeek_gquic.cyutags;db:zeek_gquic.cyutags;kind:termfield;friendly:CYU Fingerprint Digest;help:gquic cyutags");

  // http.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/http/main.zeek.html#type-HTTP::Info
  this.http_trans_depthField = this.api.addField("field:zeek_http.trans_depth;db:zeek_http.trans_depth;kind:integer;friendly:Pipeline Depth;help:Pipeline Depth");
  this.http_methodField = this.api.addField("field:zeek_http.method;db:zeek_http.method;kind:termfield;friendly:Request Method;help:Request Method");
  this.http_hostField = this.api.addField("field:zeek_http.host;db:zeek_http.host;kind:termfield;friendly:Host Header;help:Host Header");
  this.http_uriField = this.api.addField("field:zeek_http.uri;db:zeek_http.uri;kind:termfield;friendly:URI;help:URI");
  this.http_referrerField = this.api.addField("field:zeek_http.referrer;db:zeek_http.referrer;kind:termfield;friendly:Referrer Header;help:Referrer Header");
  this.http_versionField = this.api.addField("field:zeek_http.version;db:zeek_http.version;kind:termfield;friendly:Version;help:Version");
  this.http_user_agentField = this.api.addField("field:zeek_http.user_agent;db:zeek_http.user_agent;kind:termfield;friendly:User Agent;help:User Agent");
  this.http_originField = this.api.addField("field:zeek_http.origin;db:zeek_http.origin;kind:termfield;friendly:Origin Header;help:Origin Header");
  this.http_request_body_lenField = this.api.addField("field:zeek_http.request_body_len;db:zeek_http.request_body_len;kind:integer;friendly:Request Body Length;help:Request Body Length");
  this.http_response_body_lenField = this.api.addField("field:zeek_http.response_body_len;db:zeek_http.response_body_len;kind:integer;friendly:Response Body Length;help:Response Body Length");
  this.http_status_codeField = this.api.addField("field:zeek_http.status_code;db:zeek_http.status_code;kind:integer;friendly:Status Code;help:Status Code");
  this.http_status_msgField = this.api.addField("field:zeek_http.status_msg;db:zeek_http.status_msg;kind:termfield;friendly:Status Message;help:Status Message");
  this.http_info_codeField = this.api.addField("field:zeek_http.info_code;db:zeek_http.info_code;kind:integer;friendly:Informational Code;help:Informational Code");
  this.http_info_msgField = this.api.addField("field:zeek_http.info_msg;db:zeek_http.info_msg;kind:termfield;friendly:Informational Message;help:Informational Message");
  this.http_tagsField = this.api.addField("field:zeek_http.tags;db:zeek_http.tags;kind:termfield;friendly:HTTP Tag;help:HTTP Tag");
  this.http_proxiedField = this.api.addField("field:zeek_http.proxied;db:zeek_http.proxied;kind:termfield;friendly:Proxy Header;help:Proxy Header");
  this.http_orig_fuidsField = this.api.addField("field:zeek_http.orig_fuids;db:zeek_http.orig_fuids;kind:termfield;friendly:Originating File ID;help:Originating File ID");
  this.http_orig_filenamesField = this.api.addField("field:zeek_http.orig_filenames;db:zeek_http.orig_filenames;kind:termfield;friendly:Originating Filename;help:Originating Filename");
  this.http_orig_mime_typesField = this.api.addField("field:zeek_http.orig_mime_types;db:zeek_http.orig_mime_types;kind:termfield;friendly:Originating File Magic;help:Originating File Magic");
  this.http_resp_fuidsField = this.api.addField("field:zeek_http.resp_fuids;db:zeek_http.resp_fuids;kind:termfield;friendly:Responding File ID;help:Responding File ID");
  this.http_resp_filenamesField = this.api.addField("field:zeek_http.resp_filenames;db:zeek_http.resp_filenames;kind:termfield;friendly:Responding Filename;help:Responding Filename");
  this.http_resp_mime_typesField = this.api.addField("field:zeek_http.resp_mime_types;db:zeek_http.resp_mime_types;kind:termfield;friendly:Responding File Magic;help:Responding File Magic");
  this.http_post_usernameField = this.api.addField("field:zeek_http.post_username;db:zeek_http.post_username;kind:termfield;friendly:POST User;help:POST User");
  this.http_post_password_plainField = this.api.addField("field:zeek_http.post_password_plain;db:zeek_http.post_password_plain;kind:termfield;friendly:POST Password;help:POST Password");

  // intel.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/intel/main.zeek.html#type-Intel::Info
  this.intel_indicatorField = this.api.addField("field:zeek_intel.indicator;db:zeek_intel.indicator;kind:termfield;friendly:Indicator;help:Indicator");
  this.intel_indicator_typeField = this.api.addField("field:zeek_intel.indicator_type;db:zeek_intel.indicator_type;kind:termfield;friendly:Indicator Type;help:Indicator Type");
  this.intel_seen_whereField = this.api.addField("field:zeek_intel.seen_where;db:zeek_intel.seen_where;kind:termfield;friendly:Where Discovered;help:Where Discovered");
  this.intel_seen_nodeField = this.api.addField("field:zeek_intel.seen_node;db:zeek_intel.seen_node;kind:termfield;friendly:Discovered Node;help:Discovered Node");
  this.intel_matchedField = this.api.addField("field:zeek_intel.matched;db:zeek_intel.matched;kind:termfield;friendly:Match Indicator;help:Match Indicator");
  this.intel_sourcesField = this.api.addField("field:zeek_intel.sources;db:zeek_intel.sources;kind:termfield;friendly:Match Source;help:Match Source");
  this.intel_file_mime_typeField = this.api.addField("field:zeek_intel.file_mime_type;db:zeek_intel.file_mime_type;kind:termfield;friendly:File Magic;help:File Magic");
  this.intel_file_descriptionField = this.api.addField("field:zeek_intel.file_description;db:zeek_intel.file_description;kind:termfield;friendly:File Description;help:File Description");

  // irc.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/irc/main.zeek.html#type-IRC::Info
  this.irc_nickField = this.api.addField("field:zeek_irc.nick;db:zeek_irc.nick;kind:termfield;friendly:Nickname;help:Nickname");
  this.irc_commandField = this.api.addField("field:zeek_irc.command;db:zeek_irc.command;kind:termfield;friendly:Command;help:Command");
  this.irc_valueField = this.api.addField("field:zeek_irc.value;db:zeek_irc.value;kind:termfield;friendly:Value;help:Value");
  this.irc_addlField = this.api.addField("field:zeek_irc.addl;db:zeek_irc.addl;kind:termfield;friendly:Additional Data;help:Additional Data");
  this.irc_dcc_file_nameField = this.api.addField("field:zeek_irc.dcc_file_name;db:zeek_irc.dcc_file_name;kind:termfield;friendly:DCC Filename;help:DCC Filename");
  this.irc_dcc_file_sizeField = this.api.addField("field:zeek_irc.dcc_file_size;db:zeek_irc.dcc_file_size;kind:integer;friendly:DCC File Size;help:DCC File Size");
  this.irc_dcc_mime_typeField = this.api.addField("field:zeek_irc.dcc_mime_type;db:zeek_irc.dcc_mime_type;kind:termfield;friendly:DCC File Magic;help:DCC File Magic");

  // iso_cotp.log
  // https://github.com/amzn/zeek-plugin-s7comm/blob/master/scripts/main.zeek
  this.iso_cotp_pdu_typeField = this.api.addField("field:zeek_iso_cotp.pdu_type;db:zeek_iso_cotp.pdu_type;kind:termfield;friendly:PDU Type;help:PDU Type");

  // kerberos.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/krb/main.zeek.html#type-KRB::Info
  this.kerberos_cnameField = this.api.addField("field:zeek_kerberos.cname;db:zeek_kerberos.cname;kind:termfield;friendly:Client;help:Client");
  this.kerberos_snameField = this.api.addField("field:zeek_kerberos.sname;db:zeek_kerberos.sname;kind:termfield;friendly:Service;help:Service");
  this.kerberos_successField = this.api.addField("field:zeek_kerberos.success;db:zeek_kerberos.success;kind:termfield;friendly:Success;help:Success");
  this.kerberos_error_msgField = this.api.addField("field:zeek_kerberos.error_msg;db:zeek_kerberos.error_msg;kind:termfield;friendly:Error Message;help:Error Message");
  this.kerberos_fromField = this.api.addField("field:zeek_kerberos.from;db:zeek_kerberos.from;kind:termfield;friendly:Ticket Valid From;help:Ticket Valid From");
  this.kerberos_tillField = this.api.addField("field:zeek_kerberos.till;db:zeek_kerberos.till;kind:termfield;friendly:Ticket Valid Till;help:Ticket Valid Till");
  this.kerberos_cipherField = this.api.addField("field:zeek_kerberos.cipher;db:zeek_kerberos.cipher;kind:termfield;friendly:Encryption Type;help:Encryption Type");
  this.kerberos_forwardableField = this.api.addField("field:zeek_kerberos.forwardable;db:zeek_kerberos.forwardable;kind:termfield;friendly:Forwardable;help:Forwardable");
  this.kerberos_renewableField = this.api.addField("field:zeek_kerberos.renewable;db:zeek_kerberos.renewable;kind:termfield;friendly:Renewable;help:Renewable");
  this.kerberos_request_typeField = this.api.addField("field:zeek_kerberos.request_type;db:zeek_kerberos.request_type;kind:termfield;friendly:Request Type;help:Request Type");
  this.kerberos_client_cert_subjectField = this.api.addField("field:zeek_kerberos.client_cert_subject;db:zeek_kerberos.client_cert_subject;kind:termfield;friendly:Client Certificate Subject;help:Client Certificate Subject");
  this.kerberos_client_cert_fuidField = this.api.addField("field:zeek_kerberos.client_cert_fuid;db:zeek_kerberos.client_cert_fuid;kind:termfield;friendly:Client Certificate File ID;help:Client Certificate File ID");
  this.kerberos_server_cert_subjectField = this.api.addField("field:zeek_kerberos.server_cert_subject;db:zeek_kerberos.server_cert_subject;kind:termfield;friendly:Server Certificate Subject;help:Server Certificate Subject");
  this.kerberos_server_cert_fuidField = this.api.addField("field:zeek_kerberos.server_cert_fuid;db:zeek_kerberos.server_cert_fuid;kind:termfield;friendly:Server Certificate File ID;help:Server Certificate File ID");

  // known_certs.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/ssl/known-certs.zeek.html#type-Known::CertsInfo
  this.known_certs_subjectField = this.api.addField("field:zeek_known_certs.subject;db:zeek_known_certs.subject;kind:termfield;friendly:Certificate Subject;help:Certificate Subject");
  this.known_certs_issuer_subjectField = this.api.addField("field:zeek_known_certs.issuer_subject;db:zeek_known_certs.issuer_subject;kind:termfield;friendly:Issuer Subject;help:Issuer Subject");
  this.known_certs_serialField = this.api.addField("field:zeek_known_certs.serial;db:zeek_known_certs.serial;kind:termfield;friendly:Serial Number;help:Serial Number");

  // known_modbus.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/known-masters-slaves.zeek.html#type-Known::ModbusInfo
  this.known_modbus_device_typeField = this.api.addField("field:zeek_known_modbus.device_type;db:zeek_known_modbus.device_type;kind:termfield;friendly:Role;help:Role");

  // ldap.log
  // https://github.com/SoftwareConsultingEmporium/ldap-analyzer/blob/master/scripts/main.bro
  this.ldap_message_idField = this.api.addField("field:zeek_ldap.message_id;db:zeek_ldap.message_id;kind:termfield;friendly:Message ID;help:Message ID");
  this.ldap_operationField = this.api.addField("field:zeek_ldap.operation;db:zeek_ldap.operation;kind:termfield;friendly:Operation;help:Operation");
  this.ldap_valueField = this.api.addField("field:zeek_ldap.value;db:zeek_ldap.value;kind:termfield;friendly:Request Value;help:Request Value");
  this.ldap_entryField = this.api.addField("field:zeek_ldap.entry;db:zeek_ldap.entry;kind:termfield;friendly:Entry;help:Entry");
  this.ldap_result_codeField = this.api.addField("field:zeek_ldap.result_code;db:zeek_ldap.result_code;kind:integer;friendly:Result Code;help:Result Code");
  this.ldap_resultField = this.api.addField("field:zeek_ldap.result;db:zeek_ldap.result;kind:integer;friendly:Result;help:Result");
  this.ldap_errorField = this.api.addField("field:zeek_ldap.error;db:zeek_ldap.error;kind:termfield;friendly:Error;help:Error");

  // login.log - custom login.log module (rudimentary, login/rlogin/rsh analyzers are old and not the greatest)
  this.login_successField = this.api.addField("field:zeek_login.success;db:zeek_login.success;kind:termfield;friendly:Successful Login;help:Successful Login");
  this.login_confusedField = this.api.addField("field:zeek_login.confused;db:zeek_login.confused;kind:termfield;friendly:Analyzer Confused;help:Analyzer Confused");
  this.login_client_userField = this.api.addField("field:zeek_login.client_user;db:zeek_login.client_user;kind:termfield;friendly:Client User;help:Client User");

  // modbus.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/modbus/main.zeek.html#type-Modbus::Info
  this.modbus_funcField = this.api.addField("field:zeek_modbus.func;db:zeek_modbus.func;kind:termfield;friendly:Function;help:Function");
  this.modbus_exceptionField = this.api.addField("field:zeek_modbus.exception;db:zeek_modbus.exception;kind:termfield;friendly:Exception;help:Exception");

  // modbus_detailed.log
  // https://github.com/cisagov/ICSNPP
  this.modbus_detailed_unit_idField = this.api.addField("field:zeek_modbus_detailed.unit_id;db:modbus_detailed.unit_id;kind:integer;friendly:Unit/Slave ID;help:Unit/Slave ID");
  this.modbus_detailed_funcField = this.api.addField("field:zeek_modbus_detailed.func;db:modbus_detailed.func;kind:termfield;friendly:Modbus Function Code;help:Modbus Function Code");
  this.modbus_detailed_network_directionField = this.api.addField("field:zeek_modbus_detailed.network_direction;db:modbus_detailed.network_direction;kind:termfield;friendly:Request or Response;help:Request or Response");
  this.modbus_detailed_addressField = this.api.addField("field:zeek_modbus_detailed.address;db:modbus_detailed.address;kind:integer;friendly:Starting Memory Address;help:Starting Memory Address");
  this.modbus_detailed_quantityField = this.api.addField("field:zeek_modbus_detailed.quantity;db:modbus_detailed.quantity;kind:integer;friendly:Number of Values;help:Number of Values");
  this.modbus_detailed_valuesField = this.api.addField("field:zeek_modbus_detailed.values;db:modbus_detailed.values;kind:termfield;friendly:Values;help:Values");

  // modbus_mask_write_register.log
  // https://github.com/cisagov/ICSNPP
  this.modbus_mask_write_register_unit_idField = this.api.addField("field:zeek_modbus_mask_write_register.unit_id;db:modbus_mask_write_register.unit_id;kind:integer;friendly:Unit/Slave ID;help:Unit/Slave ID");
  this.modbus_mask_write_register_funcField = this.api.addField("field:zeek_modbus_mask_write_register.func;db:modbus_mask_write_register.func;kind:termfield;friendly:Modbus Function Code;help:Modbus Function Code");
  this.modbus_mask_write_register_network_directionField = this.api.addField("field:zeek_modbus_mask_write_register.network_direction;db:modbus_mask_write_register.network_direction;kind:termfield;friendly:Request or Response;help:Request or Response");
  this.modbus_mask_write_register_addressField = this.api.addField("field:zeek_modbus_mask_write_register.address;db:modbus_mask_write_register.address;kind:integer;friendly:Starting Memory Address;help:Starting Memory Address");
  this.modbus_mask_write_register_and_maskField = this.api.addField("field:zeek_modbus_mask_write_register.and_mask;db:modbus_mask_write_register.and_mask;kind:integer;friendly:Boolean AND mask to apply to target register;help:Boolean AND mask to apply to target register");
  this.modbus_mask_write_register_or_maskField = this.api.addField("field:zeek_modbus_mask_write_register.or_mask;db:modbus_mask_write_register.or_mask;kind:integer;friendly:Boolean OR mask to apply to target register;help:Boolean OR mask to apply to target register");

  // modbus_read_write_multiple_registers.log
  // https://github.com/cisagov/ICSNPP
  this.modbus_read_write_multiple_registers_unit_idField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.unit_id;db:modbus_read_write_multiple_registers.unit_id;kind:integer;friendly:Unit/Slave ID;help:Unit/Slave ID");
  this.modbus_read_write_multiple_registers_funcField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.func;db:modbus_read_write_multiple_registers.func;kind:termfield;friendly:Modbus Function Code;help:Modbus Function Code");
  this.modbus_read_write_multiple_registers_network_directionField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.network_direction;db:modbus_read_write_multiple_registers.network_direction;kind:termfield;friendly:Request or Response;help:Request or Response");
  this.modbus_read_write_multiple_registers_write_start_addressField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.write_start_address;db:modbus_read_write_multiple_registers.write_start_address;kind:integer;friendly:Starting address of the registers to write to;help:Starting address of the registers to write to");
  this.modbus_read_write_multiple_registers_write_registersField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.write_registers;db:modbus_read_write_multiple_registers.write_registers;kind:termfield;friendly:Register values written;help:Register values written");
  this.modbus_read_write_multiple_registers_read_start_addressField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.read_start_address;db:modbus_read_write_multiple_registers.read_start_address;kind:integer;friendly:Starting address of the registers to read;help:Starting address of the registers to read");
  this.modbus_read_write_multiple_registers_read_quantityField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.read_quantity;db:modbus_read_write_multiple_registers.read_quantity;kind:integer;friendly:Number of registers to read;help:Number of registers to read");
  this.modbus_read_write_multiple_registers_read_registersField = this.api.addField("field:zeek_modbus_read_write_multiple_registers.read_registers;db:modbus_read_write_multiple_registers.read_registers;kind:termfield;friendly:Register values read;help:Register values read");

  // modbus_register_change.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/modbus/track-memmap.zeek.html#type-Modbus::MemmapInfo
  this.modbus_register_change_registerField = this.api.addField("field:zeek_modbus_register_change.register;db:zeek_modbus_register_change.register;kind:integer;friendly:Register;help:Register");
  this.modbus_register_change_old_valField = this.api.addField("field:zeek_modbus_register_change.old_val;db:zeek_modbus_register_change.old_val;kind:integer;friendly:Old Value;help:Old Value");
  this.modbus_register_change_new_valField = this.api.addField("field:zeek_modbus_register_change.new_val;db:zeek_modbus_register_change.new_val;kind:integer;friendly:New Value;help:New Value");
  this.modbus_register_change_deltaField = this.api.addField("field:zeek_modbus_register_change.delta;db:zeek_modbus_register_change.delta;kind:termfield;friendly:Change Interval;help:Change Interval");

  // mqtt_connect.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::ConnectInfo
  this.mqtt_connect_proto_nameField = this.api.addField("field:zeek_mqtt_connect.proto_name;db:zeek_mqtt_connect.proto_name;kind:termfield;friendly:MQTT Protocol;help:MQTT Protocol");
  this.mqtt_connect_proto_versionField = this.api.addField("field:zeek_mqtt_connect.proto_version;db:zeek_mqtt_connect.proto_version;kind:termfield;friendly:Protocol Version;help:Protocol Version");
  this.mqtt_connect_client_idField = this.api.addField("field:zeek_mqtt_connect.client_id;db:zeek_mqtt_connect.client_id;kind:termfield;friendly:Client ID;help:Client ID");
  this.mqtt_connect_connect_statusField = this.api.addField("field:zeek_mqtt_connect.connect_status;db:zeek_mqtt_connect.connect_status;kind:termfield;friendly:Connect Status;help:Connect Status");
  this.mqtt_connect_will_topicField = this.api.addField("field:zeek_mqtt_connect.will_topic;db:zeek_mqtt_connect.will_topic;kind:termfield;friendly:LWT Topic;help:Last Will and Testament Topic");
  this.mqtt_connect_will_payloadField = this.api.addField("field:zeek_mqtt_connect.will_payload;db:zeek_mqtt_connect.will_payload;kind:termfield;friendly:LWT Payload;help:Last Will and Testament Payload");

  // mqtt_publish.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::PublishInfo
  this.mqtt_publish_from_clientField = this.api.addField("field:zeek_mqtt_publish.from_client;db:zeek_mqtt_publish.from_client;kind:termfield;friendly:From Client;help:From Client");
  this.mqtt_publish_retainField = this.api.addField("field:zeek_mqtt_publish.retain;db:zeek_mqtt_publish.retain;kind:termfield;friendly:Retain Flag;help:Retain Flag");
  this.mqtt_publish_qosField = this.api.addField("field:zeek_mqtt_publish.qos;db:zeek_mqtt_publish.qos;kind:termfield;friendly:QoS Level;help:QoS Level");
  this.mqtt_publish_statusField = this.api.addField("field:zeek_mqtt_publish.status;db:zeek_mqtt_publish.status;kind:termfield;friendly:Message Status;help:Message Status");
  this.mqtt_publish_topicField = this.api.addField("field:zeek_mqtt_publish.topic;db:zeek_mqtt_publish.topic;kind:termfield;friendly:Topic;help:Topic");
  this.mqtt_publish_payloadField = this.api.addField("field:zeek_mqtt_publish.payload;db:zeek_mqtt_publish.payload;kind:termfield;friendly:Payload;help:Payload");
  this.mqtt_publish_payload_lenField = this.api.addField("field:zeek_mqtt_publish.payload_len;db:zeek_mqtt_publish.payload_len;kind:integer;friendly:Payload Length;help:Payload Length");

  // mqtt_subscribe.log
  // https://docs.zeek.org/en/stable/scripts/policy/protocols/mqtt/main.zeek.html#type-MQTT::SubscribeInfo
  this.mqtt_subscribe_actionField = this.api.addField("field:zeek_mqtt_subscribe.action;db:zeek_mqtt_subscribe.action;kind:termfield;friendly:Action;help:Action");
  this.mqtt_subscribe_topicsField = this.api.addField("field:zeek_mqtt_subscribe.topics;db:zeek_mqtt_subscribe.topics;kind:termfield;friendly:Topic;help:Topic");
  this.mqtt_subscribe_qos_levelsField = this.api.addField("field:zeek_mqtt_subscribe.qos_levels;db:zeek_mqtt_subscribe.qos_levels;kind:integer;friendly:QoS Level Requested;help:QoS Level Requested");
  this.mqtt_subscribe_granted_qos_levelField = this.api.addField("field:zeek_mqtt_subscribe.granted_qos_level;db:zeek_mqtt_subscribe.granted_qos_level;kind:integer;friendly:QoS Level Granted;help:QoS Level Granted");
  this.mqtt_subscribe_ackField = this.api.addField("field:zeek_mqtt_subscribe.ack;db:zeek_mqtt_subscribe.ack;kind:termfield;friendly:ACKed;help:ACKed");

  // mysql.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/mysql/main.zeek.html#type-MySQL::Info
  this.mysql_cmdField = this.api.addField("field:zeek_mysql.cmd;db:zeek_mysql.cmd;kind:termfield;friendly:Command;help:Command");
  this.mysql_argField = this.api.addField("field:zeek_mysql.arg;db:zeek_mysql.arg;kind:termfield;friendly:Argument;help:Argument");
  this.mysql_successField = this.api.addField("field:zeek_mysql.success;db:zeek_mysql.success;kind:termfield;friendly:Success;help:Success");
  this.mysql_rowsField = this.api.addField("field:zeek_mysql.rows;db:zeek_mysql.rows;kind:integer;friendly:Rows Affected;help:Rows Affected");
  this.mysql_responseField = this.api.addField("field:zeek_mysql.response;db:zeek_mysql.response;kind:termfield;friendly:Response;help:Response");

  // notice.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/main.zeek.html#type-Notice::Info
  this.notice_file_mime_typeField = this.api.addField("field:zeek_notice.file_mime_type;db:zeek_notice.file_mime_type;kind:termfield;friendly:File Magic;help:File Magic");
  this.notice_file_descField = this.api.addField("field:zeek_notice.file_desc;db:zeek_notice.file_desc;kind:termfield;friendly:File Description;help:File Description");
  this.notice_noteField = this.api.addField("field:zeek_notice.note;db:zeek_notice.note;kind:termfield;friendly:Notice Type;help:Notice Type");
  this.notice_categoryField = this.api.addField("field:zeek_notice.category;db:zeek_notice.category;kind:termfield;friendly:Category;help:Category");
  this.notice_sub_categoryField = this.api.addField("field:zeek_notice.sub_category;db:zeek_notice.sub_category;kind:termfield;friendly:Subcategory;help:Subcategory");
  this.notice_msgField = this.api.addField("field:zeek_notice.msg;db:zeek_notice.msg;kind:termfield;friendly:Message;help:Message");
  this.notice_subField = this.api.addField("field:zeek_notice.sub;db:zeek_notice.sub;kind:termfield;friendly:Submessage;help:Submessage");
  this.notice_srcField = this.api.addField("field:zeek_notice.src;db:zeek_notice.src;kind:termfield;friendly:Notice Source;help:Notice Source");
  this.notice_dstField = this.api.addField("field:zeek_notice.dst;db:zeek_notice.dst;kind:termfield;friendly:Notice Destination;help:Notice Destination");
  this.notice_pField = this.api.addField("field:zeek_notice.p;db:zeek_notice.p;kind:integer;friendly:Notice Port;help:Notice Port");
  this.notice_nField = this.api.addField("field:zeek_notice.n;db:zeek_notice.n;kind:integer;friendly:Notice Count or Code;help:Notice Count or Code");
  this.notice_peer_descrField = this.api.addField("field:zeek_notice.peer_descr;db:zeek_notice.peer_descr;kind:termfield;friendly:Remote Peer;help:Remote Peer");
  this.notice_actionsField = this.api.addField("field:zeek_notice.actions;db:zeek_notice.actions;kind:termfield;friendly:Action;help:Action");
  this.notice_suppress_forField = this.api.addField("field:zeek_notice.suppress_for;db:zeek_notice.suppress_for;kind:termfield;friendly:Suppress Interval;help:Suppress Interval");
  this.notice_droppedField = this.api.addField("field:zeek_notice.dropped;db:zeek_notice.dropped;kind:termfield;friendly:Dropped;help:Dropped");
  this.notice_remote_location_country_codeField = this.api.addField("field:zeek_notice.remote_location_country_code;db:zeek_notice.remote_location_country_code;kind:termfield;friendly:Notice Country Code;help:Notice Country Code");
  this.notice_remote_location_regionField = this.api.addField("field:zeek_notice.remote_location_region;db:zeek_notice.remote_location_region;kind:termfield;friendly:Notice Region;help:Notice Region");
  this.notice_remote_location_cityField = this.api.addField("field:zeek_notice.remote_location_city;db:zeek_notice.remote_location_city;kind:termfield;friendly:Notice City;help:Notice City");
  this.notice_remote_location_latitudeField = this.api.addField("field:zeek_notice.remote_location_latitude;db:zeek_notice.remote_location_latitude;kind:termfield;friendly:Notice Latitude;help:Notice Latitude");
  this.notice_remote_location_longitudeField = this.api.addField("field:zeek_notice.remote_location_longitude;db:zeek_notice.remote_location_longitude;kind:termfield;friendly:Notice Longitude;help:Notice Longitude");

  // ntlm.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ntlm/main.zeek.html#type-NTLM::Info
  this.ntlm_hostField = this.api.addField("field:zeek_ntlm.host;db:zeek_ntlm.host;kind:termfield;friendly:Client Hostname;help:Client Hostname");
  this.ntlm_domainField = this.api.addField("field:zeek_ntlm.domain;db:zeek_ntlm.domain;kind:termfield;friendly:Client Domain Name;help:Client Domain Name");
  this.ntlm_successField = this.api.addField("field:zeek_ntlm.success;db:zeek_ntlm.success;kind:termfield;friendly:Authentication Success;help:Authentication Success");
  this.ntlm_statusField = this.api.addField("field:zeek_ntlm.status;db:zeek_ntlm.status;kind:termfield;friendly:Status;help:Status");
  this.ntlm_server_nb_computerField = this.api.addField("field:zeek_ntlm.server_nb_computer;db:zeek_ntlm.server_nb_computer;kind:termfield;friendly:Server CHALLENGE NetBIOS;help:Server CHALLENGE NetBIOS");
  this.ntlm_server_dns_computerField = this.api.addField("field:zeek_ntlm.server_dns_computer;db:zeek_ntlm.server_dns_computer;kind:termfield;friendly:Server CHALLENGE DNS;help:Server CHALLENGE DNS");
  this.ntlm_server_treeField = this.api.addField("field:zeek_ntlm.server_tree;db:zeek_ntlm.server_tree;kind:termfield;friendly:Server CHALLENGE Tree;help:Server CHALLENGE Tree");

  // ntp.log
  // https://docs.zeek.org/en/latest/scripts/base/protocols/ntp/main.zeek.html#type-NTP::Info
  this.ntp_versionField = this.api.addField("field:zeek_ntp.version;db:zeek_ntp.version;kind:integer;friendly:NTP Version;help:NTP Version");
  this.ntp_modeField = this.api.addField("field:zeek_ntp.mode;db:zeek_ntp.mode;kind:termfield;friendly:NTP Mode Code;help:NTP Mode Code");
  this.ntp_mode_strField = this.api.addField("field:zeek_ntp.mode_str;db:zeek_ntp.mode_str;kind:termfield;friendly:NTP Mode;help:NTP Mode");
  this.ntp_stratumField = this.api.addField("field:zeek_ntp.stratum;db:zeek_ntp.stratum;kind:termfield;friendly:Stratum;help:Stratum");
  this.ntp_pollField = this.api.addField("field:zeek_ntp.poll;db:zeek_ntp.poll;kind:termfield;friendly:Poll Interval;help:Poll Interval");
  this.ntp_precisionField = this.api.addField("field:zeek_ntp.precision;db:zeek_ntp.precision;kind:termfield;friendly:Clock Precision;help:Clock Precision");
  this.ntp_root_delayField = this.api.addField("field:zeek_ntp.root_delay;db:zeek_ntp.root_delay;kind:termfield;friendly:Synchronizing Distance;help:Synchronizing Distance");
  this.ntp_root_dispField = this.api.addField("field:zeek_ntp.root_disp;db:zeek_ntp.root_disp;kind:termfield;friendly:Estimated Drift Rate;help:Estimated Drift Rate");
  this.ntp_ref_idField = this.api.addField("field:zeek_ntp.ref_id;db:zeek_ntp.ref_id;kind:termfield;friendly:Reference Clock Identifier;help:Reference Clock Identifier");
  this.ntp_ref_timeField = this.api.addField("field:zeek_ntp.ref_time;db:zeek_ntp.ref_time;kind:termfield;friendly:Reference Timestamp;help:Reference Timestamp");
  this.ntp_org_timeField = this.api.addField("field:zeek_ntp.org_time;db:zeek_ntp.org_time;kind:termfield;friendly:Originate Timestamp;help:Originate Timestamp");
  this.ntp_rec_timeField = this.api.addField("field:zeek_ntp.rec_time;db:zeek_ntp.rec_time;kind:termfield;friendly:Receive Timestamp;help:Receive Timestamp");
  this.ntp_xmt_timeField = this.api.addField("field:zeek_ntp.xmt_time;db:zeek_ntp.xmt_time;kind:termfield;friendly:Transmit Timestamp;help:Transmit Timestamp");
  this.ntp_num_extsField = this.api.addField("field:zeek_ntp.num_exts;db:zeek_ntp.num_exts;kind:integer;friendly:Extension Fields;help:Extension Fields");

  // pe.log
  // https://docs.zeek.org/en/stable/scripts/base/files/pe/main.zeek.html#type-PE::Info
  this.pe_machineField = this.api.addField("field:zeek_pe.machine;db:zeek_pe.machine;kind:termfield;friendly:Target Machine;help:Target Machine");
  this.pe_compile_tsField = this.api.addField("field:zeek_pe.compile_ts;db:zeek_pe.compile_ts;kind:termfield;friendly:Compile Timestamp;help:Compile Timestamp");
  this.pe_osField = this.api.addField("field:zeek_pe.os;db:zeek_pe.os;kind:termfield;friendly:Target OS;help:Target Operating System");
  this.pe_subsystemField = this.api.addField("field:zeek_pe.subsystem;db:zeek_pe.subsystem;kind:termfield;friendly:Target Subsystem;help:Target Subsystem");
  this.pe_is_exeField = this.api.addField("field:zeek_pe.is_exe;db:zeek_pe.is_exe;kind:termfield;friendly:Executable;help:Is an executable (vs. an object file)");
  this.pe_is_64bitField = this.api.addField("field:zeek_pe.is_64bit;db:zeek_pe.is_64bit;kind:termfield;friendly:64 Bit;help:Is a 64-bit object");
  this.pe_uses_aslrField = this.api.addField("field:zeek_pe.uses_aslr;db:zeek_pe.uses_aslr;kind:termfield;friendly:Uses ASLR;help:Uses Address Space Layout Randomization");
  this.pe_uses_depField = this.api.addField("field:zeek_pe.uses_dep;db:zeek_pe.uses_dep;kind:termfield;friendly:Uses DEP;help:Uses Data Execution Prevention");
  this.pe_uses_code_integrityField = this.api.addField("field:zeek_pe.uses_code_integrity;db:zeek_pe.uses_code_integrity;kind:termfield;friendly:Enforces Integrity Checks;help:Enforces Code Integrity Checks");
  this.pe_uses_sehField = this.api.addField("field:zeek_pe.uses_seh;db:zeek_pe.uses_seh;kind:termfield;friendly:Uses SEH;help:Uses Structured Exception Handling");
  this.pe_has_import_tableField = this.api.addField("field:zeek_pe.has_import_table;db:zeek_pe.has_import_table;kind:termfield;friendly:Has Import Table;help:Has Import Table");
  this.pe_has_export_tableField = this.api.addField("field:zeek_pe.has_export_table;db:zeek_pe.has_export_table;kind:termfield;friendly:Has Export Table;help:Has Export Table");
  this.pe_has_cert_tableField = this.api.addField("field:zeek_pe.has_cert_table;db:zeek_pe.has_cert_table;kind:termfield;friendly:Has Certificate Table;help:Has Attribute Certificate Table");
  this.pe_has_debug_dataField = this.api.addField("field:zeek_pe.has_debug_data;db:zeek_pe.has_debug_data;kind:termfield;friendly:Has Debug Table;help:Has Debug Table");
  this.pe_section_namesField = this.api.addField("field:zeek_pe.section_names;db:zeek_pe.section_names;kind:termfield;friendly:Sections;help:Sections");

  // profinet.log
  // https://github.com/amzn/zeek-plugin-profinet/blob/master/scripts/main.zeek
  this.profinet_operation_typeField = this.api.addField("field:zeek_profinet.operation_type;db:zeek_profinet.operation_type;kind:termfield;friendly:Operation;help:Operation");
  this.profinet_block_versionField = this.api.addField("field:zeek_profinet.block_version;db:zeek_profinet.block_version;kind:termfield;friendly:Block Version;help:Block Version");
  this.profinet_slot_numberField = this.api.addField("field:zeek_profinet.slot_number;db:zeek_profinet.slot_number;kind:integer;friendly:Slot;help:Slot");
  this.profinet_subslot_numberField = this.api.addField("field:zeek_profinet.subslot_number;db:zeek_profinet.subslot_number;kind:integer;friendly:Subslot;help:Subslot");
  this.profinet_indexField = this.api.addField("field:zeek_profinet.index;db:zeek_profinet.index;kind:termfield;friendly:Index;help:Index");

  // profinet_dce_rpc.log
  // https://github.com/amzn/zeek-plugin-profinet/blob/master/scripts/main.zeek
  this.profinet_dce_rpc_versionField = this.api.addField("field:zeek_profinet_dce_rpc.version;db:zeek_profinet_dce_rpc.version;kind:integer;friendly:Version;help:Version");
  this.profinet_dce_rpc_packet_typeField = this.api.addField("field:zeek_profinet_dce_rpc.packet_type;db:zeek_profinet_dce_rpc.packet_type;kind:termfield;friendly:Packet Type;help:Packet Type");
  this.profinet_dce_rpc_object_uuidField = this.api.addField("field:zeek_profinet_dce_rpc.object_uuid;db:zeek_profinet_dce_rpc.object_uuid;kind:termfield;friendly:Object UUID;help:Object UUID");
  this.profinet_dce_rpc_interface_uuidField = this.api.addField("field:zeek_profinet_dce_rpc.interface_uuid;db:zeek_profinet_dce_rpc.interface_uuid;kind:termfield;friendly:Interface UUID;help:Interface UUID");
  this.profinet_dce_rpc_activity_uuidField = this.api.addField("field:zeek_profinet_dce_rpc.activity_uuid;db:zeek_profinet_dce_rpc.activity_uuid;kind:termfield;friendly:Activity UUID;help:Activity UUID");
  this.profinet_dce_rpc_server_boot_timeField = this.api.addField("field:zeek_profinet_dce_rpc.server_boot_time;db:zeek_profinet_dce_rpc.server_boot_time;kind:integer;friendly:Server Boot Time;help:Server Boot Time");
  this.profinet_dce_rpc_operationField = this.api.addField("field:zeek_profinet_dce_rpc.operation;db:zeek_profinet_dce_rpc.operation;kind:termfield;friendly:Operation;help:Operation");

  // radius.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/radius/main.zeek.html#type-RADIUS::Info
  this.radius_macField = this.api.addField("field:zeek_radius.mac;db:zeek_radius.mac;kind:termfield;friendly:MAC Address;help:MAC Address");
  this.radius_framed_addrField = this.api.addField("field:zeek_radius.framed_addr;db:zeek_radius.framed_addr;kind:termfield;friendly:Framed Address;help:Framed Address");
  this.radius_tunnel_clientField = this.api.addField("field:zeek_radius.tunnel_client;db:zeek_radius.tunnel_client;kind:termfield;friendly:Initiator Address;help:Initiator Address");
  this.radius_connect_infoField = this.api.addField("field:zeek_radius.connect_info;db:zeek_radius.connect_info;kind:termfield;friendly:Connect Info;help:Connect Info");
  this.radius_reply_msgField = this.api.addField("field:zeek_radius.reply_msg;db:zeek_radius.reply_msg;kind:termfield;friendly:Reply Message;help:Reply Message");
  this.radius_resultField = this.api.addField("field:zeek_radius.result;db:zeek_radius.result;kind:termfield;friendly:Result;help:Result");
  this.radius_ttlField = this.api.addField("field:zeek_radius.ttl;db:zeek_radius.ttl;kind:termfield;friendly:TTL;help:TTL");

  // rdp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/rdp/main.zeek.html#type-RDP::Info
  this.rdp_cookieField = this.api.addField("field:zeek_rdp.cookie;db:zeek_rdp.cookie;kind:termfield;friendly:Cookie;help:Cookie");
  this.rdp_resultField = this.api.addField("field:zeek_rdp.result;db:zeek_rdp.result;kind:termfield;friendly:Connection Result;help:Connection Result");
  this.rdp_security_protocolField = this.api.addField("field:zeek_rdp.security_protocol;db:zeek_rdp.security_protocol;kind:termfield;friendly:Security Protocol;help:Security Protocol");
  this.rdp_client_channelsField = this.api.addField("field:zeek_rdp.client_channels;db:zeek_rdp.client_channels;kind:termfield;friendly:Channel;help:Channel");
  this.rdp_keyboard_layoutField = this.api.addField("field:zeek_rdp.keyboard_layout;db:zeek_rdp.keyboard_layout;kind:termfield;friendly:Keyboard Layout;help:Keyboard Layout");
  this.rdp_client_buildField = this.api.addField("field:zeek_rdp.client_build;db:zeek_rdp.client_build;kind:termfield;friendly:Client Version;help:Client Version");
  this.rdp_client_nameField = this.api.addField("field:zeek_rdp.client_name;db:zeek_rdp.client_name;kind:termfield;friendly:Client Name;help:Client Name");
  this.rdp_client_dig_product_idField = this.api.addField("field:zeek_rdp.client_dig_product_id;db:zeek_rdp.client_dig_product_id;kind:termfield;friendly:Client Product ID;help:Client Product ID");
  this.rdp_desktop_widthField = this.api.addField("field:zeek_rdp.desktop_width;db:zeek_rdp.desktop_width;kind:integer;friendly:Desktop Width;help:Desktop Width");
  this.rdp_desktop_heightField = this.api.addField("field:zeek_rdp.desktop_height;db:zeek_rdp.desktop_height;kind:integer;friendly:Desktop Height;help:Desktop Height");
  this.rdp_requested_color_depthField = this.api.addField("field:zeek_rdp.requested_color_depth;db:zeek_rdp.requested_color_depth;kind:termfield;friendly:Color Depth;help:Color Depth");
  this.rdp_cert_typeField = this.api.addField("field:zeek_rdp.cert_type;db:zeek_rdp.cert_type;kind:termfield;friendly:Certificate Type;help:Certificate Type");
  this.rdp_cert_countField = this.api.addField("field:zeek_rdp.cert_count;db:zeek_rdp.cert_count;kind:integer;friendly:Certificate Count;help:Certificate Count");
  this.rdp_cert_permanentField = this.api.addField("field:zeek_rdp.cert_permanent;db:zeek_rdp.cert_permanent;kind:termfield;friendly:Certificate is Permanent;help:Certificate is Permanent");
  this.rdp_encryption_levelField = this.api.addField("field:zeek_rdp.encryption_level;db:zeek_rdp.encryption_level;kind:termfield;friendly:Encryption Level;help:Encryption Level");
  this.rdp_encryption_methodField = this.api.addField("field:zeek_rdp.encryption_method;db:zeek_rdp.encryption_method;kind:termfield;friendly:Encryption Method;help:Encryption Method");

  // rfb.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/rfb/main.zeek.html#type-RFB::Info
  this.rfb_client_major_versionField = this.api.addField("field:zeek_rfb.client_major_version;db:zeek_rfb.client_major_version;kind:termfield;friendly:Client Major Version;help:Client Major Version");
  this.rfb_client_minor_versionField = this.api.addField("field:zeek_rfb.client_minor_version;db:zeek_rfb.client_minor_version;kind:termfield;friendly:Client Minor Version;help:Client Minor Version");
  this.rfb_server_major_versionField = this.api.addField("field:zeek_rfb.server_major_version;db:zeek_rfb.server_major_version;kind:termfield;friendly:Server Major Version;help:Server Major Version");
  this.rfb_server_minor_versionField = this.api.addField("field:zeek_rfb.server_minor_version;db:zeek_rfb.server_minor_version;kind:termfield;friendly:Server Minor Version;help:Server Minor Version");
  this.rfb_authentication_methodField = this.api.addField("field:zeek_rfb.authentication_method;db:zeek_rfb.authentication_method;kind:termfield;friendly:Authentication Method;help:Authentication Method");
  this.rfb_authField = this.api.addField("field:zeek_rfb.auth;db:zeek_rfb.auth;kind:termfield;friendly:Authentication Success;help:Authentication Success");
  this.rfb_share_flagField = this.api.addField("field:zeek_rfb.share_flag;db:zeek_rfb.share_flag;kind:termfield;friendly:Shared Session;help:Shared Session");
  this.rfb_desktop_nameField = this.api.addField("field:zeek_rfb.desktop_name;db:zeek_rfb.desktop_name;kind:termfield;friendly:Desktop Name;help:Desktop Name");
  this.rfb_widthField = this.api.addField("field:zeek_rfb.width;db:zeek_rfb.width;kind:integer;friendly:Desktop Width;help:Desktop Width");
  this.rfb_heightField = this.api.addField("field:zeek_rfb.height;db:zeek_rfb.height;kind:integer;friendly:Desktop Height;help:Desktop Height");

  // s7comm.log
  // https://github.com/amzn/zeek-plugin-s7comm/blob/master/scripts/main.zeek
  this.s7comm_rosctrField = this.api.addField("field:zeek_s7comm.rosctr;db:zeek_s7comm.rosctr;kind:termfield;friendly:Message Type;help:Message Type");
  this.s7comm_parameterField = this.api.addField("field:zeek_s7comm.parameter;db:zeek_s7comm.parameter;kind:termfield;friendly:Parameters;help:Parameters");
  this.s7comm_parameters_classField = this.api.addField("field:zeek_s7comm.parameters.class;db:zeek_s7comm.parameters.class;kind:termfield;friendly:Class;help:Class");
  this.s7comm_parameters_codeField = this.api.addField("field:zeek_s7comm.parameters.code;db:zeek_s7comm.parameters.code;kind:termfield;friendly:Code;help:Code");
  this.s7comm_parameters_groupField = this.api.addField("field:zeek_s7comm.parameters.group;db:zeek_s7comm.parameters.group;kind:termfield;friendly:Group;help:Group");
  this.s7comm_parameters_modeField = this.api.addField("field:zeek_s7comm.parameters.mode;db:zeek_s7comm.parameters.mode;kind:termfield;friendly:Mode;help:Mode");
  this.s7comm_parameters_subField = this.api.addField("field:zeek_s7comm.parameters.sub;db:zeek_s7comm.parameters.sub;kind:termfield;friendly:Sub;help:Sub");
  this.s7comm_parameters_typeField = this.api.addField("field:zeek_s7comm.parameters.type;db:zeek_s7comm.parameters.type;kind:termfield;friendly:Type;help:Type");
  this.s7comm_item_countField = this.api.addField("field:zeek_s7comm.item_count;db:zeek_s7comm.item_count;kind:integer;friendly:Data Entries;help:Total number of data entries");
  this.s7comm_data_infoField = this.api.addField("field:zeek_s7comm.data_info;db:zeek_s7comm.data_info;kind:termfield;friendly:Data Entry;help:Data of first entry");

  // signatures.log
  this.signatures_noteField = this.api.addField("field:zeek_signatures.note;db:zeek_signatures.note;kind:termfield;friendly:Note;help:Note");
  this.signatures_signature_idField = this.api.addField("field:zeek_signatures.signature_id;db:zeek_signatures.signature_id;kind:termfield;friendly:Signature ID;help:Signature ID");
  this.signatures_event_messageField = this.api.addField("field:zeek_signatures.event_message;db:zeek_signatures.event_message;kind:termfield;friendly:Message;help:Message");
  this.signatures_sub_messageField = this.api.addField("field:zeek_signatures.sub_message;db:zeek_signatures.sub_message;kind:termfield;friendly:Submessage;help:Submessage");
  this.signatures_signature_countField = this.api.addField("field:zeek_signatures.signature_count;db:zeek_signatures.signature_count;kind:integer;friendly:Signatures Matched;help:Signatures Matched");
  this.signatures_host_countField = this.api.addField("field:zeek_signatures.host_count;db:zeek_signatures.host_count;kind:integer;friendly:Host or Engine Count;help:Host or Engine Count");
  this.signatures_engineField = this.api.addField("field:zeek_signatures.engine;db:zeek_signatures.engine;kind:termfield;friendly:Scan Engines;help:Scan Engines");
  this.signatures_hitsField = this.api.addField("field:zeek_signatures.hits;db:zeek_signatures.hits;kind:termfield;friendly:Hits;help:Hits");

  // sip.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/sip/main.zeek.html#type-SIP::Info
  this.sip_trans_depthField = this.api.addField("field:zeek_sip.trans_depth;db:zeek_sip.trans_depth;kind:integer;friendly:Pipeline Depth;help:Pipeline Depth");
  this.sip_methodField = this.api.addField("field:zeek_sip.method;db:zeek_sip.method;kind:termfield;friendly:Request Method;help:Request Method");
  this.sip_uriField = this.api.addField("field:zeek_sip.uri;db:zeek_sip.uri;kind:termfield;friendly:URI;help:URI");
  this.sip_dateField = this.api.addField("field:zeek_sip.date;db:zeek_sip.date;kind:termfield;friendly:Request Date Header;help:Request Date Header");
  this.sip_request_fromField = this.api.addField("field:zeek_sip.request_from;db:zeek_sip.request_from;kind:termfield;friendly:Request From Header;help:Request From Header");
  this.sip_request_toField = this.api.addField("field:zeek_sip.request_to;db:zeek_sip.request_to;kind:termfield;friendly:Request To Header;help:Request To Header");
  this.sip_response_fromField = this.api.addField("field:zeek_sip.response_from;db:zeek_sip.response_from;kind:termfield;friendly:Response From Header;help:Response From Header");
  this.sip_response_toField = this.api.addField("field:zeek_sip.response_to;db:zeek_sip.response_to;kind:termfield;friendly:Response To Header;help:Response To Header");
  this.sip_reply_toField = this.api.addField("field:zeek_sip.reply_to;db:zeek_sip.reply_to;kind:termfield;friendly:Reply-To Header;help:Reply-To Header");
  this.sip_call_idField = this.api.addField("field:zeek_sip.call_id;db:zeek_sip.call_id;kind:termfield;friendly:Client Call-ID Header;help:Client Call-ID Header");
  this.sip_seqField = this.api.addField("field:zeek_sip.seq;db:zeek_sip.seq;kind:termfield;friendly:Client CSeq Header;help:Client CSeq Header");
  this.sip_subjectField = this.api.addField("field:zeek_sip.subject;db:zeek_sip.subject;kind:termfield;friendly:Client Subject Header;help:Client Subject Header");
  this.sip_request_pathField = this.api.addField("field:zeek_sip.request_path;db:zeek_sip.request_path;kind:termfield;friendly:Request Path;help:Request Path");
  this.sip_response_pathField = this.api.addField("field:zeek_sip.response_path;db:zeek_sip.response_path;kind:termfield;friendly:Response Path;help:Response Path");
  this.sip_user_agentField = this.api.addField("field:zeek_sip.user_agent;db:zeek_sip.user_agent;kind:termfield;friendly:User Agent;help:User Agent");
  this.sip_status_codeField = this.api.addField("field:zeek_sip.status_code;db:zeek_sip.status_code;kind:termfield;friendly:Status Code;help:Status Code");
  this.sip_status_msgField = this.api.addField("field:zeek_sip.status_msg;db:zeek_sip.status_msg;kind:termfield;friendly:Status Message;help:Status Message");
  this.sip_warningField = this.api.addField("field:zeek_sip.warning;db:zeek_sip.warning;kind:termfield;friendly:Warning Header;help:Warning Header");
  this.sip_request_body_lenField = this.api.addField("field:zeek_sip.request_body_len;db:zeek_sip.request_body_len;kind:integer;friendly:Request Body Length;help:Request Body Length");
  this.sip_response_body_lenField = this.api.addField("field:zeek_sip.response_body_len;db:zeek_sip.response_body_len;kind:integer;friendly:Response Body Length;help:Response Body Length");
  this.sip_content_typeField = this.api.addField("field:zeek_sip.content_type;db:zeek_sip.content_type;kind:termfield;friendly:Content Type Header;help:Content Type Header");
  this.sip_versionField = this.api.addField("field:zeek_sip.version;db:zeek_sip.version;kind:termfield;friendly:Version;help:Version");

  // smb_cmd.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::CmdInfo
  this.smb_cmd_commandField = this.api.addField("field:zeek_smb_cmd.command;db:zeek_smb_cmd.command;kind:termfield;friendly:Command;help:Command");
  this.smb_cmd_sub_commandField = this.api.addField("field:zeek_smb_cmd.sub_command;db:zeek_smb_cmd.sub_command;kind:termfield;friendly:Subcommand;help:Subcommand");
  this.smb_cmd_argumentField = this.api.addField("field:zeek_smb_cmd.argument;db:zeek_smb_cmd.argument;kind:termfield;friendly:Argument;help:Argument");
  this.smb_cmd_statusField = this.api.addField("field:zeek_smb_cmd.status;db:zeek_smb_cmd.status;kind:termfield;friendly:Status;help:Status");
  this.smb_cmd_rttField = this.api.addField("field:zeek_smb_cmd.rtt;db:zeek_smb_cmd.rtt;kind:termfield;friendly:Round Trip Time;help:Round Trip Time");
  this.smb_cmd_versionField = this.api.addField("field:zeek_smb_cmd.version;db:zeek_smb_cmd.version;kind:termfield;friendly:Version;help:Version");
  this.smb_cmd_treeField = this.api.addField("field:zeek_smb_cmd.tree;db:zeek_smb_cmd.tree;kind:termfield;friendly:Tree;help:Tree");
  this.smb_cmd_tree_serviceField = this.api.addField("field:zeek_smb_cmd.tree_service;db:zeek_smb_cmd.tree_service;kind:termfield;friendly:Tree Service;help:Tree Service");

  // smb_files.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::FileInfo
  this.smb_files_actionField = this.api.addField("field:zeek_smb_files.action;db:zeek_smb_files.action;kind:termfield;friendly:Action;help:Action");
  this.smb_files_pathField = this.api.addField("field:zeek_smb_files.path;db:zeek_smb_files.path;kind:termfield;friendly:File Path;help:File Path");
  this.smb_files_nameField = this.api.addField("field:zeek_smb_files.name;db:zeek_smb_files.name;kind:termfield;friendly:File Name;help:File Name");
  this.smb_files_sizeField = this.api.addField("field:zeek_smb_files.size;db:zeek_smb_files.size;kind:integer;friendly:File Size;help:File Size");
  this.smb_files_prev_nameField = this.api.addField("field:zeek_smb_files.prev_name;db:zeek_smb_files.prev_name;kind:termfield;friendly:Previous File Name;help:Previous File Name");
  this.smb_files_times_modifiedField = this.api.addField("field:zeek_smb_files.times_modified;db:zeek_smb_files.times_modified;kind:termfield;friendly:Write Time;help:Write Time");
  this.smb_files_times_accessedField = this.api.addField("field:zeek_smb_files.times_accessed;db:zeek_smb_files.times_accessed;kind:termfield;friendly:Access Time;help:Access Time");
  this.smb_files_times_createdField = this.api.addField("field:zeek_smb_files.times_created;db:zeek_smb_files.times_created;kind:termfield;friendly:Creation Time;help:Creation Time");
  this.smb_files_times_changedField = this.api.addField("field:zeek_smb_files.times_changed;db:zeek_smb_files.times_changed;kind:termfield;friendly:Modified Time;help:Modified Time");
  this.smb_files_data_offset_reqField = this.api.addField("field:zeek_smb_files.data_offset_req;db:zeek_smb_files.data_offset_req;kind:integer;friendly:Data Offset Requested;help:Data Offset Requested");
  this.smb_files_data_len_reqField = this.api.addField("field:zeek_smb_files.data_len_req;db:zeek_smb_files.data_len_req;kind:integer;friendly:Data Length Requested;help:Data Length Requested");
  this.smb_files_data_len_rspField = this.api.addField("field:zeek_smb_files.data_len_rsp;db:zeek_smb_files.data_len_rsp;kind:integer;friendly:Data Length In Response;help:Data Length In Response");

  // smb_mapping.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smb/main.zeek.html#type-SMB::TreeInfo
  this.smb_mapping_pathField = this.api.addField("field:zeek_smb_mapping.path;db:zeek_smb_mapping.path;kind:termfield;friendly:Tree Path;help:Tree Path");
  this.smb_mapping_resource_typeField = this.api.addField("field:zeek_smb_mapping.resource_type;db:zeek_smb_mapping.resource_type;kind:termfield;friendly:Resource Type;help:Resource Type");
  this.smb_mapping_native_file_systemField = this.api.addField("field:zeek_smb_mapping.native_file_system;db:zeek_smb_mapping.native_file_system;kind:termfield;friendly:File System;help:File System");
  this.smb_mapping_share_typeField = this.api.addField("field:zeek_smb_mapping.share_type;db:zeek_smb_mapping.share_type;kind:termfield;friendly:Share Type;help:Share Type");

  // smtp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/smtp/main.zeek.html#type-SMTP::Info
  this.smtp_trans_depthField = this.api.addField("field:zeek_smtp.trans_depth;db:zeek_smtp.trans_depth;kind:integer;friendly:Transaction Depth;help:Transaction Depth");
  this.smtp_heloField = this.api.addField("field:zeek_smtp.helo;db:zeek_smtp.helo;kind:termfield;friendly:HELO;help:HELO");
  this.smtp_mailfromField = this.api.addField("field:zeek_smtp.mailfrom;db:zeek_smtp.mailfrom;kind:termfield;friendly:FROM Addresses;help:FROM Addresses");
  this.smtp_rcpttoField = this.api.addField("field:zeek_smtp.rcptto;db:zeek_smtp.rcptto;kind:termfield;friendly:RCPT TO;help:RCPT TO");
  this.smtp_dateField = this.api.addField("field:zeek_smtp.date;db:zeek_smtp.date;kind:termfield;friendly:Date;help:Date");
  this.smtp_fromField = this.api.addField("field:zeek_smtp.from;db:zeek_smtp.from;kind:termfield;friendly:FROM;help:FROM");
  this.smtp_toField = this.api.addField("field:zeek_smtp.to;db:zeek_smtp.to;kind:termfield;friendly:TO;help:TO");
  this.smtp_ccField = this.api.addField("field:zeek_smtp.cc;db:zeek_smtp.cc;kind:termfield;friendly:CC;help:CC");
  this.smtp_reply_toField = this.api.addField("field:zeek_smtp.reply_to;db:zeek_smtp.reply_to;kind:termfield;friendly:Reply-To;help:Reply-To");
  this.smtp_msg_idField = this.api.addField("field:zeek_smtp.msg_id;db:zeek_smtp.msg_id;kind:termfield;friendly:MsgId;help:MsgId");
  this.smtp_in_reply_toField = this.api.addField("field:zeek_smtp.in_reply_to;db:zeek_smtp.in_reply_to;kind:termfield;friendly:In-Reply-To;help:In-Reply-To");
  this.smtp_subjectField = this.api.addField("field:zeek_smtp.subject;db:zeek_smtp.subject;kind:termfield;friendly:Subject;help:Subject");
  this.smtp_x_originating_ipField = this.api.addField("field:zeek_smtp.x_originating_ip;db:zeek_smtp.x_originating_ip;kind:termfield;friendly:X-Originating-IP;help:X-Originating-IP");
  this.smtp_first_receivedField = this.api.addField("field:zeek_smtp.first_received;db:zeek_smtp.first_received;kind:termfield;friendly:First Received;help:First Received");
  this.smtp_second_receivedField = this.api.addField("field:zeek_smtp.second_received;db:zeek_smtp.second_received;kind:termfield;friendly:Second Received;help:Second Received");
  this.smtp_last_replyField = this.api.addField("field:zeek_smtp.last_reply;db:zeek_smtp.last_reply;kind:termfield;friendly:Last Reply;help:Last Reply");
  this.smtp_last_reply_codeField = this.api.addField("field:zeek_smtp.last_reply_code;db:zeek_smtp.last_reply_code;kind:termfield;friendly:Last Reply Code;help:Last Reply Code");
  this.smtp_last_reply_msgField = this.api.addField("field:zeek_smtp.last_reply_msg;db:zeek_smtp.last_reply_msg;kind:termfield;friendly:Last Reply Message;help:Last Reply Message");
  this.smtp_pathField = this.api.addField("field:zeek_smtp.path;db:zeek_smtp.path;kind:termfield;friendly:Tranmission Path;help:Tranmission Path");
  this.smtp_user_agentField = this.api.addField("field:zeek_smtp.user_agent;db:zeek_smtp.user_agent;kind:termfield;friendly:User Agent;help:User Agent");
  this.smtp_tlsField = this.api.addField("field:zeek_smtp.tls;db:zeek_smtp.tls;kind:termfield;friendly:TLS;help:TLS");
  this.smtp_is_webmailField = this.api.addField("field:zeek_smtp.is_webmail;db:zeek_smtp.is_webmail;kind:termfield;friendly:Is Webmail;help:Is Webmail");

  // snmp.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/snmp/main.zeek.html#type-SNMP::Info
  this.snmp_durationField = this.api.addField("field:zeek_snmp.duration;db:zeek_snmp.duration;kind:termfield;friendly:Duration;help:Duration");
  this.snmp_versionField = this.api.addField("field:zeek_snmp.version;db:zeek_snmp.version;kind:termfield;friendly:Version;help:Version");
  this.snmp_communityField = this.api.addField("field:zeek_snmp.community;db:zeek_snmp.community;kind:termfield;friendly:Community;help:Community");
  this.snmp_get_requestsField = this.api.addField("field:zeek_snmp.get_requests;db:zeek_snmp.get_requests;kind:integer;friendly:Get Requests;help:Get Requests");
  this.snmp_get_bulk_requestsField = this.api.addField("field:zeek_snmp.get_bulk_requests;db:zeek_snmp.get_bulk_requests;kind:integer;friendly:Get Bulk Requests;help:Get Bulk Requests");
  this.snmp_get_responsesField = this.api.addField("field:zeek_snmp.get_responses;db:zeek_snmp.get_responses;kind:integer;friendly:Get Responses;help:Get Responses");
  this.snmp_set_requestsField = this.api.addField("field:zeek_snmp.set_requests;db:zeek_snmp.set_requests;kind:integer;friendly:Set Requests;help:Set Requests");
  this.snmp_display_stringField = this.api.addField("field:zeek_snmp.display_string;db:zeek_snmp.display_string;kind:termfield;friendly:Display String;help:Display String");
  this.snmp_up_sinceField = this.api.addField("field:zeek_snmp.up_since;db:zeek_snmp.up_since;kind:termfield;friendly:Up Since Timestamp;help:Up Since Timestamp");

  // socks.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/socks/main.zeek.html#type-SOCKS::Info
  this.socks_versionField = this.api.addField("field:zeek_socks.version;db:zeek_socks.version;kind:integer;friendly:Version;help:Version");
  this.socks_server_statusField = this.api.addField("field:zeek_socks.server_status;db:zeek_socks.server_status;kind:termfield;friendly:Server Status;help:Server Status");
  this.socks_request_hostField = this.api.addField("field:zeek_socks.request_host;db:zeek_socks.request_host;kind:termfield;friendly:Client Address;help:Client Address");
  this.socks_request_nameField = this.api.addField("field:zeek_socks.request_name;db:zeek_socks.request_name;kind:termfield;friendly:Client Name;help:Client Name");
  this.socks_request_portField = this.api.addField("field:zeek_socks.request_port;db:zeek_socks.request_port;kind:integer;friendly:Client Port;help:Client Port");
  this.socks_bound_hostField = this.api.addField("field:zeek_socks.bound_host;db:zeek_socks.bound_host;kind:termfield;friendly:Server Address;help:Server Address");
  this.socks_bound_nameField = this.api.addField("field:zeek_socks.bound_name;db:zeek_socks.bound_name;kind:termfield;friendly:Server Name;help:Server Name");
  this.socks_bound_portField = this.api.addField("field:zeek_socks.bound_port;db:zeek_socks.bound_port;kind:integer;friendly:Server Port;help:Server Port");

  // software.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/software/main.zeek.html#type-Software::Info
  this.software_software_typeField = this.api.addField("field:zeek_software.software_type;db:zeek_software.software_type;kind:termfield;friendly:Software Type;help:Software Type");
  this.software_nameField = this.api.addField("field:zeek_software.name;db:zeek_software.name;kind:termfield;friendly:Software Name;help:Software Name");
  this.software_version_majorField = this.api.addField("field:zeek_software.version_major;db:zeek_software.version_major;kind:integer;friendly:Major Version;help:Major Version");
  this.software_version_minorField = this.api.addField("field:zeek_software.version_minor;db:zeek_software.version_minor;kind:integer;friendly:Minor Version;help:Minor Version");
  this.software_version_minor2Field = this.api.addField("field:zeek_software.version_minor2;db:zeek_software.version_minor2;kind:integer;friendly:Minor Subversion;help:Minor Subversion");
  this.software_version_minor3Field = this.api.addField("field:zeek_software.version_minor3;db:zeek_software.version_minor3;kind:integer;friendly:Minor Patch;help:Minor Patch");
  this.software_version_addlField = this.api.addField("field:zeek_software.version_addl;db:zeek_software.version_addl;kind:termfield;friendly:Additional Version;help:Additional Version");
  this.software_unparsed_versionField = this.api.addField("field:zeek_software.unparsed_version;db:zeek_software.unparsed_version;kind:termfield;friendly:Version;help:Version");

  // spicy-noise.log (renamed to "noise" in Logstash)
  // https://github.com/theparanoids/spicy-noise/blob/master/zeek/spicy-noise.zeek
  this.noise_msg_typeField = this.api.addField("field:zeek_noise.msg_type;db:zeek_noise.msg_type;kind:termfield;friendly:Message Type;help:Message Type");
  this.noise_senderField = this.api.addField("field:zeek_noise.sender;db:zeek_noise.sender;kind:termfield;friendly:Sender;help:Sender");
  this.noise_receiverField = this.api.addField("field:zeek_noise.receiver;db:zeek_noise.receiver;kind:termfield;friendly:Receiver;help:Receiver");
  this.noise_unenc_ephemeralField = this.api.addField("field:zeek_noise.unenc_ephemeral;db:zeek_noise.unenc_ephemeral;kind:termfield;friendly:Unencrypted Ephermeral;help:Unencrypted Ephermeral");
  this.noise_enc_staticField = this.api.addField("field:zeek_noise.enc_static;db:zeek_noise.enc_static;kind:termfield;friendly:Encrypted Static;help:Encrypted Static");
  this.noise_enc_timestampField = this.api.addField("field:zeek_noise.enc_timestamp;db:zeek_noise.enc_timestamp;kind:termfield;friendly:Encrypted Timestamp;help:Encrypted Timestamp");
  this.noise_enc_nothingField = this.api.addField("field:zeek_noise.enc_nothing;db:zeek_noise.enc_nothing;kind:termfield;friendly:Encrypted Nothing;help:Encrypted Nothing");
  this.noise_nonceField = this.api.addField("field:zeek_noise.nonce;db:zeek_noise.nonce;kind:termfield;friendly:Nonce;help:Nonce");
  this.noise_enc_cookieField = this.api.addField("field:zeek_noise.enc_cookie;db:zeek_noise.enc_cookie;kind:termfield;friendly:Encrypted Cookie;help:Encrypted Cookie");
  this.noise_mac1Field = this.api.addField("field:zeek_noise.mac1;db:zeek_noise.mac1;kind:termfield;friendly:MAC1;help:MAC1");
  this.noise_mac2Field = this.api.addField("field:zeek_noise.mac2;db:zeek_noise.mac2;kind:termfield;friendly:MAC2;help:MAC2");
  this.noise_enc_payload_lenField = this.api.addField("field:zeek_noise.enc_payload_len;db:zeek_noise.enc_payload_len;kind:integer;friendly:Encrypted Payload Length;help:Encrypted Payload Length");
  this.noise_enc_payloadField = this.api.addField("field:zeek_noise.enc_payload;db:zeek_noise.enc_payload;kind:termfield;friendly:Encrypted Payload;help:Encrypted Payload");

  // ssh.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ssh/main.zeek.html#type-SSH::Info
  this.ssh_versionField = this.api.addField("field:zeek_ssh.version;db:zeek_ssh.version;kind:integer;friendly:Version;help:Version");
  this.ssh_auth_successField = this.api.addField("field:zeek_ssh.auth_success;db:zeek_ssh.auth_success;kind:termfield;friendly:Authentication Success;help:Authentication Success");
  this.ssh_auth_attemptsField = this.api.addField("field:zeek_ssh.auth_attempts;db:zeek_ssh.auth_attempts;kind:integer;friendly:Authentication Attempts;help:Authentication Attempts");
  this.ssh_directionField = this.api.addField("field:zeek_ssh.direction;db:zeek_ssh.direction;kind:termfield;friendly:Connection Direction;help:Connection Direction");
  this.ssh_clientField = this.api.addField("field:zeek_ssh.client;db:zeek_ssh.client;kind:termfield;friendly:Client Version;help:Client Version");
  this.ssh_serverField = this.api.addField("field:zeek_ssh.server;db:zeek_ssh.server;kind:termfield;friendly:Server Version;help:Server Version");
  this.ssh_cipher_algField = this.api.addField("field:zeek_ssh.cipher_alg;db:zeek_ssh.cipher_alg;kind:termfield;friendly:Cipher;help:Cipher Algorithm");
  this.ssh_mac_algField = this.api.addField("field:zeek_ssh.mac_alg;db:zeek_ssh.mac_alg;kind:termfield;friendly:Signing Algorithm;help:Signing Algorithm");
  this.ssh_compression_algField = this.api.addField("field:zeek_ssh.compression_alg;db:zeek_ssh.compression_alg;kind:termfield;friendly:Compression Algorithm;help:Compression Algorithm");
  this.ssh_kex_algField = this.api.addField("field:zeek_ssh.kex_alg;db:zeek_ssh.kex_alg;kind:termfield;friendly:Key Exchange Algorithm;help:Key Exchange Algorithm");
  this.ssh_host_key_algField = this.api.addField("field:zeek_ssh.host_key_alg;db:zeek_ssh.host_key_alg;kind:termfield;friendly:Server Host Key Algorithm;help:Server Host Key Algorithm");
  this.ssh_host_keyField = this.api.addField("field:zeek_ssh.host_key;db:zeek_ssh.host_key;kind:termfield;friendly:Server Key Fingerprint;help:Server Key Fingerprint");
  this.ssh_remote_location_country_codeField = this.api.addField("field:zeek_ssh.remote_location_country_code;db:zeek_ssh.remote_location_country_code;kind:termfield;friendly:SSH Remote Country Code;help:SSH Remote Country Code");
  this.ssh_remote_location_regionField = this.api.addField("field:zeek_ssh.remote_location_region;db:zeek_ssh.remote_location_region;kind:termfield;friendly:SSH Remote Region;help:SSH Remote Region");
  this.ssh_remote_location_cityField = this.api.addField("field:zeek_ssh.remote_location_city;db:zeek_ssh.remote_location_city;kind:termfield;friendly:SSH Remote City;help:SSH Remote City");
  this.ssh_remote_location_latitudeField = this.api.addField("field:zeek_ssh.remote_location_latitude;db:zeek_ssh.remote_location_latitude;kind:termfield;friendly:SSH Remote Latitude;help:SSH Remote Latitude");
  this.ssh_remote_location_longitudeField = this.api.addField("field:zeek_ssh.remote_location_longitude;db:zeek_ssh.remote_location_longitude;kind:termfield;friendly:SSH Remote Longitude;help:SSH Remote Longitude");
  this.ssh_hasshVersionField = this.api.addField("field:zeek_ssh.hasshVersion;db:zeek_ssh.hasshVersion;kind:termfield;friendly:HASSH Version;help:HASSH Version");
  this.ssh_hasshField = this.api.addField("field:zeek_ssh.hassh;db:zeek_ssh.hassh;kind:termfield;friendly:HASSH Client Fingerprint;help:HASSH Client Fingerprint");
  this.ssh_hasshServerField = this.api.addField("field:zeek_ssh.hasshServer;db:zeek_ssh.hasshServer;kind:termfield;friendly:HASSH Server Fingerprint;help:HASSH Server Fingerprint");
  this.ssh_hasshAlgorithmsField = this.api.addField("field:zeek_ssh.hasshAlgorithms;db:zeek_ssh.hasshAlgorithms;kind:termfield;friendly:HASSH Client Algorithms;help:HASSH Client Algorithms");
  this.ssh_hasshServerAlgorithmsField = this.api.addField("field:zeek_ssh.hasshServerAlgorithms;db:zeek_ssh.hasshServerAlgorithms;kind:termfield;friendly:HASSH Server Algorithms;help:HASSH Server Algorithms");
  this.ssh_cshkaField = this.api.addField("field:zeek_ssh.cshka;db:zeek_ssh.cshka;kind:termfield;friendly:HASSH Client Host Key Algorithms;help:HASSH Client Host Key Algorithms");
  this.ssh_sshkaField = this.api.addField("field:zeek_ssh.sshka;db:zeek_ssh.sshka;kind:termfield;friendly:HASSH Server Host Key Algorithms;help:HASSH Server Host Key Algorithms");

  // ssl.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/ssl/main.zeek.html#type-SSL::Info
  this.ssl_ssl_versionField = this.api.addField("field:zeek_ssl.ssl_version;db:zeek_ssl.ssl_version;kind:termfield;friendly:Version;help:Version");
  this.ssl_cipherField = this.api.addField("field:zeek_ssl.cipher;db:zeek_ssl.cipher;kind:termfield;friendly:Cipher;help:Cipher");
  this.ssl_curveField = this.api.addField("field:zeek_ssl.curve;db:zeek_ssl.curve;kind:termfield;friendly:Elliptic Curve;help:Elliptic Curve");
  this.ssl_server_nameField = this.api.addField("field:zeek_ssl.server_name;db:zeek_ssl.server_name;kind:termfield;friendly:Server Name;help:Server Name");
  this.ssl_resumedField = this.api.addField("field:zeek_ssl.resumed;db:zeek_ssl.resumed;kind:termfield;friendly:Resumed;help:Resumed");
  this.ssl_last_alertField = this.api.addField("field:zeek_ssl.last_alert;db:zeek_ssl.last_alert;kind:termfield;friendly:Last Alert;help:Last Alert");
  this.ssl_next_protocolField = this.api.addField("field:zeek_ssl.next_protocol;db:zeek_ssl.next_protocol;kind:termfield;friendly:Next Protocol;help:Next Protocol");
  this.ssl_establishedField = this.api.addField("field:zeek_ssl.established;db:zeek_ssl.established;kind:termfield;friendly:Established;help:Established");
  this.ssl_cert_chain_fuidsField = this.api.addField("field:zeek_ssl.cert_chain_fuids;db:zeek_ssl.cert_chain_fuids;kind:termfield;friendly:Certificate Chain File ID;help:Certificate Chain File ID");
  this.ssl_client_cert_chain_fuidsField = this.api.addField("field:zeek_ssl.client_cert_chain_fuids;db:zeek_ssl.client_cert_chain_fuids;kind:termfield;friendly:Client Certificate File ID;help:Client Certificate File ID");
  this.ssl_issuer_fullField = this.api.addField("field:zeek_ssl.issuer_full;db:zeek_ssl.issuer_full;kind:termfield;friendly:Issuer;help:Issuer");
  this.ssl_subject_CField = this.api.addField("field:zeek_ssl.subject.C;db:zeek_ssl.subject.C;kind:termfield;friendly:Subject Country;help:Subject Country");
  this.ssl_subject_CNField = this.api.addField("field:zeek_ssl.subject.CN;db:zeek_ssl.subject.CN;kind:termfield;friendly:Subject Common Name;help:Subject Common Name");
  this.ssl_subject_descriptionField = this.api.addField("field:zeek_ssl.subject.description;db:zeek_ssl.subject.description;kind:termfield;friendly:Subject Description;help:Subject Description");
  this.ssl_subject_emailAddressField = this.api.addField("field:zeek_ssl.subject.emailAddress;db:zeek_ssl.subject.emailAddress;kind:termfield;friendly:Subject Email Address;help:Subject Email Address");
  this.ssl_subject_fullField = this.api.addField("field:zeek_ssl.subject_full;db:zeek_ssl.subject_full;kind:termfield;friendly:Subject;help:Subject");
  this.ssl_subject_GNField = this.api.addField("field:zeek_ssl.subject.GN;db:zeek_ssl.subject.GN;kind:termfield;friendly:Subject Given Name;help:Subject Given Name");
  this.ssl_subject_initialsField = this.api.addField("field:zeek_ssl.subject.initials;db:zeek_ssl.subject.initials;kind:termfield;friendly:Subject Initials;help:Subject Initials");
  this.ssl_subject_LField = this.api.addField("field:zeek_ssl.subject.L;db:zeek_ssl.subject.L;kind:termfield;friendly:Subject Locality;help:Subject Locality");
  this.ssl_subject_OField = this.api.addField("field:zeek_ssl.subject.O;db:zeek_ssl.subject.O;kind:termfield;friendly:Subject Organization;help:Subject Organization");
  this.ssl_subject_OUField = this.api.addField("field:zeek_ssl.subject.OU;db:zeek_ssl.subject.OU;kind:termfield;friendly:Subject Organization Unit;help:Subject Organization Unit");
  this.ssl_subject_postalCodeField = this.api.addField("field:zeek_ssl.subject.postalCode;db:zeek_ssl.subject.postalCode;kind:termfield;friendly:Subject Postal Code;help:Subject Postal Code");
  this.ssl_subject_pseudonymField = this.api.addField("field:zeek_ssl.subject.pseudonym;db:zeek_ssl.subject.pseudonym;kind:termfield;friendly:Subject Pseudonym;help:Subject Pseudonym");
  this.ssl_subject_serialNumberField = this.api.addField("field:zeek_ssl.subject.serialNumber;db:zeek_ssl.subject.serialNumber;kind:termfield;friendly:Subject Serial Number;help:Subject Serial Number");
  this.ssl_subject_SNField = this.api.addField("field:zeek_ssl.subject.SN;db:zeek_ssl.subject.SN;kind:termfield;friendly:Subject Surname;help:Subject Surname");
  this.ssl_subject_STField = this.api.addField("field:zeek_ssl.subject.ST;db:zeek_ssl.subject.ST;kind:termfield;friendly:Subject State;help:Subject State");
  this.ssl_subject_streetField = this.api.addField("field:zeek_ssl.subject.street;db:zeek_ssl.subject.street;kind:termfield;friendly:Subject Street;help:Subject Street");
  this.ssl_subject_titleField = this.api.addField("field:zeek_ssl.subject.title;db:zeek_ssl.subject.title;kind:termfield;friendly:Subject Title;help:Subject Title");
  this.ssl_issuer_CNField = this.api.addField("field:zeek_ssl.issuer.CN;db:zeek_ssl.issuer.CN;kind:termfield;friendly:Issuer Common Name;help:Issuer Common Name");
  this.ssl_issuer_CField = this.api.addField("field:zeek_ssl.issuer.C;db:zeek_ssl.issuer.C;kind:termfield;friendly:Issuer Country;help:Issuer Country");
  this.ssl_issuer_OField = this.api.addField("field:zeek_ssl.issuer.O;db:zeek_ssl.issuer.O;kind:termfield;friendly:Issuer Organization;help:Issuer Organization");
  this.ssl_issuer_OUField = this.api.addField("field:zeek_ssl.issuer.OU;db:zeek_ssl.issuer.OU;kind:termfield;friendly:Issuer Organization Unit;help:Issuer Organization Unit");
  this.ssl_issuer_STField = this.api.addField("field:zeek_ssl.issuer.ST;db:zeek_ssl.issuer.ST;kind:termfield;friendly:Issuer State;help:Issuer State");
  this.ssl_issuer_SNField = this.api.addField("field:zeek_ssl.issuer.SN;db:zeek_ssl.issuer.SN;kind:termfield;friendly:Issuer Surname;help:Issuer Surname");
  this.ssl_issuer_LField = this.api.addField("field:zeek_ssl.issuer.L;db:zeek_ssl.issuer.L;kind:termfield;friendly:Issuer Locality;help:Issuer Locality");
  this.ssl_issuer_DCField = this.api.addField("field:zeek_ssl.issuer.DC;db:zeek_ssl.issuer.DC;kind:termfield;friendly:Issuer Distinguished Name;help:Issuer Distinguished Name");
  this.ssl_issuer_GNField = this.api.addField("field:zeek_ssl.issuer.GN;db:zeek_ssl.issuer.GN;kind:termfield;friendly:Issuer Given Name;help:Issuer Given Name");
  this.ssl_issuer_pseudonymField = this.api.addField("field:zeek_ssl.issuer.pseudonym;db:zeek_ssl.issuer.pseudonym;kind:termfield;friendly:Issuer Pseudonym;help:Issuer Pseudonym");
  this.ssl_issuer_serialNumberField = this.api.addField("field:zeek_ssl.issuer.serialNumber;db:zeek_ssl.issuer.serialNumber;kind:termfield;friendly:Issuer Serial Number;help:Issuer Serial Number");
  this.ssl_issuer_titleField = this.api.addField("field:zeek_ssl.issuer.title;db:zeek_ssl.issuer.title;kind:termfield;friendly:Issuer Title;help:Issuer Title");
  this.ssl_issuer_initialsField = this.api.addField("field:zeek_ssl.issuer.initials;db:zeek_ssl.issuer.initials;kind:termfield;friendly:Issuer Initials;help:Issuer Initials");
  this.ssl_issuer_emailAddressField = this.api.addField("field:zeek_ssl.issuer.emailAddress;db:zeek_ssl.issuer.emailAddress;kind:termfield;friendly:Issuer Email Address;help:Issuer Email Address");
  this.ssl_client_subject_fullField = this.api.addField("field:zeek_ssl.client_subject_full;db:zeek_ssl.client_subject_full;kind:termfield;friendly:Client Subject;help:Client Subject");
  this.ssl_client_subject_CNField = this.api.addField("field:zeek_ssl.client_subject.CN;db:zeek_ssl.client_subject.CN;kind:termfield;friendly:Client Subject Common Name;help:Client Subject Common Name");
  this.ssl_client_subject_CField = this.api.addField("field:zeek_ssl.client_subject.C;db:zeek_ssl.client_subject.C;kind:termfield;friendly:Client Subject Country;help:Client Subject Country");
  this.ssl_client_subject_OField = this.api.addField("field:zeek_ssl.client_subject.O;db:zeek_ssl.client_subject.O;kind:termfield;friendly:Client Subject Organization;help:Client Subject Organization");
  this.ssl_client_subject_OUField = this.api.addField("field:zeek_ssl.client_subject.OU;db:zeek_ssl.client_subject.OU;kind:termfield;friendly:Client Subject Organization Unit;help:Client Subject Organization Unit");
  this.ssl_client_subject_STField = this.api.addField("field:zeek_ssl.client_subject.ST;db:zeek_ssl.client_subject.ST;kind:termfield;friendly:Client Subject State;help:Client Subject State");
  this.ssl_client_subject_SNField = this.api.addField("field:zeek_ssl.client_subject.SN;db:zeek_ssl.client_subject.SN;kind:termfield;friendly:Client Subject Surname;help:Client Subject Surname");
  this.ssl_client_subject_LField = this.api.addField("field:zeek_ssl.client_subject.L;db:zeek_ssl.client_subject.L;kind:termfield;friendly:Client Subject Locality;help:Client Subject Locality");
  this.ssl_client_subject_GNField = this.api.addField("field:zeek_ssl.client_subject.GN;db:zeek_ssl.client_subject.GN;kind:termfield;friendly:Client Subject Given Name;help:Client Subject Given Name");
  this.ssl_client_subject_pseudonymField = this.api.addField("field:zeek_ssl.client_subject.pseudonym;db:zeek_ssl.client_subject.pseudonym;kind:termfield;friendly:Client Subject Pseudonym;help:Client Subject Pseudonym");
  this.ssl_client_subject_serialNumberField = this.api.addField("field:zeek_ssl.client_subject.serialNumber;db:zeek_ssl.client_subject.serialNumber;kind:termfield;friendly:Client Subject Serial Number;help:Client Subject Serial Number");
  this.ssl_client_subject_titleField = this.api.addField("field:zeek_ssl.client_subject.title;db:zeek_ssl.client_subject.title;kind:termfield;friendly:Client Subject Title;help:Client Subject Title");
  this.ssl_client_subject_initialsField = this.api.addField("field:zeek_ssl.client_subject.initials;db:zeek_ssl.client_subject.initials;kind:termfield;friendly:Client Subject Initials;help:Client Subject Initials");
  this.ssl_client_subject_emailAddressField = this.api.addField("field:zeek_ssl.client_subject.emailAddress;db:zeek_ssl.client_subject.emailAddress;kind:termfield;friendly:Client Subject Email Address;help:Client Subject Email Address");
  this.ssl_client_issuer_fullField = this.api.addField("field:zeek_ssl.client_issuer_full;db:zeek_ssl.client_issuer_full;kind:termfield;friendly:Client Issuer;help:Client Issuer");
  this.ssl_client_issuer_CNField = this.api.addField("field:zeek_ssl.client_issuer.CN;db:zeek_ssl.client_issuer.CN;kind:termfield;friendly:Client Issuer Common Name;help:Client Issuer Common Name");
  this.ssl_client_issuer_CField = this.api.addField("field:zeek_ssl.client_issuer.C;db:zeek_ssl.client_issuer.C;kind:termfield;friendly:Client Issuer Country;help:Client Issuer Country");
  this.ssl_client_issuer_OField = this.api.addField("field:zeek_ssl.client_issuer.O;db:zeek_ssl.client_issuer.O;kind:termfield;friendly:Client Issuer Organization;help:Client Issuer Organization");
  this.ssl_client_issuer_OUField = this.api.addField("field:zeek_ssl.client_issuer.OU;db:zeek_ssl.client_issuer.OU;kind:termfield;friendly:Client Issuer Organization Unit;help:Client Issuer Organization Unit");
  this.ssl_client_issuer_STField = this.api.addField("field:zeek_ssl.client_issuer.ST;db:zeek_ssl.client_issuer.ST;kind:termfield;friendly:Client Issuer State;help:Client Issuer State");
  this.ssl_client_issuer_SNField = this.api.addField("field:zeek_ssl.client_issuer.SN;db:zeek_ssl.client_issuer.SN;kind:termfield;friendly:Client Issuer Surname;help:Client Issuer Surname");
  this.ssl_client_issuer_LField = this.api.addField("field:zeek_ssl.client_issuer.L;db:zeek_ssl.client_issuer.L;kind:termfield;friendly:Client Issuer Locality;help:Client Issuer Locality");
  this.ssl_client_issuer_DCField = this.api.addField("field:zeek_ssl.client_issuer.DC;db:zeek_ssl.client_issuer.DC;kind:termfield;friendly:Client Issuer Distinguished Name;help:Client Issuer Distinguished Name");
  this.ssl_client_issuer_GNField = this.api.addField("field:zeek_ssl.client_issuer.GN;db:zeek_ssl.client_issuer.GN;kind:termfield;friendly:Client Issuer Given Name;help:Client Issuer Given Name");
  this.ssl_client_issuer_pseudonymField = this.api.addField("field:zeek_ssl.client_issuer.pseudonym;db:zeek_ssl.client_issuer.pseudonym;kind:termfield;friendly:Client Issuer Pseudonym;help:Client Issuer Pseudonym");
  this.ssl_client_issuer_serialNumberField = this.api.addField("field:zeek_ssl.client_issuer.serialNumber;db:zeek_ssl.client_issuer.serialNumber;kind:termfield;friendly:Client Issuer Serial Number;help:Client Issuer Serial Number");
  this.ssl_client_issuer_titleField = this.api.addField("field:zeek_ssl.client_issuer.title;db:zeek_ssl.client_issuer.title;kind:termfield;friendly:Client Issuer Title;help:Client Issuer Title");
  this.ssl_client_issuer_initialsField = this.api.addField("field:zeek_ssl.client_issuer.initials;db:zeek_ssl.client_issuer.initials;kind:termfield;friendly:Client Issuer Initials;help:Client Issuer Initials");
  this.ssl_client_issuer_emailAddressField = this.api.addField("field:zeek_ssl.client_issuer.emailAddress;db:zeek_ssl.client_issuer.emailAddress;kind:termfield;friendly:Client Issuer Email Address;help:Client Issuer Email Address");
  this.ssl_validation_statusField = this.api.addField("field:zeek_ssl.validation_status;db:zeek_ssl.validation_status;kind:termfield;friendly:Validation Status;help:Validation Status");
  this.ssl_ja3Field = this.api.addField("field:zeek_ssl.ja3;db:zeek_ssl.ja3;kind:termfield;friendly:JA3 Fingerprint;help:JA3 Fingerprint");
  this.ssl_ja3sField = this.api.addField("field:zeek_ssl.ja3s;db:zeek_ssl.ja3s;kind:termfield;friendly:JA3S Fingerprint;help:JA3S Fingerprint");
  this.ssl_ja3_descField = this.api.addField("field:zeek_ssl.ja3_desc;db:zeek_ssl.ja3_desc;kind:termfield;friendly:JA3 Fingerprint Lookup;help:JA3 Fingerprint Lookup");
  this.ssl_ja3s_descField = this.api.addField("field:zeek_ssl.ja3s_desc;db:zeek_ssl.ja3s_desc;kind:termfield;friendly:JA3S Fingerprint Lookup;help:JA3S Fingerprint Lookup");

  // syslog.log
  // https://docs.zeek.org/en/stable/scripts/base/protocols/syslog/main.zeek.html#type-Syslog::Info
  this.syslog_facilityField = this.api.addField("field:zeek_syslog.facility;db:zeek_syslog.facility;kind:termfield;friendly:Facility;help:Facility");
  this.syslog_severityField = this.api.addField("field:zeek_syslog.severity;db:zeek_syslog.severity;kind:termfield;friendly:Severity;help:Severity");
  this.syslog_messageField = this.api.addField("field:zeek_syslog.message;db:zeek_syslog.message;kind:termfield;friendly:Message;help:Message");

  // tds.log - https://github.com/amzn/zeek-plugin-tds
  // https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek
  this.tds_commandField = this.api.addField("field:zeek_tds.command;db:zeek_tds.command;kind:termfield;friendly:Command;help:Command");

  // tds_rpc.log - https://github.com/amzn/zeek-plugin-tds
  // https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek
  this.tds_rpc_procedure_nameField = this.api.addField("field:zeek_tds_rpc.procedure_name;db:zeek_tds_rpc.procedure_name;kind:termfield;friendly:Procedure;help:Procedure");
  this.tds_rpc_parametersField = this.api.addField("field:zeek_tds_rpc.parameters;db:zeek_tds_rpc.parameters;kind:termfield;friendly:Parameters;help:Parameters");

  // tds_sql_batch.log - https://github.com/amzn/zeek-plugin-tds
  // https://github.com/amzn/zeek-plugin-tds/blob/master/scripts/main.zeek
  this.tds_sql_batch_header_typeField = this.api.addField("field:zeek_tds_sql_batch.header_type;db:zeek_tds_sql_batch.header_type;kind:termfield;friendly:Header Type;help:Header Type");
  this.tds_sql_batch_queryField = this.api.addField("field:zeek_tds_sql_batch.query;db:zeek_tds_sql_batch.query;kind:termfield;friendly:Query;help:Query");

  // tftp.log
  // https://github.com/zeek/spicy-tftp
  this.tftp_block_ackedField = this.api.addField("field:zeek_tftp.block_acked;db:zeek_tftp.block_acked;kind:integer;friendly:Highest Block ACKed;help:Highest Block ACKed");
  this.tftp_block_sentField = this.api.addField("field:zeek_tftp.block_sent;db:zeek_tftp.block_sent;kind:integer;friendly:Highest Block Sent;help:Highest Block Sent");
  this.tftp_error_codeField = this.api.addField("field:zeek_tftp.error_code;db:zeek_tftp.error_code;kind:integer;friendly:Error Code;help:Error Code");
  this.tftp_error_msgField = this.api.addField("field:zeek_tftp.error_msg;db:zeek_tftp.error_msg;kind:integer;friendly:Error Message;help:Error Message");
  this.tftp_fnameField = this.api.addField("field:zeek_tftp.fname;db:zeek_tftp.fname;kind:termfield;friendly:File Name;help:File Name");
  this.tftp_modeField = this.api.addField("field:zeek_tftp.mode;db:zeek_tftp.mode;kind:termfield;friendly:Transfer Mode;help:Transfer Mode");
  this.tftp_sizeField = this.api.addField("field:zeek_tftp.size;db:zeek_tftp.size;kind:termfield;friendly:Transfer Size;help:Transfer Size");
  this.tftp_uid_dataField = this.api.addField("field:zeek_tftp.uid_data;db:zeek_tftp.uid_data;kind:termfield;friendly:Data Connection ID;help:Data Connection ID");
  this.tftp_wrqField = this.api.addField("field:zeek_tftp.wrq;db:zeek_tftp.wrq;kind:termfield;friendly:Write Request;help:Write Request");

  // tunnel.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/tunnels/main.zeek.html#type-Tunnel::Info
  this.tunnel_tunnel_typeField = this.api.addField("field:zeek_tunnel.tunnel_type;db:zeek_tunnel.tunnel_type;kind:termfield;friendly:Tunnel Type;help:Tunnel Type");
  this.tunnel_actionField = this.api.addField("field:zeek_tunnel.action;db:zeek_tunnel.action;kind:termfield;friendly:Action;help:Action");

  // weird.log
  // https://docs.zeek.org/en/stable/scripts/base/frameworks/notice/weird.zeek.html#type-Weird::Info
  this.weird_nameField = this.api.addField("field:zeek_weird.name;db:zeek_weird.name;kind:termfield;friendly:Name;help:Name");
  this.weird_addlField = this.api.addField("field:zeek_weird.addl;db:zeek_weird.addl;kind:termfield;friendly:Additional Info;help:Additional Info");
  this.weird_noticeField = this.api.addField("field:zeek_weird.notice;db:zeek_weird.notice;kind:termfield;friendly:Notice;help:Generated a notice");
  this.weird_peerField = this.api.addField("field:zeek_weird.peer;db:zeek_weird.peer;kind:termfield;friendly:Remote Peer;help:Remote Peer");

  // x509.log
  // https://docs.zeek.org/en/stable/scripts/base/files/x509/main.zeek.html#type-X509::Info
  this.x509_certificate_versionField = this.api.addField("field:zeek_x509.certificate_version;db:zeek_x509.certificate_version;kind:integer;friendly:Version;help:Version");
  this.x509_certificate_serialField = this.api.addField("field:zeek_x509.certificate_serial;db:zeek_x509.certificate_serial;kind:termfield;friendly:Serial Number;help:Serial Number");
  this.x509_certificate_subject_fullField = this.api.addField("field:zeek_x509.certificate_subject_full;db:zeek_x509.certificate_subject_full;kind:termfield;friendly:Subject;help:Subject");
  this.x509_certificate_subject_CNField = this.api.addField("field:zeek_x509.certificate_subject.CN;db:zeek_x509.certificate_subject.CN;kind:termfield;friendly:Subject Common Name;help:Subject Common Name");
  this.x509_certificate_subject_CField = this.api.addField("field:zeek_x509.certificate_subject.C;db:zeek_x509.certificate_subject.C;kind:termfield;friendly:Subject Country;help:Subject Country");
  this.x509_certificate_subject_descriptionField = this.api.addField("field:zeek_x509.certificate_subject.description;db:zeek_x509.certificate_subject.description;kind:termfield;friendly:Subject Description;help:Subject Description");
  this.x509_certificate_subject_postalCodeField = this.api.addField("field:zeek_x509.certificate_subject.postalCode;db:zeek_x509.certificate_subject.postalCode;kind:termfield;friendly:Subject Postal Code;help:Subject Postal Code");
  this.x509_certificate_subject_streetField = this.api.addField("field:zeek_x509.certificate_subject.street;db:zeek_x509.certificate_subject.street;kind:termfield;friendly:Subject Street;help:Subject Street");
  this.x509_certificate_subject_OField = this.api.addField("field:zeek_x509.certificate_subject.O;db:zeek_x509.certificate_subject.O;kind:termfield;friendly:Subject Organization;help:Subject Organization");
  this.x509_certificate_subject_OUField = this.api.addField("field:zeek_x509.certificate_subject.OU;db:zeek_x509.certificate_subject.OU;kind:termfield;friendly:Subject Organization Unit;help:Subject Organization Unit");
  this.x509_certificate_subject_STField = this.api.addField("field:zeek_x509.certificate_subject.ST;db:zeek_x509.certificate_subject.ST;kind:termfield;friendly:Subject State;help:Subject State");
  this.x509_certificate_subject_SNField = this.api.addField("field:zeek_x509.certificate_subject.SN;db:zeek_x509.certificate_subject.SN;kind:termfield;friendly:Subject Surname;help:Subject Surname");
  this.x509_certificate_subject_LField = this.api.addField("field:zeek_x509.certificate_subject.L;db:zeek_x509.certificate_subject.L;kind:termfield;friendly:Subject Locality;help:Subject Locality");
  this.x509_certificate_subject_DCField = this.api.addField("field:zeek_x509.certificate_subject.DC;db:zeek_x509.certificate_subject.DC;kind:termfield;friendly:Subject Distinguished Name;help:Subject Distinguished Name");
  this.x509_certificate_subject_GNField = this.api.addField("field:zeek_x509.certificate_subject.GN;db:zeek_x509.certificate_subject.GN;kind:termfield;friendly:Subject Given Name;help:Subject Given Name");
  this.x509_certificate_subject_pseudonymField = this.api.addField("field:zeek_x509.certificate_subject.pseudonym;db:zeek_x509.certificate_subject.pseudonym;kind:termfield;friendly:Subject Pseudonym;help:Subject Pseudonym");
  this.x509_certificate_subject_serialNumberField = this.api.addField("field:zeek_x509.certificate_subject.serialNumber;db:zeek_x509.certificate_subject.serialNumber;kind:termfield;friendly:Subject Serial Number;help:Subject Serial Number");
  this.x509_certificate_subject_titleField = this.api.addField("field:zeek_x509.certificate_subject.title;db:zeek_x509.certificate_subject.title;kind:termfield;friendly:Subject Title;help:Subject Title");
  this.x509_certificate_subject_initialsField = this.api.addField("field:zeek_x509.certificate_subject.initials;db:zeek_x509.certificate_subject.initials;kind:termfield;friendly:Subject Initials;help:Subject Initials");
  this.x509_certificate_subject_emailAddressField = this.api.addField("field:zeek_x509.certificate_subject.emailAddress;db:zeek_x509.certificate_subject.emailAddress;kind:termfield;friendly:Subject Email Address;help:Subject Email Address");
  this.x509_certificate_issuer_fullField = this.api.addField("field:zeek_x509.certificate_issuer_full;db:zeek_x509.certificate_issuer_full;kind:termfield;friendly:Issuer;help:Issuer");
  this.x509_certificate_issuer_CNField = this.api.addField("field:zeek_x509.certificate_issuer.CN;db:zeek_x509.certificate_issuer.CN;kind:termfield;friendly:Issuer Common Name;help:Issuer Common Name");
  this.x509_certificate_issuer_DCField = this.api.addField("field:zeek_x509.certificate_issuer.DC;db:zeek_x509.certificate_issuer.DC;kind:termfield;friendly:Issuer Common Name;help:Issuer Distinguished Name");
  this.x509_certificate_issuer_CField = this.api.addField("field:zeek_x509.certificate_issuer.C;db:zeek_x509.certificate_issuer.C;kind:termfield;friendly:Issuer Country;help:Issuer Country");
  this.x509_certificate_issuer_OField = this.api.addField("field:zeek_x509.certificate_issuer.O;db:zeek_x509.certificate_issuer.O;kind:termfield;friendly:Issuer Organization;help:Issuer Organization");
  this.x509_certificate_issuer_OUField = this.api.addField("field:zeek_x509.certificate_issuer.OU;db:zeek_x509.certificate_issuer.OU;kind:termfield;friendly:Issuer Organization Unit;help:Issuer Organization Unit");
  this.x509_certificate_issuer_STField = this.api.addField("field:zeek_x509.certificate_issuer.ST;db:zeek_x509.certificate_issuer.ST;kind:termfield;friendly:Issuer State;help:Issuer State");
  this.x509_certificate_issuer_SNField = this.api.addField("field:zeek_x509.certificate_issuer.SN;db:zeek_x509.certificate_issuer.SN;kind:termfield;friendly:Issuer Surname;help:Issuer Surname");
  this.x509_certificate_issuer_LField = this.api.addField("field:zeek_x509.certificate_issuer.L;db:zeek_x509.certificate_issuer.L;kind:termfield;friendly:Issuer Locality;help:Issuer Locality");
  this.x509_certificate_issuer_GNField = this.api.addField("field:zeek_x509.certificate_issuer.GN;db:zeek_x509.certificate_issuer.GN;kind:termfield;friendly:Issuer Given Name;help:Issuer Given Name");
  this.x509_certificate_issuer_pseudonymField = this.api.addField("field:zeek_x509.certificate_issuer.pseudonym;db:zeek_x509.certificate_issuer.pseudonym;kind:termfield;friendly:Issuer Pseudonym;help:Issuer Pseudonym");
  this.x509_certificate_issuer_serialNumberField = this.api.addField("field:zeek_x509.certificate_issuer.serialNumber;db:zeek_x509.certificate_issuer.serialNumber;kind:termfield;friendly:Issuer Serial Number;help:Issuer Serial Number");
  this.x509_certificate_issuer_titleField = this.api.addField("field:zeek_x509.certificate_issuer.title;db:zeek_x509.certificate_issuer.title;kind:termfield;friendly:Issuer Title;help:Issuer Title");
  this.x509_certificate_issuer_initialsField = this.api.addField("field:zeek_x509.certificate_issuer.initials;db:zeek_x509.certificate_issuer.initials;kind:termfield;friendly:Issuer Initials;help:Issuer Initials");
  this.x509_certificate_issuer_emailAddressField = this.api.addField("field:zeek_x509.certificate_issuer.emailAddress;db:zeek_x509.certificate_issuer.emailAddress;kind:termfield;friendly:Issuer Email Address;help:Issuer Email Address");
  this.x509_certificate_not_valid_beforeField = this.api.addField("field:zeek_x509.certificate_not_valid_before;db:zeek_x509.certificate_not_valid_before;kind:termfield;friendly:Not Valid Before;help:Not Valid Before");
  this.x509_certificate_not_valid_afterField = this.api.addField("field:zeek_x509.certificate_not_valid_after;db:zeek_x509.certificate_not_valid_after;kind:termfield;friendly:Not Valid After;help:Not Valid After");
  this.x509_certificate_key_algField = this.api.addField("field:zeek_x509.certificate_key_alg;db:zeek_x509.certificate_key_alg;kind:termfield;friendly:Key Algorithm;help:Key Algorithm");
  this.x509_certificate_sig_algField = this.api.addField("field:zeek_x509.certificate_sig_alg;db:zeek_x509.certificate_sig_alg;kind:termfield;friendly:Signature Algorithm;help:Signature Algorithm");
  this.x509_certificate_key_typeField = this.api.addField("field:zeek_x509.certificate_key_type;db:zeek_x509.certificate_key_type;kind:termfield;friendly:Key Type;help:Key Type");
  this.x509_certificate_key_lengthField = this.api.addField("field:zeek_x509.certificate_key_length;db:zeek_x509.certificate_key_length;kind:integer;friendly:Key Bitlength;help:Key Bitlength");
  this.x509_certificate_exponentField = this.api.addField("field:zeek_x509.certificate_exponent;db:zeek_x509.certificate_exponent;kind:termfield;friendly:RSA Exponent;help:RSA Exponent");
  this.x509_certificate_curveField = this.api.addField("field:zeek_x509.certificate_curve;db:zeek_x509.certificate_curve;kind:termfield;friendly:Elliptic Curve;help:Elliptic Curve");
  this.x509_san_dnsField = this.api.addField("field:zeek_x509.san_dns;db:zeek_x509.san_dns;kind:termfield;friendly:SAN DNS;help:Subject Alternative Name DNS");
  this.x509_san_uriField = this.api.addField("field:zeek_x509.san_uri;db:zeek_x509.san_uri;kind:termfield;friendly:SAN URI;help:Subject Alternative Name URI");
  this.x509_san_emailField = this.api.addField("field:zeek_x509.san_email;db:zeek_x509.san_email;kind:termfield;friendly:SAN Email;help:Subject Alternative Name Email");
  this.x509_san_ipField = this.api.addField("field:zeek_x509.san_ip;db:zeek_x509.san_ip;kind:termfield;friendly:SAN IP;help:Subject Alternative Name IP");
  this.x509_basic_constraints_caField = this.api.addField("field:zeek_x509.basic_constraints_ca;db:zeek_x509.basic_constraints_ca;kind:termfield;friendly:CA Flag;help:CA Flag");
  this.x509_basic_constraints_path_lenField = this.api.addField("field:zeek_x509.basic_constraints_path_len;db:zeek_x509.basic_constraints_path_len;kind:integer;friendly:Maximum Path Length;help:Maximum Path Length");

  // todo: look at expressions for things that have parents (tunnelling, parent files, etc.)
  // todo: look at IP types and use ipPrint?

  // add right-clicks
  var allFields = [
    "communityId",
    "host.name",
    "ip.protocol",
    "mac.dst",
    "mac.src",
    "node",
    "oui.dst",
    "oui.src",
    "protocols",
    "rootId",
    "tags",
    "zeek.action",
    "zeek.community_id",
    "zeek.destination_geo.city_name",
    "zeek.destination_geo.country_name",
    "zeek.destination_ip_reverse_dns",
    "zeek.filename",
    "zeek.filetype",
    "zeek.freq_score_v1",
    "zeek.freq_score_v2",
    "zeek.fuid",
    "zeek.logType",
    "zeek.orig_h",
    "zeek.orig_hostname",
    "zeek.orig_l2_addr",
    "zeek.orig_l2_oui",
    "zeek.orig_p",
    "zeek.orig_segment",
    "zeek.password",
    "zeek.proto",
    "zeek.resp_h",
    "zeek.resp_hostname",
    "zeek.resp_l2_addr",
    "zeek.resp_l2_oui",
    "zeek.resp_p",
    "zeek.resp_segment",
    "zeek.result",
    "zeek.service",
    "zeek.service_version",
    "zeek.source_geo.city_name",
    "zeek.source_geo.country_name",
    "zeek.source_ip_reverse_dns",
    "zeek.ts",
    "zeek.uid",
    "zeek.user",
    "zeek_bacnet.bvlc_function",
    "zeek_bacnet.invoke_id",
    "zeek_bacnet.pdu_type",
    "zeek_bacnet.pdu_service",
    "zeek_bacnet.result_code",
    "zeek_bacnet_discovery.instance_number",
    "zeek_bacnet_discovery.object_type",
    "zeek_bacnet_discovery.object_name",
    "zeek_bacnet_discovery.pdu_service",
    "zeek_bacnet_discovery.range",
    "zeek_bacnet_discovery.range_low",
    "zeek_bacnet_discovery.range_high",
    "zeek_bacnet_discovery.vendor",
    "zeek_bacnet_property.array_index",
    "zeek_bacnet_property.instance_number",
    "zeek_bacnet_property.object_type",
    "zeek_bacnet_property.pdu_service",
    "zeek_bacnet_property.property",
    "zeek_bacnet_property.value",
    "zeek_bsap_ip_header.num_msg",
    "zeek_bsap_ip_header.type_name",
    "zeek_bsap_ip_rdb.app_func_code",
    "zeek_bsap_ip_rdb.data",
    "zeek_bsap_ip_rdb.data_len",
    "zeek_bsap_ip_rdb.func_code",
    "zeek_bsap_ip_rdb.header_size",
    "zeek_bsap_ip_rdb.mes_seq",
    "zeek_bsap_ip_rdb.node_status",
    "zeek_bsap_ip_rdb.res_seq",
    "zeek_bsap_ip_rdb.sequence",
    "zeek_bsap_ip_unknown.data",
    "zeek_bsap_serial_header.ctl",
    "zeek_bsap_serial_header.dadd",
    "zeek_bsap_serial_header.dfun",
    "zeek_bsap_serial_header.nsb",
    "zeek_bsap_serial_header.sadd",
    "zeek_bsap_serial_header.seq",
    "zeek_bsap_serial_header.ser",
    "zeek_bsap_serial_header.sfun",
    "zeek_bsap_serial_header.type_name",
    "zeek_bsap_serial_rdb.data",
    "zeek_bsap_serial_rdb.func_code",
    "zeek_bsap_serial_rdb_ext.data",
    "zeek_bsap_serial_rdb_ext.dfun",
    "zeek_bsap_serial_rdb_ext.extfun",
    "zeek_bsap_serial_rdb_ext.nsb",
    "zeek_bsap_serial_rdb_ext.seq",
    "zeek_bsap_serial_rdb_ext.sfun",
    "zeek_bsap_serial_unknown.data",
    "zeek_cip.attribute_id",
    "zeek_cip.cip_sequence_count",
    "zeek_cip.cip_service",
    "zeek_cip.cip_status",
    "zeek_cip.class_id",
    "zeek_cip.class_name",
    "zeek_cip.data_id",
    "zeek_cip.direction",
    "zeek_cip.instance_id",
    "zeek_cip.other_id",
    "zeek_cip_identity.device_state",
    "zeek_cip_identity.device_status",
    "zeek_cip_identity.device_type_id",
    "zeek_cip_identity.device_type_name",
    "zeek_cip_identity.encapsulation_version",
    "zeek_cip_identity.product_code",
    "zeek_cip_identity.product_name",
    "zeek_cip_identity.revision",
    "zeek_cip_identity.serial_number",
    "zeek_cip_identity.socket_address",
    "zeek_cip_identity.socket_address_geo.city_name",
    "zeek_cip_identity.socket_address_geo.country_name",
    "zeek_cip_identity.socket_address_asn",
    "zeek_cip_identity.socket_port",
    "zeek_cip_identity.vendor_id",
    "zeek_cip_identity.vendor_name",
    "zeek_cip_io.connection_id",
    "zeek_cip_io.data_length",
    "zeek_cip_io.sequence_number",
    "zeek_cip_io.io_data",
    "zeek_conn.conn_state",
    "zeek_conn.conn_state_description",
    "zeek_conn.duration",
    "zeek_conn.history",
    "zeek_conn.inner_vlan",
    "zeek_conn.local_orig",
    "zeek_conn.local_resp",
    "zeek_conn.missed_bytes",
    "zeek_conn.orig_bytes",
    "zeek_conn.orig_ip_bytes",
    "zeek_conn.orig_pkts",
    "zeek_conn.resp_bytes",
    "zeek_conn.resp_ip_bytes",
    "zeek_conn.resp_pkts",
    "zeek_conn.tunnel_parents",
    "zeek_conn.vlan",
    "zeek_dce_rpc.endpoint",
    "zeek_dce_rpc.named_pipe",
    "zeek_dce_rpc.operation",
    "zeek_dce_rpc.rtt",
    "zeek_dhcp.assigned_ip",
    "zeek_dhcp.client_fqdn",
    "zeek_dhcp.client_message",
    "zeek_dhcp.client_software",
    "zeek_dhcp.domain",
    "zeek_dhcp.duration",
    "zeek_dhcp.host_name",
    "zeek_dhcp.lease_time",
    "zeek_dhcp.mac",
    "zeek_dhcp.msg_types",
    "zeek_dhcp.requested_ip",
    "zeek_dhcp.server_message",
    "zeek_dhcp.server_software",
    "zeek_dhcp.trans_id",
    "zeek_dnp3.fc_reply",
    "zeek_dnp3.fc_request",
    "zeek_dnp3.iin",
    "zeek_dnp3.iin_flags",
    "zeek_dnp3_control.block_type",
    "zeek_dnp3_control.function_code",
    "zeek_dnp3_control.index_number",
    "zeek_dnp3_control.trip_control_code",
    "zeek_dnp3_control.operation_type",
    "zeek_dnp3_control.execute_count",
    "zeek_dnp3_control.on_time",
    "zeek_dnp3_control.off_time",
    "zeek_dnp3_control.status_code",
    "zeek_dnp3_objects.function_code",
    "zeek_dnp3_objects.object_type",
    "zeek_dnp3_objects.object_count",
    "zeek_dnp3_objects.range_low",
    "zeek_dnp3_objects.range_high",
    "zeek_dns.AA",
    "zeek_dns.answers",
    "zeek_dns.qclass",
    "zeek_dns.qclass_name",
    "zeek_dns.qtype",
    "zeek_dns.qtype_name",
    "zeek_dns.query",
    "zeek_dns.RA",
    "zeek_dns.rcode",
    "zeek_dns.rcode_name",
    "zeek_dns.RD",
    "zeek_dns.rejected",
    "zeek_dns.rtt",
    "zeek_dns.TC",
    "zeek_dns.trans_id",
    "zeek_dns.TTLs",
    "zeek_dns.Z",
    "zeek_dpd.failure_reason",
    "zeek_dpd.service",
    "zeek_enip.enip_command",
    "zeek_enip.enip_status",
    "zeek_enip.length",
    "zeek_enip.options",
    "zeek_enip.sender_context",
    "zeek_enip.session_handle",
    "zeek_files.analyzers",
    "zeek_files.conn_uids",
    "zeek_files.depth",
    "zeek_files.duration",
    "zeek_files.extracted",
    "zeek_files.extracted_cutoff",
    "zeek_files.extracted_size",
    "zeek_files.filename",
    "zeek_files.is_orig",
    "zeek_files.local_orig",
    "zeek_files.md5",
    "zeek_files.mime_type",
    "zeek_files.missing_bytes",
    "zeek_files.overflow_bytes",
    "zeek_files.parent_fuid",
    "zeek_files.rx_hosts",
    "zeek_files.seen_bytes",
    "zeek_files.sha1",
    "zeek_files.sha256",
    "zeek_files.source",
    "zeek_files.timedout",
    "zeek_files.total_bytes",
    "zeek_files.tx_hosts",
    "zeek_ftp.arg",
    "zeek_ftp.command",
    "zeek_ftp.data_channel_orig_h",
    "zeek_ftp.data_channel_passive",
    "zeek_ftp.data_channel_resp_h",
    "zeek_ftp.data_channel_resp_p",
    "zeek_ftp.file_size",
    "zeek_ftp.mime_type",
    "zeek_ftp.reply_code",
    "zeek_ftp.reply_msg",
    "zeek_gquic.cyu",
    "zeek_gquic.cyutags",
    "zeek_gquic.server_name",
    "zeek_gquic.tag_count",
    "zeek_gquic.user_agent",
    "zeek_gquic.version",
    "zeek_http.host",
    "zeek_http.info_code",
    "zeek_http.info_msg",
    "zeek_http.method",
    "zeek_http.orig_filenames",
    "zeek_http.orig_fuids",
    "zeek_http.orig_mime_types",
    "zeek_http.origin",
    "zeek_http.post_password_plain",
    "zeek_http.post_username",
    "zeek_http.proxied",
    "zeek_http.referrer",
    "zeek_http.request_body_len",
    "zeek_http.resp_filenames",
    "zeek_http.resp_fuids",
    "zeek_http.resp_mime_types",
    "zeek_http.response_body_len",
    "zeek_http.status_code",
    "zeek_http.status_msg",
    "zeek_http.tags",
    "zeek_http.trans_depth",
    "zeek_http.uri",
    "zeek_http.user_agent",
    "zeek_http.version",
    "zeek_intel.file_description",
    "zeek_intel.file_mime_type",
    "zeek_intel.indicator",
    "zeek_intel.indicator_type",
    "zeek_intel.matched",
    "zeek_intel.seen_node",
    "zeek_intel.seen_where",
    "zeek_intel.sources",
    "zeek_irc.addl",
    "zeek_irc.command",
    "zeek_irc.dcc_file_name",
    "zeek_irc.dcc_file_size",
    "zeek_irc.dcc_mime_type",
    "zeek_irc.nick",
    "zeek_irc.value",
    "zeek_iso_cotp.pdu_type",
    "zeek_kerberos.cipher",
    "zeek_kerberos.client_cert_fuid",
    "zeek_kerberos.client_cert_subject",
    "zeek_kerberos.cname",
    "zeek_kerberos.error_msg",
    "zeek_kerberos.forwardable",
    "zeek_kerberos.from",
    "zeek_kerberos.renewable",
    "zeek_kerberos.request_type",
    "zeek_kerberos.server_cert_fuid",
    "zeek_kerberos.server_cert_subject",
    "zeek_kerberos.sname",
    "zeek_kerberos.success",
    "zeek_kerberos.till",
    "zeek_known_certs.issuer_subject",
    "zeek_known_certs.serial",
    "zeek_known_certs.subject",
    "zeek_known_modbus.device_type",
    "zeek_ldap.entry",
    "zeek_ldap.error",
    "zeek_ldap.message_id",
    "zeek_ldap.operation",
    "zeek_ldap.result",
    "zeek_ldap.result_code",
    "zeek_ldap.value",
    "zeek_login.client_user",
    "zeek_login.confused",
    "zeek_login.success",
    "zeek_modbus.exception",
    "zeek_modbus.func",
    "zeek_modbus_detailed.unit_id",
    "zeek_modbus_detailed.func",
    "zeek_modbus_detailed.network_direction",
    "zeek_modbus_detailed.address",
    "zeek_modbus_detailed.quantity",
    "zeek_modbus_detailed.values",
    "zeek_modbus_mask_write_register.unit_id",
    "zeek_modbus_mask_write_register.func",
    "zeek_modbus_mask_write_register.network_direction",
    "zeek_modbus_mask_write_register.address",
    "zeek_modbus_mask_write_register.and_mask",
    "zeek_modbus_mask_write_register.or_mask",
    "zeek_modbus_read_write_multiple_registers.unit_id",
    "zeek_modbus_read_write_multiple_registers.func",
    "zeek_modbus_read_write_multiple_registers.network_direction",
    "zeek_modbus_read_write_multiple_registers.write_start_address",
    "zeek_modbus_read_write_multiple_registers.write_registers",
    "zeek_modbus_read_write_multiple_registers.read_start_address",
    "zeek_modbus_read_write_multiple_registers.read_quantity",
    "zeek_modbus_read_write_multiple_registers.read_registers",
    "zeek_modbus_register_change.delta",
    "zeek_modbus_register_change.new_val",
    "zeek_modbus_register_change.old_val",
    "zeek_modbus_register_change.register",
    "zeek_mqtt_connect.client_id",
    "zeek_mqtt_connect.connect_status",
    "zeek_mqtt_connect.proto_name",
    "zeek_mqtt_connect.proto_version",
    "zeek_mqtt_connect.will_payload",
    "zeek_mqtt_connect.will_topic",
    "zeek_mqtt_publish.from_client",
    "zeek_mqtt_publish.payload",
    "zeek_mqtt_publish.payload_len",
    "zeek_mqtt_publish.qos",
    "zeek_mqtt_publish.retain",
    "zeek_mqtt_publish.status",
    "zeek_mqtt_publish.topic",
    "zeek_mqtt_subscribe.ack",
    "zeek_mqtt_subscribe.action",
    "zeek_mqtt_subscribe.granted_qos_level",
    "zeek_mqtt_subscribe.qos_levels",
    "zeek_mqtt_subscribe.topics",
    "zeek_mysql.arg",
    "zeek_mysql.cmd",
    "zeek_mysql.response",
    "zeek_mysql.rows",
    "zeek_mysql.success",
    "zeek_noise.msg_type",
    "zeek_noise.sender",
    "zeek_noise.receiver",
    "zeek_noise.unenc_ephemeral",
    "zeek_noise.enc_static",
    "zeek_noise.enc_timestamp",
    "zeek_noise.enc_nothing",
    "zeek_noise.nonce",
    "zeek_noise.enc_cookie",
    "zeek_noise.mac1",
    "zeek_noise.mac2",
    "zeek_noise.enc_payload_len",
    "zeek_noise.enc_payload",
    "zeek_notice.actions",
    "zeek_notice.category",
    "zeek_notice.dropped",
    "zeek_notice.dst",
    "zeek_notice.file_desc",
    "zeek_notice.file_mime_type",
    "zeek_notice.msg",
    "zeek_notice.n",
    "zeek_notice.note",
    "zeek_notice.p",
    "zeek_notice.peer_descr",
    "zeek_notice.remote_location_city",
    "zeek_notice.remote_location_country_code",
    "zeek_notice.remote_location_latitude",
    "zeek_notice.remote_location_longitude",
    "zeek_notice.remote_location_region",
    "zeek_notice.src",
    "zeek_notice.sub",
    "zeek_notice.sub_category",
    "zeek_notice.suppress_for",
    "zeek_ntlm.domain",
    "zeek_ntlm.host",
    "zeek_ntlm.server_dns_computer",
    "zeek_ntlm.server_nb_computer",
    "zeek_ntlm.server_tree",
    "zeek_ntlm.status",
    "zeek_ntlm.success",
    "zeek_ntp.mode",
    "zeek_ntp.mode_str",
    "zeek_ntp.num_exts",
    "zeek_ntp.org_time",
    "zeek_ntp.poll",
    "zeek_ntp.precision",
    "zeek_ntp.rec_time",
    "zeek_ntp.ref_id",
    "zeek_ntp.ref_time",
    "zeek_ntp.root_delay",
    "zeek_ntp.root_disp",
    "zeek_ntp.stratum",
    "zeek_ntp.version",
    "zeek_ntp.xmt_time",
    "zeek_pe.compile_ts",
    "zeek_pe.has_cert_table",
    "zeek_pe.has_debug_data",
    "zeek_pe.has_export_table",
    "zeek_pe.has_import_table",
    "zeek_pe.is_64bit",
    "zeek_pe.is_exe",
    "zeek_pe.machine",
    "zeek_pe.os",
    "zeek_pe.section_names",
    "zeek_pe.subsystem",
    "zeek_pe.uses_aslr",
    "zeek_pe.uses_code_integrity",
    "zeek_pe.uses_dep",
    "zeek_pe.uses_seh",
    "zeek_profinet.block_version",
    "zeek_profinet.index",
    "zeek_profinet.operation_type",
    "zeek_profinet.slot_number",
    "zeek_profinet.subslot_number",
    "zeek_profinet_dce_rpc.activity_uuid",
    "zeek_profinet_dce_rpc.interface_uuid",
    "zeek_profinet_dce_rpc.object_uuid",
    "zeek_profinet_dce_rpc.operation",
    "zeek_profinet_dce_rpc.packet_type",
    "zeek_profinet_dce_rpc.server_boot_time",
    "zeek_profinet_dce_rpc.version",
    "zeek_radius.connect_info",
    "zeek_radius.framed_addr",
    "zeek_radius.mac",
    "zeek_radius.reply_msg",
    "zeek_radius.result",
    "zeek_radius.ttl",
    "zeek_radius.tunnel_client",
    "zeek_rdp.cert_count",
    "zeek_rdp.cert_permanent",
    "zeek_rdp.cert_type",
    "zeek_rdp.client_build",
    "zeek_rdp.client_channels",
    "zeek_rdp.client_dig_product_id",
    "zeek_rdp.client_name",
    "zeek_rdp.cookie",
    "zeek_rdp.desktop_height",
    "zeek_rdp.desktop_width",
    "zeek_rdp.encryption_level",
    "zeek_rdp.encryption_method",
    "zeek_rdp.keyboard_layout",
    "zeek_rdp.requested_color_depth",
    "zeek_rdp.result",
    "zeek_rdp.security_protocol",
    "zeek_rfb.auth",
    "zeek_rfb.authentication_method",
    "zeek_rfb.client_major_version",
    "zeek_rfb.client_minor_version",
    "zeek_rfb.desktop_name",
    "zeek_rfb.height",
    "zeek_rfb.server_major_version",
    "zeek_rfb.server_minor_version",
    "zeek_rfb.share_flag",
    "zeek_rfb.width",
    "zeek_s7comm.data_info",
    "zeek_s7comm.item_count",
    "zeek_s7comm.parameter",
    "zeek_s7comm.parameters.class",
    "zeek_s7comm.parameters.code",
    "zeek_s7comm.parameters.group",
    "zeek_s7comm.parameters.mode",
    "zeek_s7comm.parameters.sub",
    "zeek_s7comm.parameters.type",
    "zeek_s7comm.rosctr",
    "zeek_signatures.engine",
    "zeek_signatures.event_message",
    "zeek_signatures.hits",
    "zeek_signatures.host_count",
    "zeek_signatures.note",
    "zeek_signatures.signature_count",
    "zeek_signatures.signature_id",
    "zeek_signatures.sub_message",
    "zeek_sip.call_id",
    "zeek_sip.content_type",
    "zeek_sip.date",
    "zeek_sip.method",
    "zeek_sip.reply_to",
    "zeek_sip.request_body_len",
    "zeek_sip.request_from",
    "zeek_sip.request_path",
    "zeek_sip.request_to",
    "zeek_sip.response_body_len",
    "zeek_sip.response_from",
    "zeek_sip.response_path",
    "zeek_sip.response_to",
    "zeek_sip.seq",
    "zeek_sip.status_code",
    "zeek_sip.status_msg",
    "zeek_sip.subject",
    "zeek_sip.trans_depth",
    "zeek_sip.uri",
    "zeek_sip.user_agent",
    "zeek_sip.version",
    "zeek_sip.warning",
    "zeek_smb_cmd.argument",
    "zeek_smb_cmd.command",
    "zeek_smb_cmd.rtt",
    "zeek_smb_cmd.status",
    "zeek_smb_cmd.sub_command",
    "zeek_smb_cmd.tree",
    "zeek_smb_cmd.tree_service",
    "zeek_smb_cmd.user",
    "zeek_smb_cmd.version",
    "zeek_smb_files.action",
    "zeek_smb_files.data_len_req",
    "zeek_smb_files.data_len_rsp",
    "zeek_smb_files.data_offset_req",
    "zeek_smb_files.name",
    "zeek_smb_files.path",
    "zeek_smb_files.prev_name",
    "zeek_smb_files.size",
    "zeek_smb_files.times_accessed",
    "zeek_smb_files.times_changed",
    "zeek_smb_files.times_created",
    "zeek_smb_files.times_modified",
    "zeek_smb_mapping.native_file_system",
    "zeek_smb_mapping.path",
    "zeek_smb_mapping.resource_type",
    "zeek_smb_mapping.share_type",
    "zeek_smtp.cc",
    "zeek_smtp.date",
    "zeek_smtp.first_received",
    "zeek_smtp.from",
    "zeek_smtp.helo",
    "zeek_smtp.in_reply_to",
    "zeek_smtp.is_webmail",
    "zeek_smtp.last_reply",
    "zeek_smtp.last_reply_code",
    "zeek_smtp.last_reply_msg",
    "zeek_smtp.mailfrom",
    "zeek_smtp.msg_id",
    "zeek_smtp.path",
    "zeek_smtp.rcptto",
    "zeek_smtp.reply_to",
    "zeek_smtp.second_received",
    "zeek_smtp.subject",
    "zeek_smtp.tls",
    "zeek_smtp.to",
    "zeek_smtp.trans_depth",
    "zeek_smtp.user_agent",
    "zeek_smtp.x_originating_ip",
    "zeek_snmp.community",
    "zeek_snmp.display_string",
    "zeek_snmp.duration",
    "zeek_snmp.get_bulk_requests",
    "zeek_snmp.get_requests",
    "zeek_snmp.get_responses",
    "zeek_snmp.set_requests",
    "zeek_snmp.up_since",
    "zeek_snmp.version",
    "zeek_socks.bound_host",
    "zeek_socks.bound_name",
    "zeek_socks.bound_port",
    "zeek_socks.request_host",
    "zeek_socks.request_name",
    "zeek_socks.request_port",
    "zeek_socks.server_status",
    "zeek_socks.version",
    "zeek_software.name",
    "zeek_software.software_type",
    "zeek_software.unparsed_version",
    "zeek_software.version_addl",
    "zeek_software.version_major",
    "zeek_software.version_minor",
    "zeek_software.version_minor2",
    "zeek_software.version_minor3",
    "zeek_ssh.auth_attempts",
    "zeek_ssh.auth_success",
    "zeek_ssh.cipher_alg",
    "zeek_ssh.client",
    "zeek_ssh.compression_alg",
    "zeek_ssh.cshka",
    "zeek_ssh.direction",
    "zeek_ssh.hassh",
    "zeek_ssh.hasshAlgorithms",
    "zeek_ssh.hasshServer",
    "zeek_ssh.hasshServerAlgorithms",
    "zeek_ssh.hasshVersion",
    "zeek_ssh.host_key",
    "zeek_ssh.host_key_alg",
    "zeek_ssh.kex_alg",
    "zeek_ssh.mac_alg",
    "zeek_ssh.remote_location_city",
    "zeek_ssh.remote_location_country_code",
    "zeek_ssh.remote_location_latitude",
    "zeek_ssh.remote_location_longitude",
    "zeek_ssh.remote_location_region",
    "zeek_ssh.server",
    "zeek_ssh.sshka",
    "zeek_ssh.version",
    "zeek_ssl.cert_chain_fuids",
    "zeek_ssl.cipher",
    "zeek_ssl.client_cert_chain_fuids",
    "zeek_ssl.client_issuer.C",
    "zeek_ssl.client_issuer.CN",
    "zeek_ssl.client_issuer.DC",
    "zeek_ssl.client_issuer.emailAddress",
    "zeek_ssl.client_issuer.GN",
    "zeek_ssl.client_issuer.initials",
    "zeek_ssl.client_issuer.L",
    "zeek_ssl.client_issuer.O",
    "zeek_ssl.client_issuer.OU",
    "zeek_ssl.client_issuer.pseudonym",
    "zeek_ssl.client_issuer.serialNumber",
    "zeek_ssl.client_issuer.SN",
    "zeek_ssl.client_issuer.ST",
    "zeek_ssl.client_issuer.title",
    "zeek_ssl.client_issuer_full",
    "zeek_ssl.client_subject.C",
    "zeek_ssl.client_subject.CN",
    "zeek_ssl.client_subject.emailAddress",
    "zeek_ssl.client_subject.GN",
    "zeek_ssl.client_subject.initials",
    "zeek_ssl.client_subject.L",
    "zeek_ssl.client_subject.O",
    "zeek_ssl.client_subject.OU",
    "zeek_ssl.client_subject.pseudonym",
    "zeek_ssl.client_subject.serialNumber",
    "zeek_ssl.client_subject.SN",
    "zeek_ssl.client_subject.ST",
    "zeek_ssl.client_subject.title",
    "zeek_ssl.client_subject_full",
    "zeek_ssl.curve",
    "zeek_ssl.established",
    "zeek_ssl.issuer.C",
    "zeek_ssl.issuer.CN",
    "zeek_ssl.issuer.DC",
    "zeek_ssl.issuer.emailAddress",
    "zeek_ssl.issuer.GN",
    "zeek_ssl.issuer.initials",
    "zeek_ssl.issuer.L",
    "zeek_ssl.issuer.O",
    "zeek_ssl.issuer.OU",
    "zeek_ssl.issuer.pseudonym",
    "zeek_ssl.issuer.serialNumber",
    "zeek_ssl.issuer.SN",
    "zeek_ssl.issuer.ST",
    "zeek_ssl.issuer.title",
    "zeek_ssl.issuer_full",
    "zeek_ssl.ja3",
    "zeek_ssl.ja3_desc",
    "zeek_ssl.ja3s",
    "zeek_ssl.ja3s_desc",
    "zeek_ssl.last_alert",
    "zeek_ssl.next_protocol",
    "zeek_ssl.resumed",
    "zeek_ssl.server_name",
    "zeek_ssl.ssl_version",
    "zeek_ssl.subject.C",
    "zeek_ssl.subject.CN",
    "zeek_ssl.subject.description",
    "zeek_ssl.subject.emailAddress",
    "zeek_ssl.subject.GN",
    "zeek_ssl.subject.initials",
    "zeek_ssl.subject.L",
    "zeek_ssl.subject.O",
    "zeek_ssl.subject.OU",
    "zeek_ssl.subject.postalCode",
    "zeek_ssl.subject.pseudonym",
    "zeek_ssl.subject.serialNumber",
    "zeek_ssl.subject.SN",
    "zeek_ssl.subject.ST",
    "zeek_ssl.subject.street",
    "zeek_ssl.subject.title",
    "zeek_ssl.subject_full",
    "zeek_ssl.validation_status",
    "zeek_syslog.facility",
    "zeek_syslog.message",
    "zeek_syslog.severity",
    "zeek_tds.command",
    "zeek_tds_rpc.parameters",
    "zeek_tds_rpc.procedure_name",
    "zeek_tds_sql_batch.header_type",
    "zeek_tds_sql_batch.query",
    "zeek_tftp.block_acked",
    "zeek_tftp.block_sent",
    "zeek_tftp.error_code",
    "zeek_tftp.error_msg",
    "zeek_tftp.fname",
    "zeek_tftp.mode",
    "zeek_tftp.size",
    "zeek_tftp.uid_data",
    "zeek_tftp.wrq",
    "zeek_tunnel.action",
    "zeek_tunnel.tunnel_type",
    "zeek_weird.addl",
    "zeek_weird.name",
    "zeek_weird.notice",
    "zeek_weird.peer",
    "zeek_x509.basic_constraints_ca",
    "zeek_x509.basic_constraints_path_len",
    "zeek_x509.certificate_curve",
    "zeek_x509.certificate_exponent",
    "zeek_x509.certificate_issuer.C",
    "zeek_x509.certificate_issuer.CN",
    "zeek_x509.certificate_issuer.DC",
    "zeek_x509.certificate_issuer.emailAddress",
    "zeek_x509.certificate_issuer.GN",
    "zeek_x509.certificate_issuer.initials",
    "zeek_x509.certificate_issuer.L",
    "zeek_x509.certificate_issuer.O",
    "zeek_x509.certificate_issuer.OU",
    "zeek_x509.certificate_issuer.pseudonym",
    "zeek_x509.certificate_issuer.serialNumber",
    "zeek_x509.certificate_issuer.SN",
    "zeek_x509.certificate_issuer.ST",
    "zeek_x509.certificate_issuer.title",
    "zeek_x509.certificate_issuer_full",
    "zeek_x509.certificate_key_alg",
    "zeek_x509.certificate_key_length",
    "zeek_x509.certificate_key_type",
    "zeek_x509.certificate_not_valid_after",
    "zeek_x509.certificate_not_valid_before",
    "zeek_x509.certificate_serial",
    "zeek_x509.certificate_sig_alg",
    "zeek_x509.certificate_subject.C",
    "zeek_x509.certificate_subject.CN",
    "zeek_x509.certificate_subject.DC",
    "zeek_x509.certificate_subject.description",
    "zeek_x509.certificate_subject.emailAddress",
    "zeek_x509.certificate_subject.GN",
    "zeek_x509.certificate_subject.initials",
    "zeek_x509.certificate_subject.L",
    "zeek_x509.certificate_subject.O",
    "zeek_x509.certificate_subject.OU",
    "zeek_x509.certificate_subject.postalCode",
    "zeek_x509.certificate_subject.pseudonym",
    "zeek_x509.certificate_subject.serialNumber",
    "zeek_x509.certificate_subject.SN",
    "zeek_x509.certificate_subject.ST",
    "zeek_x509.certificate_subject.street",
    "zeek_x509.certificate_subject.title",
    "zeek_x509.certificate_subject_full",
    "zeek_x509.certificate_version",
    "zeek_x509.san_dns",
    "zeek_x509.san_email",
    "zeek_x509.san_ip",
    "zeek_x509.san_uri"
  ];
  var allFieldsStr = allFields.join(',');

  // add URL link for assigned transport protocol numbers
  var protoFieldsStr = allFields.filter(value => /^(network\.transport|zeek.proto|ip\.protocol)$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_proto",  {name:"Protocol Registry", url:'https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml', fields:protoFieldsStr});

  // add right-click for searching IANA for services
  var serviceFieldsStr = allFields.filter(value => /^(zeek\.service|protocols?|network\.protocol)$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_service",  {name:"Service Registry", url:'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=%TEXT%', fields:serviceFieldsStr});

  // add right-click for searching VirusTotal for other IP addresses
  var ipFieldsStr = allFields.filter(value => /[_\.-](h|ip)$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_ip",  {name:"VirusTotal IP", url:"https://www.virustotal.com/en/ip-address/%TEXT%/information", fields:ipFieldsStr});

  // add right-click for searching IANA for ports
  var portFieldsStr = allFields.filter(value => /(^|src|dst|source|dest|destination|[\b_\.-])p(ort)?s?$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_port",            {name:"Port Registry", url:'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=%TEXT%', fields:portFieldsStr});
  this.api.addRightClick("malcolm_websearch_port_moloch",     {name:"Port Registry", url:'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=%TEXT%', category:"port"});

  // add right-click for searching VirusTotal for hash signatures
  var hashFieldsStr = allFields.filter(value => /(^|[\b_\.-])(md5|sha(1|256|384|512))\b/i.test(value)).join(',');
  this.api.addRightClick("malcolm_vt_fields_hash",         {name:"VirusTotal Hash", url:"https://www.virustotal.com/gui/file/%TEXT%/detection", fields:hashFieldsStr});
  this.api.addRightClick("malcolm_vt_fields_hash_moloch",  {name:"VirusTotal Hash", url:"https://www.virustotal.com/gui/file/%TEXT%/detection", category:"md5"});

  // add right-click for searching the web for signature IDs
  var sigFieldsStr = allFields.filter(value => /(^|[\b_\.-])(hit|signature(_?id))?s?$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_sig",  {name:"Web Search", url:'https://duckduckgo.com/?q="%TEXT%"', fields:sigFieldsStr});

  // add right-click for searching ARIN for ASN
  var asnFieldsStr = allFields.filter(value => /(as\.number|(src|dst)ASN|asn\.(src|dst))$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_asn",  {name:"ARIN ASN", url:'https://search.arin.net/rdap/?query=%TEXT%&searchFilter=asn', fields:asnFieldsStr});

  // add right-click for searching mime/media/content types
  var mimeFieldsStr = allFields.filter(value => /(^zeek\.filetype$|mime[_\.-]?type)/i.test(value)).join(',');
  this.api.addRightClick("malcolm_websearch_mime",  {name:"Media Type Registry", url:'https://www.iana.org/assignments/media-types/%TEXT%', fields:mimeFieldsStr});

  // add right-click for extracted/quarantined files from zeek
  var carvedFieldsStr = allFields.filter(value => /^zeek_files\.extracted$/i.test(value)).join(',');
  this.api.addRightClick("malcolm_carved_file_quarantined",         {name:"Download (if quarantined)", url:"/dl-extracted-files/quarantine/%TEXT%", fields:carvedFieldsStr});
  this.api.addRightClick("malcolm_carved_file_preserved",           {name:"Download (if preserved)", url:"/dl-extracted-files/preserved/%TEXT%", fields:carvedFieldsStr});

  // add right-clicks for pivoting into Kibana from Arkime (see nginx.conf)
  var filterLabel = "Kibana %DBFIELD%";
  var filterUrl = "idmol2kib/filter?start=%ISOSTART%&stop=%ISOSTOP%&field=%DBFIELD%&value=%TEXT%";

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
    "      session.zeek.service_version || session.zeek.user || session.zeek.password || " +
    "      session.zeek.action || session.zeek.result || session.zeek.freq_score_v1 || session.zeek.freq_score_v2 )\n" +
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
    "      +arrayList(session.zeek, 'service_version', 'Service Version', 'zeek.service_version')\n" +
    "      +arrayList(session.zeek, 'action', 'Action', 'zeek.action')\n" +
    "      +arrayList(session.zeek, 'result', 'Result', 'zeek.result')\n" +
    "      +arrayList(session.zeek, 'user', 'User', 'zeek.user')\n" +
    "      +arrayList(session.zeek, 'password', 'Password', 'zeek.password')\n" +
    "      +arrayList(session.zeek, 'freq_score_v1', 'Freq Score v1', 'zeek.freq_score_v1')\n" +
    "      +arrayList(session.zeek, 'freq_score_v2', 'Freq Score v2', 'zeek.freq_score_v2')\n" +

    // file information
    "  if (session.zeek.fuid || session.zeek.filename || session.zeek.filetype)\n" +
    "    dl.sessionDetailMeta(suffix=\"File IDs\")\n" +
    "      +arrayList(session.zeek, 'fuid', 'File ID', 'zeek.fuid')\n" +
    "      +arrayList(session.zeek, 'filename', 'File Name', 'zeek.filename')\n" +
    "      +arrayList(session.zeek, 'filetype', 'File Magic', 'zeek.filetype')\n" +

    // ####################################################################
    "  br\n");

  this.api.addView("zeek_bacnet", "require:zeek_bacnet;title:Zeek bacnet.log;fields:zeek_bacnet.bvlc_function,zeek_bacnet.pdu_type,zeek_bacnet.pdu_service,zeek_bacnet.invoke_id,zeek_bacnet.result_code");
  this.api.addView("zeek_bacnet_discovery", "require:zeek_bacnet_discovery;title:Zeek bacnet_discovery.log;fields:zeek_bacnet_discovery.pdu_service,zeek_bacnet_discovery.object_type,zeek_bacnet_discovery.instance_number,zeek_bacnet_discovery.vendor,zeek_bacnet_discovery.range,zeek_bacnet_discovery.range_low,zeek_bacnet_discovery.range_high,zeek_bacnet_discovery.object_name");
  this.api.addView("zeek_bacnet_property", "require:zeek_bacnet_property;title:Zeek bacnet_property.log;fields:zeek_bacnet_property.pdu_service,zeek_bacnet_property.object_type,zeek_bacnet_property.instance_number,zeek_bacnet_property.property,zeek_bacnet_property.array_index,zeek_bacnet_property.value");
  this.api.addView("zeek_bsap_ip_header", "require:zeek_bsap_ip_header;title:Zeek bsap_ip_header.log;fields:zeek_bsap_ip_header.num_msg,zeek_bsap_ip_header.type_name");
  this.api.addView("zeek_bsap_ip_rdb", "require:zeek_bsap_ip_rdb;title:Zeek bsap_ip_rdb.log;fields:zeek_bsap_ip_rdb.app_func_code,zeek_bsap_ip_rdb.data,zeek_bsap_ip_rdb.data_len,zeek_bsap_ip_rdb.func_code,zeek_bsap_ip_rdb.header_size,zeek_bsap_ip_rdb.mes_seq,zeek_bsap_ip_rdb.node_status,zeek_bsap_ip_rdb.res_seq,zeek_bsap_ip_rdb.sequence");
  this.api.addView("zeek_bsap_ip_unknown", "require:zeek_bsap_ip_unknown;title:Zeek bsap_ip_unknown.log;fields:zeek_bsap_ip_unknown.data");
  this.api.addView("zeek_bsap_serial_header", "require:zeek_bsap_serial_header;title:Zeek bsap_serial_header.log;fields:zeek_bsap_serial_header.ctl,zeek_bsap_serial_header.dadd,zeek_bsap_serial_header.dfun,zeek_bsap_serial_header.nsb,zeek_bsap_serial_header.sadd,zeek_bsap_serial_header.seq,zeek_bsap_serial_header.ser,zeek_bsap_serial_header.sfun,zeek_bsap_serial_header.type_name");
  this.api.addView("zeek_bsap_serial_rdb", "require:zeek_bsap_serial_rdb;title:Zeek bsap_serial_rdb.log;fields:zeek_bsap_serial_rdb.data,zeek_bsap_serial_rdb.func_code");
  this.api.addView("zeek_bsap_serial_rdb_ext", "require:zeek_bsap_serial_rdb_ext;title:Zeek bsap_serial_rdb_ext.log;fields:zeek_bsap_serial_rdb_ext.data,zeek_bsap_serial_rdb_ext.dfun,zeek_bsap_serial_rdb_ext.extfun,zeek_bsap_serial_rdb_ext.nsb,zeek_bsap_serial_rdb_ext.seq,zeek_bsap_serial_rdb_ext.sfun");
  this.api.addView("zeek_bsap_serial_unknown", "require:zeek_bsap_serial_unknown;title:Zeek bsap_serial_unknown.log;fields:zeek_bsap_serial_unknown.data");
  this.api.addView("zeek_cip", "require:zeek_cip;title:Zeek cip.log;fields:zeek_cip.cip_sequence_count,zeek_cip.direction,zeek_cip.cip_service,zeek_cip.cip_status,zeek_cip.class_id,zeek_cip.class_name,zeek_cip.instance_id,zeek_cip.attribute_id,zeek_cip.data_id,zeek_cip.other_id");
  this.api.addView("zeek_cip_identity", "require:zeek_cip_identity;title:Zeek cip_identity.log;fields:zeek_cip_identity.encapsulation_version,zeek_cip_identity.socket_address,zeek_cip_identity.socket_address_geo.city_name,zeek_cip_identity.socket_address_geo.country_name,zeek_cip_identity.socket_address_asn,zeek_cip_identity.socket_port,zeek_cip_identity.vendor_id,zeek_cip_identity.vendor_name,zeek_cip_identity.device_type_id,zeek_cip_identity.device_type_name,zeek_cip_identity.product_code,zeek_cip_identity.revision,zeek_cip_identity.device_status,zeek_cip_identity.serial_number,zeek_cip_identity.product_name,zeek_cip_identity.device_state");
  this.api.addView("zeek_cip_io", "require:zeek_cip_io;title:Zeek cip_io.log;fields:zeek_cip_io.connection_id,zeek_cip_io.sequence_number,zeek_cip_io.data_length,zeek_cip_io.io_data");
  this.api.addView("zeek_conn", "require:zeek_conn;title:Zeek conn.log;fields:zeek_conn.duration,zeek_conn.orig_bytes,zeek_conn.resp_bytes,zeek_conn.conn_state,zeek_conn.conn_state_description,zeek_conn.local_orig,zeek_conn.local_resp,zeek_conn.missed_bytes,zeek_conn.history,zeek_conn.orig_pkts,zeek_conn.orig_ip_bytes,zeek_conn.resp_pkts,zeek_conn.resp_ip_bytes,zeek_conn.tunnel_parents,zeek_conn.vlan,zeek_conn.inner_vlan");
  this.api.addView("zeek_dce_rpc", "require:zeek_dce_rpc;title:Zeek dce_rpc.log;fields:zeek_dce_rpc.rtt,zeek_dce_rpc.named_pipe,zeek_dce_rpc.endpoint,zeek_dce_rpc.operation");
  this.api.addView("zeek_dhcp", "require:zeek_dhcp;title:Zeek dhcp.log;fields:zeek_dhcp.mac,zeek_dhcp.assigned_ip,zeek_dhcp.lease_time,zeek_dhcp.trans_id,zeek_dhcp.client_fqdn,zeek_dhcp.client_message,zeek_dhcp.domain,zeek_dhcp.duration,zeek_dhcp.host_name,zeek_dhcp.msg_types,zeek_dhcp.requested_ip,zeek_dhcp.server_message,zeek_dhcp.client_software,zeek_dhcp.server_software");
  this.api.addView("zeek_dnp3", "require:zeek_dnp3;title:Zeek dnp3.log;fields:zeek_dnp3.fc_request,zeek_dnp3.fc_reply,zeek_dnp3.iin,zeek_dnp3.iin_flags");
  this.api.addView("zeek_dnp3_control", "require:zeek_dnp3_control;title:Zeek dnp3_control.log;fields:zeek_dnp3_control.block_type,zeek_dnp3_control.function_code,zeek_dnp3_control.index_number,zeek_dnp3_control.trip_control_code,zeek_dnp3_control.operation_type,zeek_dnp3_control.execute_count,zeek_dnp3_control.on_time,zeek_dnp3_control.off_time,zeek_dnp3_control.status_code");
  this.api.addView("zeek_dnp3_objects", "require:zeek_dnp3_objects;title:Zeek dnp3_objects.log;fields:zeek_dnp3_objects.function_code,zeek_dnp3_objects.object_type,zeek_dnp3_objects.object_count,zeek_dnp3_objects.range_low,zeek_dnp3_objects.range_high");
  this.api.addView("zeek_dns", "require:zeek_dns;title:Zeek dns.log;fields:zeek_dns.trans_id,zeek_dns.rtt,zeek_dns.query,zeek_dns.qclass,zeek_dns.qclass_name,zeek_dns.qtype,zeek_dns.qtype_name,zeek_dns.rcode,zeek_dns.rcode_name,zeek_dns.AA,zeek_dns.TC,zeek_dns.RD,zeek_dns.RA,zeek_dns.Z,zeek_dns.answers,zeek_dns.TTLs,zeek_dns.rejected");
  this.api.addView("zeek_dpd", "require:zeek_dpd;title:Zeek dpd.log;fields:zeek_dpd.service,zeek_dpd.failure_reason");
  this.api.addView("zeek_enip", "require:zeek_enip;title:Zeek enip.log;fields:zeek_enip.enip_command,zeek_enip.length,zeek_enip.session_handle,zeek_enip.enip_status,zeek_enip.sender_context,zeek_enip.options");
  this.api.addView("zeek_files", "require:zeek_files;title:Zeek files.log;fields:zeek_files.tx_hosts,zeek_files.rx_hosts,zeek_files.conn_uids,zeek_files.source,zeek_files.depth,zeek_files.analyzers,zeek_files.mime_type,zeek_files.filename,zeek_files.duration,zeek_files.local_orig,zeek_files.is_orig,zeek_files.seen_bytes,zeek_files.total_bytes,zeek_files.missing_bytes,zeek_files.overflow_bytes,zeek_files.timedout,zeek_files.parent_fuid,zeek_files.md5,zeek_files.sha1,zeek_files.sha256,zeek_files.extracted,zeek_files.extracted_cutoff,zeek_files.extracted_size");
  this.api.addView("zeek_ftp", "require:zeek_ftp;title:Zeek ftp.log;fields:zeek_ftp.command,zeek_ftp.arg,zeek_ftp.mime_type,zeek_ftp.file_size,zeek_ftp.reply_code,zeek_ftp.reply_msg,zeek_ftp.data_channel_passive,zeek_ftp.data_channel_orig_h,zeek_ftp.data_channel_resp_h,zeek_ftp.data_channel_resp_p");
  this.api.addView("zeek_gquic", "require:zeek_gquic;title:Zeek gquic.log;fields:zeek_gquic.version,zeek_gquic.server_name,zeek_gquic.user_agent,zeek_gquic.tag_count,zeek_gquic.cyu,zeek_gquic.cyutags");
  this.api.addView("zeek_http", "require:zeek_http;title:Zeek http.log;fields:zeek_http.trans_depth,zeek_http.method,zeek_http.host,zeek_http.uri,zeek_http.origin,zeek_http.post_password_plain,zeek_http.post_username,zeek_http.referrer,zeek_http.version,zeek_http.user_agent,zeek_http.request_body_len,zeek_http.response_body_len,zeek_http.status_code,zeek_http.status_msg,zeek_http.info_code,zeek_http.info_msg,zeek_http.tags,zeek_http.proxied,zeek_http.orig_fuids,zeek_http.orig_filenames,zeek_http.orig_mime_types,zeek_http.resp_fuids,zeek_http.resp_filenames,zeek_http.resp_mime_types");
  this.api.addView("zeek_intel", "require:zeek_intel;title:Zeek intel.log;fields:zeek_intel.indicator,zeek_intel.indicator_type,zeek_intel.seen_where,zeek_intel.seen_node,zeek_intel.matched,zeek_intel.sources,zeek_intel.file_mime_type,zeek_intel.file_description");
  this.api.addView("zeek_irc", "require:zeek_irc;title:Zeek irc.log;fields:zeek_irc.nick,zeek_irc.command,zeek_irc.value,zeek_irc.addl,zeek_irc.dcc_file_name,zeek_irc.dcc_file_size,zeek_irc.dcc_mime_type");
  this.api.addView("zeek_iso_cotp", "require:zeek_iso_cotp;title:Zeek iso_cotp.log;fields:zeek_iso_cotp.pdu_type");
  this.api.addView("zeek_kerberos", "require:zeek_kerberos;title:Zeek kerberos.log;fields:zeek_kerberos.cname,zeek_kerberos.sname,zeek_kerberos.success,zeek_kerberos.error_msg,zeek_kerberos.from,zeek_kerberos.till,zeek_kerberos.cipher,zeek_kerberos.forwardable,zeek_kerberos.renewable,zeek_kerberos.request_type,zeek_kerberos.client_cert_subject,zeek_kerberos.client_cert_fuid,zeek_kerberos.server_cert_subject,zeek_kerberos.server_cert_fuid");
  this.api.addView("zeek_known_certs", "require:zeek_known_certs;title:Zeek known_certs.log;fields:zeek_known_certs.subject,zeek_known_certs.issuer_subject,zeek_known_certs.serial");
  this.api.addView("zeek_known_modbus", "require:zeek_known_modbus;title:Zeek zeek_known_modbus.log;fields:zeek_known_modbus.device_type");
  this.api.addView("zeek_ldap", "require:zeek_ldap;title:Zeek ldap.log;fields:zeek_ldap.message_id,zeek_ldap.operation,zeek_ldap.value,zeek_ldap.entry,zeek_ldap.result,zeek_ldap.result_code,zeek_ldap.error");
  this.api.addView("zeek_login", "require:zeek_login;title:Zeek login.log;fields:zeek_login.client_user,zeek_login.confused,zeek_login.success");
  this.api.addView("zeek_modbus", "require:zeek_modbus;title:Zeek modbus.log;fields:zeek_modbus.func,zeek_modbus.exception");
  this.api.addView("zeek_modbus_detailed", "require:zeek_modbus_detailed;title:Zeek modbus_detailed.log;fields:zeek_modbus_detailed.unit_id,zeek_modbus_detailed.func,zeek_modbus_detailed.network_direction,zeek_modbus_detailed.address,zeek_modbus_detailed.quantity,zeek_modbus_detailed.values");
  this.api.addView("zeek_modbus_mask_write_register", "require:zeek_modbus_mask_write_register;title:Zeek modbus_mask_write_register.log;fields:zeek_modbus_mask_write_register.unit_id,zeek_modbus_mask_write_register.func,zeek_modbus_mask_write_register.network_direction,zeek_modbus_mask_write_register.address,zeek_modbus_mask_write_register.and_mask,zeek_modbus_mask_write_register.or_mask");
  this.api.addView("zeek_modbus_read_write_multiple_registers", "require:zeek_modbus_read_write_multiple_registers;title:Zeek modbus_read_write_multiple_registers.log;fields:zeek_modbus_read_write_multiple_registers.unit_id,zeek_modbus_read_write_multiple_registers.func,zeek_modbus_read_write_multiple_registers.network_direction,zeek_modbus_read_write_multiple_registers.write_start_address,zeek_modbus_read_write_multiple_registers.write_registers,zeek_modbus_read_write_multiple_registers.read_start_address,zeek_modbus_read_write_multiple_registers.read_quantity,zeek_modbus_read_write_multiple_registers.read_registers");
  this.api.addView("zeek_modbus_register_change", "require:zeek_modbus_register_change;title:Zeek modbus_register_change.log;fields:zeek_modbus_register_change.register,zeek_modbus_register_change.old_val,zeek_modbus_register_change.new_val,zeek_modbus_register_change.delta");
  this.api.addView("zeek_mqtt_connect", "require:zeek_mqtt_connect;title:Zeek mqtt_connect.log;fields:zeek_mqtt_connect.proto_name,zeek_mqtt_connect.proto_version,zeek_mqtt_connect.client_id,zeek_mqtt_connect.connect_status,zeek_mqtt_connect.will_topic,zeek_mqtt_connect.will_payload");
  this.api.addView("zeek_mqtt_publish", "require:zeek_mqtt_publish;title:Zeek mqtt_publish.log;fields:zeek_mqtt_publish.from_client,zeek_mqtt_publish.retain,zeek_mqtt_publish.qos,zeek_mqtt_publish.status,zeek_mqtt_publish.topic,zeek_mqtt_publish.payload,zeek_mqtt_publish.payload_len");
  this.api.addView("zeek_mqtt_subscribe", "require:zeek_mqtt_subscribe;title:Zeek mqtt_subscribe.log;fields:zeek_mqtt_subscribe.action,zeek_mqtt_subscribe.topics,zeek_mqtt_subscribe.qos_levels,zeek_mqtt_subscribe.granted_qos_level,zeek_mqtt_subscribe.ack");
  this.api.addView("zeek_mysql", "require:zeek_mysql;title:Zeek mysql.log;fields:zeek_mysql.cmd,zeek_mysql.arg,zeek_mysql.success,zeek_mysql.rows,zeek_mysql.response");
  this.api.addView("zeek_noise", "require:zeek_noise;title:Zeek spicy-noise.log;fields:zeek_noise.msg_type,zeek_noise.sender,zeek_noise.receiver,zeek_noise.unenc_ephemeral,zeek_noise.enc_static,zeek_noise.enc_timestamp,zeek_noise.enc_nothing,zeek_noise.nonce,zeek_noise.enc_cookie,zeek_noise.mac1,zeek_noise.mac2,zeek_noise.enc_payload_len,zeek_noise.enc_payload");
  this.api.addView("zeek_notice", "require:zeek_notice;title:Zeek notice.log;fields:zeek_notice.file_mime_type,zeek_notice.file_desc,zeek_notice.note,zeek_notice.msg,zeek_notice.sub,zeek_notice.src,zeek_notice.dst,zeek_notice.p,zeek_notice.n,zeek_notice.peer_descr,zeek_notice.actions,zeek_notice.suppress_for,zeek_notice.dropped,zeek_notice.remote_location_country_code,zeek_notice.remote_location_region,zeek_notice.remote_location_latitude,zeek_notice.remote_location_longitude,zeek_notice.category,zeek_notice.sub_category");
  this.api.addView("zeek_ntlm", "require:zeek_ntlm;title:Zeek ntlm.log;fields:zeek_ntlm.host,zeek_ntlm.domain,zeek_ntlm.success,zeek_ntlm.status,zeek_ntlm.server_nb_computer,zeek_ntlm.server_dns_computer,zeek_ntlm.server_tree");
  this.api.addView("zeek_ntp", "require:zeek_ntp;title:Zeek ntp.log;fields:zeek_ntp.version,zeek_ntp.mode,zeek_ntp.mode_str,zeek_ntp.stratum,zeek_ntp.poll,zeek_ntp.precision,zeek_ntp.root_delay,zeek_ntp.root_disp,zeek_ntp.ref_id,zeek_ntp.ref_time,zeek_ntp.org_time,zeek_ntp.rec_time,zeek_ntp.xmt_time,zeek_ntp.num_exts");
  this.api.addView("zeek_pe", "require:zeek_pe;title:Zeek pe.log;fields:zeek_pe.machine,zeek_pe.compile_ts,zeek_pe.os,zeek_pe.subsystem,zeek_pe.is_exe,zeek_pe.is_64bit,zeek_pe.uses_aslr,zeek_pe.uses_dep,zeek_pe.uses_code_integrity,zeek_pe.uses_seh,zeek_pe.has_import_table,zeek_pe.has_export_table,zeek_pe.has_cert_table,zeek_pe.has_debug_data,zeek_pe.section_names");
  this.api.addView("zeek_profinet", "require:zeek_profinet;title:Zeek profinet.log;fields:zeek_profinet.operation_type,zeek_profinet.block_version,zeek_profinet.slot_number,zeek_profinet.subslot_number,zeek_profinet.index");
  this.api.addView("zeek_profinet_dce_rpc", "require:zeek_profinet_dce_rpc;title:Zeek profinet_dce_rpc.log;fields:zeek_profinet_dce_rpc.version,zeek_profinet_dce_rpc.packet_type,zeek_profinet_dce_rpc.object_uuid,zeek_profinet_dce_rpc.interface_uuid,zeek_profinet_dce_rpc.activity_uuid,zeek_profinet_dce_rpc.server_boot_time,zeek_profinet_dce_rpc.operation");
  this.api.addView("zeek_radius", "require:zeek_radius;title:Zeek radius.log;fields:zeek_radius.mac,zeek_radius.framed_addr,zeek_radius.tunnel_client,zeek_radius.connect_info,zeek_radius.reply_msg,zeek_radius.result,zeek_radius.ttl");
  this.api.addView("zeek_rdp", "require:zeek_rdp;title:Zeek rdp.log;fields:zeek_rdp.cookie,zeek_rdp.result,zeek_rdp.security_protocol,zeek_rdp.client_channels,zeek_rdp.keyboard_layout,zeek_rdp.client_build,zeek_rdp.client_name,zeek_rdp.client_dig_product_id,zeek_rdp.desktop_width,zeek_rdp.desktop_height,zeek_rdp.requested_color_depth,zeek_rdp.cert_type,zeek_rdp.cert_count,zeek_rdp.cert_permanent,zeek_rdp.encryption_level,zeek_rdp.encryption_method");
  this.api.addView("zeek_rfb", "require:zeek_rfb;title:Zeek rfb.log;fields:zeek_rfb.client_major_version,zeek_rfb.client_minor_version,zeek_rfb.server_major_version,zeek_rfb.server_minor_version,zeek_rfb.authentication_method,zeek_rfb.auth,zeek_rfb.share_flag,zeek_rfb.desktop_name,zeek_rfb.width,zeek_rfb.height");
  this.api.addView("zeek_s7comm", "require:zeek_s7comm;title:Zeek s7comm.log;fields:zeek_s7comm.rosctr,zeek_s7comm.parameter,zeek_s7comm.parameters.class,zeek_s7comm.parameters.code,zeek_s7comm.parameters.group,zeek_s7comm.parameters.mode,zeek_s7comm.parameters.sub,zeek_s7comm.parameters.type,zeek_s7comm.item_count,zeek_s7comm.data_info");
  this.api.addView("zeek_signatures", "require:zeek_signatures;title:Zeek signatures.log;fields:zeek_signatures.note,zeek_signatures.signature_id,zeek_signatures.engine,zeek_signatures.event_message,zeek_signatures.sub_message,zeek_signatures.signature_count,zeek_signatures.host_count");
  this.api.addView("zeek_sip", "require:zeek_sip;title:Zeek sip.log;fields:zeek_sip.trans_depth,zeek_sip.method,zeek_sip.uri,zeek_sip.date,zeek_sip.request_from,zeek_sip.request_to,zeek_sip.response_from,zeek_sip.response_to,zeek_sip.reply_to,zeek_sip.call_id,zeek_sip.seq,zeek_sip.subject,zeek_sip.request_path,zeek_sip.response_path,zeek_sip.user_agent,zeek_sip.status_code,zeek_sip.status_msg,zeek_sip.warning,zeek_sip.request_body_len,zeek_sip.response_body_len,zeek_sip.content_type,zeek_sip.version");
  this.api.addView("zeek_smb_cmd", "require:zeek_smb_cmd;title:Zeek smb_cmd.log;fields:zeek_smb_cmd.command,zeek_smb_cmd.sub_command,zeek_smb_cmd.argument,zeek_smb_cmd.status,zeek_smb_cmd.rtt,zeek_smb_cmd.version,zeek_smb_cmd.user,zeek_smb_cmd.tree,zeek_smb_cmd.tree_service");
  this.api.addView("zeek_smb_files", "require:zeek_smb_files;title:Zeek smb_files.log;fields:zeek_smb_files.action,zeek_smb_files.path,zeek_smb_files.name,zeek_smb_files.size,zeek_smb_files.prev_name,zeek_smb_files.times_modified,zeek_smb_files.times_accessed,zeek_smb_files.times_created,zeek_smb_files.times_changed,zeek_smb_files.data_offset_req,zeek_smb_files.data_len_req,zeek_smb_files.data_len_rsp");
  this.api.addView("zeek_smb_mapping", "require:zeek_smb_mapping;title:Zeek smb_mapping.log;fields:zeek_smb_mapping.path,zeek_smb_mapping.resource_type,zeek_smb_mapping.native_file_system,zeek_smb_mapping.share_type");
  this.api.addView("zeek_smtp", "require:zeek_smtp;title:Zeek smtp.log;fields:zeek_smtp.trans_depth,zeek_smtp.helo,zeek_smtp.mailfrom,zeek_smtp.rcptto,zeek_smtp.date,zeek_smtp.from,zeek_smtp.to,zeek_smtp.cc,zeek_smtp.reply_to,zeek_smtp.msg_id,zeek_smtp.in_reply_to,zeek_smtp.subject,zeek_smtp.x_originating_ip,zeek_smtp.first_received,zeek_smtp.second_received,zeek_smtp.last_reply,zeek_smtp.last_reply_code,zeek_smtp.last_reply_msg,zeek_smtp.path,zeek_smtp.user_agent,zeek_smtp.tls,zeek_smtp.is_webmail");
  this.api.addView("zeek_snmp", "require:zeek_snmp;title:Zeek snmp.log;fields:zeek_snmp.duration,zeek_snmp.version,zeek_snmp.community,zeek_snmp.get_requests,zeek_snmp.get_bulk_requests,zeek_snmp.get_responses,zeek_snmp.set_requests,zeek_snmp.display_string,zeek_snmp.up_since");
  this.api.addView("zeek_socks", "require:zeek_socks;title:Zeek socks.log;fields:zeek_socks.version,zeek_socks.server_status,zeek_socks.request_host,zeek_socks.request_name,zeek_socks.request_port,zeek_socks.bound_host,zeek_socks.bound_name,zeek_socks.bound_port");
  this.api.addView("zeek_software", "require:zeek_software;title:Zeek software.log;fields:zeek_software.software_type,zeek_software.name,zeek_software.version_major,zeek_software.version_minor,zeek_software.version_minor2,zeek_software.version_minor3,zeek_software.version_addl,zeek_software.unparsed_version");
  this.api.addView("zeek_ssh", "require:zeek_ssh;title:Zeek ssh.log;fields:zeek_ssh.version,zeek_ssh.auth_success,zeek_ssh.auth_attempts,zeek_ssh.direction,zeek_ssh.client,zeek_ssh.server,zeek_ssh.cipher_alg,zeek_ssh.mac_alg,zeek_ssh.compression_alg,zeek_ssh.kex_alg,zeek_ssh.host_key_alg,zeek_ssh.host_key,zeek_ssh.remote_location_country_code,zeek_ssh.remote_location_region,zeek_ssh.remote_location_city,zeek_ssh.remote_location_latitude,zeek_ssh.remote_location_longitude,zeek_ssh.hassh,zeek_ssh.hasshServer,zeek_ssh.hasshAlgorithms,zeek_ssh.hasshServerAlgorithms,zeek_ssh.cshka,zeek_ssh.sshka");
  this.api.addView("zeek_ssl", "require:zeek_ssl;title:Zeek ssl.log;fields:zeek_ssl.ssl_version,zeek_ssl.cipher,zeek_ssl.curve,zeek_ssl.server_name,zeek_ssl.resumed,zeek_ssl.last_alert,zeek_ssl.next_protocol,zeek_ssl.established,zeek_ssl.ja3,zeek_ssl.ja3_desc,zeek_ssl.ja3s,zeek_ssl.ja3s_desc,zeek_ssl.cert_chain_fuids,zeek_ssl.client_cert_chain_fuids,zeek_ssl.subject.CN,zeek_ssl.subject.C,zeek_ssl.subject.O,zeek_ssl.subject.OU,zeek_ssl.subject.ST,zeek_ssl.subject.SN,zeek_ssl.subject.L,zeek_ssl.subject.GN,zeek_ssl.subject.pseudonym,zeek_ssl.subject.serialNumber,zeek_ssl.subject.title,zeek_ssl.subject.initials,zeek_ssl.subject.emailAddress,zeek_ssl.subject.description,zeek_ssl.subject.postalCode,zeek_ssl.subject.street,zeek_ssl.client_subject.CN,zeek_ssl.client_subject.C,zeek_ssl.client_subject.O,zeek_ssl.client_subject.OU,zeek_ssl.client_subject.ST,zeek_ssl.client_subject.SN,zeek_ssl.client_subject.L,zeek_ssl.client_subject.GN,zeek_ssl.client_subject.pseudonym,zeek_ssl.client_subject.serialNumber,zeek_ssl.client_subject.title,zeek_ssl.client_subject.initials,zeek_ssl.client_subject.emailAddress,zeek_ssl.issuer.CN,zeek_ssl.issuer.C,zeek_ssl.issuer.O,zeek_ssl.issuer.OU,zeek_ssl.issuer.ST,zeek_ssl.issuer.SN,zeek_ssl.issuer.L,zeek_ssl.issuer.DC,zeek_ssl.issuer.GN,zeek_ssl.issuer.pseudonym,zeek_ssl.issuer.serialNumber,zeek_ssl.issuer.title,zeek_ssl.issuer.initials,zeek_ssl.issuer.emailAddress,zeek_ssl.client_issuer.CN,zeek_ssl.client_issuer.C,zeek_ssl.client_issuer.O,zeek_ssl.client_issuer.OU,zeek_ssl.client_issuer.ST,zeek_ssl.client_issuer.SN,zeek_ssl.client_issuer.L,zeek_ssl.client_issuer.DC,zeek_ssl.client_issuer.GN,zeek_ssl.client_issuer.pseudonym,zeek_ssl.client_issuer.serialNumber,zeek_ssl.client_issuer.title,zeek_ssl.client_issuer.initials,zeek_ssl.client_issuer.emailAddress,zeek_ssl.validation_status");
  this.api.addView("zeek_syslog", "require:zeek_syslog;title:Zeek syslog.log;fields:zeek_syslog.facility,zeek_syslog.severity,zeek_syslog.message");
  this.api.addView("zeek_tds", "require:zeek_tds;title:Zeek tds.log;fields:zeek_tds.command");
  this.api.addView("zeek_tds_rpc", "require:zeek_tds_rpc;title:Zeek tds_rpc.log;fields:zeek_tds_rpc.procedure_name,zeek_tds_rpc.parameters");
  this.api.addView("zeek_tds_sql_batch", "require:zeek_tds_sql_batch;title:Zeek tds_sql_batch.log;fields:zeek_tds_sql_batch.header_type,zeek_tds_sql_batch.query");
  this.api.addView("zeek_tftp", "require:zeek_tftp;title:Zeek tftp.log;fields:zeek_tftp.block_acked,zeek_tftp.block_sent,zeek_tftp.error_code,zeek_tftp.error_msg,zeek_tftp.fname,zeek_tftp.mode,zeek_tftp.size,zeek_tftp.uid_data,zeek_tftp.wrq");
  this.api.addView("zeek_tunnel", "require:zeek_tunnel;title:Zeek tunnel.log;fields:zeek_tunnel.tunnel_type,zeek_tunnel.action");
  this.api.addView("zeek_weird", "require:zeek_weird;title:Zeek weird.log;fields:zeek_weird.name,zeek_weird.addl,zeek_weird.notice,zeek_weird.peer");
  this.api.addView("zeek_x509", "require:zeek_x509;title:Zeek x509.log;fields:zeek_x509.certificate_version,zeek_x509.certificate_serial,zeek_x509.certificate_subject.CN,zeek_x509.certificate_subject.C,zeek_x509.certificate_subject.O,zeek_x509.certificate_subject.OU,zeek_x509.certificate_subject.ST,zeek_x509.certificate_subject.SN,zeek_x509.certificate_subject.L,zeek_x509.certificate_subject.DC,zeek_x509.certificate_subject.GN,zeek_x509.certificate_subject.pseudonym,zeek_x509.certificate_subject.serialNumber,zeek_x509.certificate_subject.title,zeek_x509.certificate_subject.initials,zeek_x509.certificate_subject.emailAddress,zeek_x509.certificate_subject.description,zeek_x509.certificate_subject.postalCode,zeek_x509.certificate_subject.street,zeek_x509.certificate_issuer.CN,zeek_x509.certificate_issuer.DC,zeek_x509.certificate_issuer.C,zeek_x509.certificate_issuer.O,zeek_x509.certificate_issuer.OU,zeek_x509.certificate_issuer.ST,zeek_x509.certificate_issuer.SN,zeek_x509.certificate_issuer.L,zeek_x509.certificate_issuer.GN,zeek_x509.certificate_issuer.pseudonym,zeek_x509.certificate_issuer.serialNumber,zeek_x509.certificate_issuer.title,zeek_x509.certificate_issuer.initials,zeek_x509.certificate_issuer.emailAddress,zeek_x509.certificate_not_valid_before,zeek_x509.certificate_not_valid_after,zeek_x509.certificate_key_alg,zeek_x509.certificate_sig_alg,zeek_x509.certificate_key_type,zeek_x509.certificate_key_length,zeek_x509.certificate_exponent,zeek_x509.certificate_curve,zeek_x509.san_dns,zeek_x509.san_uri,zeek_x509.san_email,zeek_x509.san_ip,zeek_x509.basic_constraints_ca,zeek_x509.basic_constraints_path_len");

  // Add the source as available
  this.api.addSource("zeek", this);
}
util.inherits(ZeekLogs, wiseSource);

ZeekLogs.prototype.load = function() {
  var self = this;
  this.data.clear();
};

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
