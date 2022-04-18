#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

# modify suricata.yaml according to many environment variables

#
# suricata.yaml: https://suricata.readthedocs.io/en/suricata-6.0.0/configuration/suricata-yaml.html
#                https://github.com/OISF/suricata/blob/master/suricata.yaml.in
#
# list the vars used here: grep -Po "\bSURICATA_\w+" suricata_config_populate.py | sort -u
#

import argparse
import logging
import os
import sys
from ruamel.yaml import YAML
from shutil import move as MoveFile
from collections.abc import Iterable
from collections import defaultdict, namedtuple

###################################################################################################
args = None
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
def val2bool(v):
    try:
        if v is None:
            return False
        elif isinstance(v, bool):
            return v
        elif isinstance(v, str):
            if v.lower() in ("yes", "true", "t", "y"):
                return True
            elif v.lower() in ("no", "false", "f", "n"):
                return False
            else:
                raise ValueError(f'Boolean value expected (got {v})')
        else:
            raise ValueError(f'Boolean value expected (got {v})')
    except:
        # just pitch it back and let the caller worry about it
        return v


###################################################################################################
def get_iterable(x):
    if isinstance(x, Iterable) and not isinstance(x, str):
        return x
    else:
        return (x,)


###################################################################################################
def deep_get(d, keys, default=None):
    k = get_iterable(keys)
    if d is None:
        return default
    if not keys:
        return d
    return deep_get(d.get(k[0]), k[1:], default)


###################################################################################################
def deep_set(d, keys, value, deleteIfNone=False):
    k = get_iterable(keys)
    for key in k[:-1]:
        if (key not in d) or (not isinstance(d[key], dict)):
            d[key] = dict()
        d = d[key]
    d[k[-1]] = value
    if (deleteIfNone == True) and (value is None):
        d.pop(k[-1], None)


###################################################################################################

DEFAULT_VARS = defaultdict(lambda: None)
DEFAULT_VARS.update(
    {
        'AF_PACKET_BLOCK_SIZE': 32768,
        'AF_PACKET_BLOCK_TIMEOUT': 10,
        'AF_PACKET_BUFFER_SIZE': 32768,
        'AF_PACKET_CHECKSUM_CHECKS': 'kernel',
        'AF_PACKET_CLUSTER_TYPE': 'cluster_flow',
        'AF_PACKET_DEFRAG': True,
        'AF_PACKET_EMERGENCY_FLUSH': False,
        'AF_PACKET_IFACE_THREADS': 'auto',
        'AF_PACKET_MMAP_LOCKED': False,
        'AF_PACKET_RING_SIZE': 2048,
        'AF_PACKET_TPACKET_V3': True,
        'AF_PACKET_USE_MMAP': True,
        'ANOMALY_APPLAYER': True,
        'ANOMALY_DECODE': False,
        'ANOMALY_ENABLED': True,
        'ANOMALY_PACKETHDR': False,
        'ANOMALY_STREAM': False,
        'ASN1_MAX_FRAMES': 256,
        'AUTOFP_SCHEDULER': 'hash',
        'CAPTURE_CHECKSUM_VALIDATION': 'none',
        'CAPTURE_DISABLE_OFFLOADING': True,
        'CUSTOM_RULES_ONLY': False,
        'DCERPC_ENABLED': True,
        'DEFRAG_HASH_SIZE': 65536,
        'DEFRAG_MAX_FRAGS': 65535,
        'DEFRAG_MEMCAP': '32mb',
        'DEFRAG_PREALLOC': True,
        'DEFRAG_TIMEOUT': 60,
        'DEFRAG_TRACKERS': 65535,
        'DHCP_ENABLED': True,
        'DHCP_EXTENDED': False,
        'DNP3_ENABLED': True,
        'DNP3_PORTS': 20000,
        'DNS_ENABLED': True,
        'DNS_PORTS': 53,
        'DNS_REQUESTS': True,
        'DNS_RESPONSES': True,
        'ENIP_ENABLED': True,
        'ENIP_PORTS': 44818,
        'EXTERNAL_NET': '!$HOME_NET',
        'FILE_DATA_PORTS': ['$HTTP_PORTS', 110, 143],
        'FILES_ENABLED': True,
        'FILES_FORCE_MAGIC': False,
        'FLOW_EMERGENCY_RECOVERY': 30,
        'FLOW_ENABLED': True,
        'FLOW_HASH_SIZE': 65536,
        'FLOW_MEMCAP': '128mb',
        'FLOW_PREALLOC': 10000,
        'FTP_ENABLED': True,
        'FTP_MEMCAP': '64mb',
        'FTP_PORTS': 21,
        'GENEVE_ENABLED': True,
        'GENEVE_PORTS': 6081,
        'HOME_NET': ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
        'HOST_HASH_SIZE': 4096,
        'HOST_MEMCAP': '32mb',
        'HOST_PREALLOC': 1000,
        'HTTP2_ENABLED': False,
        'HTTP_ENABLED': True,
        'HTTP_EXTENDED': True,
        'HTTP_PORTS': 80,
        'IKEV2_ENABLED': True,
        'IMAP_ENABLED': 'detection-only',
        'KRB5_ENABLED': True,
        'MANAGED_RULES_DIR': '/var/lib/suricata/rules',
        'MODBUS_ENABLED': True,
        'MODBUS_PORTS': 502,
        'MODBUS_STREAM_DEPTH': 0,
        'MQTT_ENABLED': True,
        'MQTT_MAX_MSG_LENGTH': '1mb',
        'MQTT_PASSWORDS': False,
        'NETFLOW_ENABLED': False,
        'NFS_ENABLED': True,
        'NTP_ENABLED': True,
        'ORACLE_PORTS': 1521,
        'PACKET_SIZE': 1514,
        'PCRE_MATCH_LIMIT': 3500,
        'PCRE_RECURSION': 1500,
        'RDP_ENABLED': True,
        'RFB_ENABLED': True,
        'RFB_PORTS': [5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909],
        'RUNMODE': 'autofp',
        'SHELLCODE_PORTS': '!80',
        'SIP_ENABLED': True,
        'SMB_ENABLED': True,
        'SMB_PORTS': [139, 445],
        'SMB_STREAM_DEPTH': 0,
        'SMTP_BODY_MD5': False,
        'SMTP_DECODE_BASE64': False,
        'SMTP_DECODE_MIME': False,
        'SMTP_DECODE_QUOTED_PRINTABLE': False,
        'SMTP_ENABLED': True,
        'SMTP_EXTENDED': True,
        'SMTP_EXTRACT_URLS': True,
        'SMTP_HEADER_VALUE_DEPTH': 2000,
        'SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_MIN_SIZE': 32768,
        'SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_WINDOW': 4096,
        'SMTP_INSPECTED_TRACKER_CONTENT_LIMIT': 100000,
        'SMTP_RAW_EXTRACTION': False,
        'SNMP_ENABLED': True,
        'SSH_ENABLED': True,
        'SSH_HASSH': True,
        'SSH_PORTS': 22,
        'STREAM_CHECKSUM_VALIDATION': True,
        'STREAM_INLINE': 'auto',
        'STREAM_MEMCAP': '64mb',
        'STREAM_REASSEMBLY_DEPTH': '1mb',
        'STREAM_REASSEMBLY_MEMCAP': '256mb',
        'STREAM_REASSEMBLY_RANDOMIZE_CHUNK_SIZE': True,
        'STREAM_REASSEMBLY_TOCLIENT_CHUNK_SIZE': 2560,
        'STREAM_REASSEMBLY_TOSERVER_CHUNK_SIZE': 2560,
        'TEREDO_ENABLED': True,
        'TEREDO_PORTS': 3544,
        'TEST_CONFIG_VERBOSITY': '',
        'TFTP_ENABLED': True,
        'TLS_ENABLED': True,
        'TLS_ENCRYPTION_HANDLING': 'bypass',
        'TLS_EXTENDED': True,
        'TLS_JA3': 'auto',
        'TLS_PORTS': 443,
        'TLS_SESSION_RESUMPTION': False,
        'VLAN_USE_FOR_TRACKING': True,
        'VXLAN_ENABLED': True,
        'VXLAN_PORTS': 4789,
    }
)
for varName, varVal in [
    (key.upper(), value)
    for key, value in os.environ.items()
    if key.upper().startswith('SURICATA') or key.upper() in ('CAPTURE_INTERFACE', 'CAPTURE_FILTER', 'SUPERVISOR_PATH')
]:
    tmpYaml = YAML(typ='safe')
    newVal = tmpYaml.load(varVal)
    if isinstance(newVal, str):
        if (newVal.lower() == 'yes') or (newVal.lower() == 'true'):
            newVal = True
        elif (newVal.lower() == 'no') or (newVal.lower() == 'false'):
            newVal = False
    DEFAULT_VARS[varName.removeprefix("SURICATA_")] = newVal

###################################################################################################
ProtocolConfig = namedtuple("ProtocolConfig", ["subs", "enabled", "destination_ports", "source_ports"], rename=False)
PROTOCOL_CONFIGS = defaultdict(lambda: ProtocolConfig([], True, None, None))
PROTOCOL_CONFIGS.update(
    {
        'anomaly': ProtocolConfig([], val2bool(DEFAULT_VARS['ANOMALY_ENABLED']), None, None),
        'dcerpc': ProtocolConfig([], val2bool(DEFAULT_VARS['DCERPC_ENABLED']), None, None),
        'dhcp': ProtocolConfig([], val2bool(DEFAULT_VARS['DHCP_ENABLED']), None, None),
        'dnp3': ProtocolConfig([], val2bool(DEFAULT_VARS['DNP3_ENABLED']), DEFAULT_VARS['DNP3_PORTS'], None),
        'dns': ProtocolConfig(['tcp', 'udp'], val2bool(DEFAULT_VARS['DNS_ENABLED']), DEFAULT_VARS['DNS_PORTS'], None),
        'enip': ProtocolConfig(
            [], val2bool(DEFAULT_VARS['ENIP_ENABLED']), DEFAULT_VARS['ENIP_PORTS'], DEFAULT_VARS['ENIP_PORTS']
        ),
        'files': ProtocolConfig([], val2bool(DEFAULT_VARS['FILES_ENABLED']), None, None),
        'flow': ProtocolConfig([], val2bool(DEFAULT_VARS['FLOW_ENABLED']), None, None),
        'ftp': ProtocolConfig([], val2bool(DEFAULT_VARS['FTP_ENABLED']), None, None),
        'http2': ProtocolConfig([], val2bool(DEFAULT_VARS['HTTP2_ENABLED']), None, None),
        'http': ProtocolConfig([], val2bool(DEFAULT_VARS['HTTP_ENABLED']), None, None),
        'ikev2': ProtocolConfig([], val2bool(DEFAULT_VARS['IKEV2_ENABLED']), None, None),
        'imap': ProtocolConfig([], val2bool(DEFAULT_VARS['IMAP_ENABLED']), None, None),
        'krb5': ProtocolConfig([], val2bool(DEFAULT_VARS['KRB5_ENABLED']), None, None),
        'modbus': ProtocolConfig([], val2bool(DEFAULT_VARS['MODBUS_ENABLED']), DEFAULT_VARS['MODBUS_PORTS'], None),
        'mqtt': ProtocolConfig([], val2bool(DEFAULT_VARS['MQTT_ENABLED']), None, None),
        'netflow': ProtocolConfig([], val2bool(DEFAULT_VARS['NETFLOW_ENABLED']), None, None),
        'nfs': ProtocolConfig([], val2bool(DEFAULT_VARS['NFS_ENABLED']), None, None),
        'ntp': ProtocolConfig([], val2bool(DEFAULT_VARS['NTP_ENABLED']), None, None),
        'rdp': ProtocolConfig([], val2bool(DEFAULT_VARS['RDP_ENABLED']), None, None),
        'rfb': ProtocolConfig([], val2bool(DEFAULT_VARS['RFB_ENABLED']), DEFAULT_VARS['RFB_PORTS'], None),
        'sip': ProtocolConfig([], val2bool(DEFAULT_VARS['SIP_ENABLED']), None, None),
        'smb': ProtocolConfig([], val2bool(DEFAULT_VARS['SMB_ENABLED']), DEFAULT_VARS['SMB_PORTS'], None),
        'smtp': ProtocolConfig([], val2bool(DEFAULT_VARS['SMTP_ENABLED']), None, None),
        'snmp': ProtocolConfig([], val2bool(DEFAULT_VARS['SNMP_ENABLED']), None, None),
        'ssh': ProtocolConfig([], val2bool(DEFAULT_VARS['SSH_ENABLED']), None, None),
        'tftp': ProtocolConfig([], val2bool(DEFAULT_VARS['TFTP_ENABLED']), None, None),
        'tls': ProtocolConfig([], val2bool(DEFAULT_VARS['TLS_ENABLED']), DEFAULT_VARS['TLS_PORTS'], None),
    }
)
DECODER_CONFIGS = defaultdict(lambda: ProtocolConfig([], True, None, None))
DECODER_CONFIGS.update(
    {
        'teredo': ProtocolConfig([], val2bool(DEFAULT_VARS['TEREDO_ENABLED']), DEFAULT_VARS['TEREDO_PORTS'], None),
        'vxlan': ProtocolConfig([], val2bool(DEFAULT_VARS['VXLAN_ENABLED']), DEFAULT_VARS['VXLAN_PORTS'], None),
        'geneve': ProtocolConfig([], val2bool(DEFAULT_VARS['GENEVE_ENABLED']), DEFAULT_VARS['VXLAN_PORTS'], None),
    }
)


###################################################################################################
def main():
    global args

    parser = argparse.ArgumentParser(
        description='\n'.join(
            [
                'modify suricata.yaml according to many environment variables',
            ]
        ),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False,
        usage='{} <arguments>'.format(script_name),
    )
    parser.add_argument('--verbose', '-v', action='count', default=1, help='Increase verbosity (e.g., -v, -vv, etc.)')
    parser.add_argument(
        '--inplace',
        dest='inplace',
        action='store_true',
        help='Modify configuration file in-place',
    )
    parser.add_argument(
        '--no-inplace',
        dest='inplace',
        action='store_false',
        help='Do not modify configuration file in-place',
    )
    parser.set_defaults(inplace=True)
    parser.add_argument(
        '-i',
        '--input',
        dest='input',
        type=str,
        default=os.getenv(
            'SURICATA_CONFIG_FILE',
            os.path.join(os.path.join(os.getenv('SUPERVISOR_PATH', '/etc'), 'suricata'), 'suricata.yml'),
        ),
        required=False,
        metavar='<string>',
        help="Input YAML file",
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output',
        type=str,
        default=None,
        required=False,
        metavar='<string>',
        help="Output YAML file (take precedence over --inplace)",
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    inFileParts = os.path.splitext(args.input)
    args.output = (
        args.output if args.output else args.input if args.inplace else inFileParts[0] + "_new" + inFileParts[1]
    )

    args.verbose = logging.CRITICAL - (10 * args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(
        level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.info(os.path.join(script_path, script_name))
    logging.info("Arguments: {}".format(sys.argv[1:]))
    logging.info("Arguments: {}".format(args))
    if args.verbose > logging.DEBUG:
        sys.tracebacklimit = 0

    ##################################################################################################
    # load input YAML
    cfg = None
    if args.input and os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            inYaml = YAML(typ='rt')
            inYaml.preserve_quotes = False
            inYaml.representer.ignore_aliases = lambda x: True
            inYaml.boolean_representation = ['no', 'yes']
            cfg = inYaml.load(f)
    # logging.debug(cfg)

    # address and port groups
    for addrKey in (
        'HOME_NET',
        'EXTERNAL_NET',
    ):
        deep_set(cfg, ['vars', 'address-groups', addrKey], DEFAULT_VARS[addrKey])
    # yer a wizard, 'arry
    for portKey in (
        'HTTP_PORTS',
        'SHELLCODE_PORTS',
        'ORACLE_PORTS',
        'SSH_PORTS',
        'DNP3_PORTS',
        'MODBUS_PORTS',
        'FILE_DATA_PORTS',
        'FTP_PORTS',
        'GENEVE_PORTS',
        'VXLAN_PORTS',
        'TEREDO_PORTS',
    ):
        deep_set(cfg, ['vars', 'port-groups', portKey], DEFAULT_VARS[portKey])

    # capture parameters
    for cfgKey in (
        ['capture', 'disable-offloading', 'CAPTURE_DISABLE_OFFLOADING'],
        ['capture', 'checksum-validation', 'CAPTURE_CHECKSUM_VALIDATION'],
    ):
        deep_set(
            cfg,
            cfgKey[:-1],
            DEFAULT_VARS[cfgKey[-1]],
        )

    # af-packet interface definitions
    if DEFAULT_VARS['CAPTURE_INTERFACE'] is not None:
        cfg.pop('af-packet', None)
        cfg['af-packet'] = [{'interface': 'default'}]
        clusterId = 99
        for iface in DEFAULT_VARS['CAPTURE_INTERFACE'].split(','):
            cfg['af-packet'].insert(
                0,
                {
                    'interface': iface,
                    'cluster-id': clusterId,
                    'block-size': DEFAULT_VARS['AF_PACKET_BLOCK_SIZE'],
                    'block-timeout': DEFAULT_VARS['AF_PACKET_BLOCK_TIMEOUT'],
                    'bpf-filter': DEFAULT_VARS['CAPTURE_FILTER'],
                    'buffer-size': DEFAULT_VARS['AF_PACKET_BUFFER_SIZE'],
                    'checksum-checks': DEFAULT_VARS['AF_PACKET_CHECKSUM_CHECKS'],
                    'cluster-type': DEFAULT_VARS['AF_PACKET_CLUSTER_TYPE'],
                    'defrag': DEFAULT_VARS['AF_PACKET_DEFRAG'],
                    'mmap-locked': DEFAULT_VARS['AF_PACKET_MMAP_LOCKED'],
                    'ring-size': DEFAULT_VARS['AF_PACKET_RING_SIZE'],
                    'threads': DEFAULT_VARS['AF_PACKET_IFACE_THREADS'],
                    'tpacket-v3': DEFAULT_VARS['AF_PACKET_TPACKET_V3'],
                    'use-emergency-flush': DEFAULT_VARS['AF_PACKET_EMERGENCY_FLUSH'],
                    'use-mmap': DEFAULT_VARS['AF_PACKET_USE_MMAP'],
                },
            )
            clusterId = clusterId - 1

    # disable all outputs, then enable just the one we want (eve-log)
    for outputIdx in range(len(cfg['outputs'])):
        for name, config in cfg['outputs'][outputIdx].items():
            cfg['outputs'][outputIdx][name]['enabled'] = name in ('eve-log')

            # while we're here, configure the eve-log section of outputs
            if name == 'eve-log':

                # enable community-id for easier cross-referencing and pcap-file for
                # tying back to the original PCAP filename
                cfg['outputs'][outputIdx][name]['community-id'] = True
                cfg['outputs'][outputIdx][name]['pcap-file'] = True

                # configure the various different output types belonging to eve-log
                if 'types' in cfg['outputs'][outputIdx][name]:

                    remainingTypes = set(list(PROTOCOL_CONFIGS.keys()))

                    for dumperIdx in reversed(range(len(cfg['outputs'][outputIdx][name]['types']))):
                        if isinstance(cfg['outputs'][outputIdx][name]['types'][dumperIdx], dict):
                            # eve.json alert type is map (has config)
                            for dumperName, dumperConfig in cfg['outputs'][outputIdx][name]['types'][dumperIdx].items():
                                remainingTypes.discard(dumperName)

                                # enable/disable this eve.json alert type (map config)
                                deep_set(
                                    cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                    [dumperName, 'enabled'],
                                    PROTOCOL_CONFIGS[dumperName].enabled,
                                )

                                if dumperName == 'alert':
                                    # don't dump payload, we can pivot to the payload with Arkime via community-id
                                    for alertParam in (
                                        'payload',
                                        'payload-printable',
                                        'packet',
                                        'http-body',
                                        'http-body-printable',
                                    ):
                                        cfg['outputs'][outputIdx][name]['types'][dumperIdx][dumperName][
                                            alertParam
                                        ] = False

                                elif dumperName == 'anomaly':
                                    for cfgKey in (
                                        [dumperName, 'types', 'decode', 'ANOMALY_DECODE'],
                                        [dumperName, 'types', 'stream', 'ANOMALY_STREAM'],
                                        [dumperName, 'types', 'applayer', 'ANOMALY_APPLAYER'],
                                        [dumperName, 'types', 'packethdr', 'ANOMALY_PACKETHDR'],
                                    ):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'dns':
                                    for cfgKey in (
                                        [dumperName, 'requests', 'DNS_REQUESTS'],
                                        [dumperName, 'responses', 'DNS_RESPONSES'],
                                        [dumperName, 'types', 'DNS_TYPES'],
                                        [dumperName, 'formats', 'DNS_FORMATS'],
                                    ):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'dhcp':
                                    for cfgKey in ([dumperName, 'extended', 'DHCP_EXTENDED'],):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'http':
                                    for cfgKey in (
                                        [dumperName, 'extended', 'HTTP_EXTENDED'],
                                        [dumperName, 'custom', 'HTTP_CUSTOM'],
                                        [dumperName, 'dump-all-headers', 'HTTP_DUMP_ALL_HEADERS'],
                                    ):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'files':
                                    for cfgKey in (
                                        [dumperName, 'force-magic', 'FILES_FORCE_MAGIC'],
                                        [dumperName, 'force-hash', 'FILES_FORCE_HASH'],
                                    ):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'mqtt':
                                    for cfgKey in ([dumperName, 'passwords', 'MQTT_PASSWORDS'],):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'smtp':
                                    for cfgKey in (
                                        [dumperName, 'extended', 'SMTP_EXTENDED'],
                                        [dumperName, 'custom', 'SMTP_CUSTOM'],
                                        [dumperName, 'md5', 'SMTP_MD5'],
                                    ):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                                elif dumperName == 'tls':
                                    for cfgKey in (
                                        [dumperName, 'extended', 'TLS_EXTENDED'],
                                        [dumperName, 'session-resumption', 'TLS_SESSION_RESUMPTION'],
                                        [dumperName, 'custom', 'TLS_CUSTOM'],
                                    ):
                                        deep_set(
                                            cfg['outputs'][outputIdx][name]['types'][dumperIdx],
                                            cfgKey[:-1],
                                            DEFAULT_VARS[cfgKey[-1]],
                                            deleteIfNone=True,
                                        )

                        else:
                            # eve.json alert type is scalar
                            dumperName = cfg['outputs'][outputIdx][name]['types'][dumperIdx]
                            remainingTypes.discard(dumperName)
                            if not PROTOCOL_CONFIGS[dumperName].enabled:
                                # we "disable" these types by removing them from the list
                                del cfg['outputs'][outputIdx][name]['types'][dumperIdx]

                    # handle the eve.json alert types that weren't handled above (were probably
                    # commented-out/missing and need to be added back in)
                    for dumperName in [x for x in list(remainingTypes) if PROTOCOL_CONFIGS[x].enabled]:
                        cfg['outputs'][outputIdx][name]['types'].append(dumperName)

    # somewhat related to what we just did for the eve-log outputs, configure the app-layer.protocols
    # parameters for the various protocols
    remainingTypes = []
    for protocol, config in cfg['app-layer']['protocols'].items():
        if isinstance(config, dict):
            if PROTOCOL_CONFIGS[protocol].subs:
                for sub in PROTOCOL_CONFIGS[protocol].subs:
                    deep_set(
                        cfg['app-layer']['protocols'],
                        [protocol, sub, 'enabled'],
                        PROTOCOL_CONFIGS[protocol].enabled,
                    )
            else:
                deep_set(
                    cfg['app-layer']['protocols'],
                    [protocol, 'enabled'],
                    PROTOCOL_CONFIGS[protocol].enabled,
                )
            if PROTOCOL_CONFIGS[protocol].destination_ports is not None:
                deep_set(
                    cfg['app-layer']['protocols'],
                    [protocol, 'detection-ports', 'dp'],
                    PROTOCOL_CONFIGS[protocol].destination_ports,
                )
            if PROTOCOL_CONFIGS[protocol].source_ports is not None:
                deep_set(
                    cfg['app-layer']['protocols'],
                    [protocol, 'detection-ports', 'sp'],
                    PROTOCOL_CONFIGS[protocol].source_ports,
                )
        else:
            remainingTypes.append(protocol)

    for protocol in remainingTypes:
        cfg['app-layer']['protocols'].pop(protocol, None)
        deep_set(
            cfg['app-layer']['protocols'],
            [protocol, 'enabled'],
            PROTOCOL_CONFIGS[protocol].enabled,
        )
        if PROTOCOL_CONFIGS[protocol].destination_ports is not None:
            deep_set(
                cfg['app-layer']['protocols'],
                [protocol, 'detection-ports', 'dp'],
                PROTOCOL_CONFIGS[protocol].destination_ports,
            )
        if PROTOCOL_CONFIGS[protocol].source_ports is not None:
            deep_set(
                cfg['app-layer']['protocols'],
                [protocol, 'detection-ports', 'sp'],
                PROTOCOL_CONFIGS[protocol].source_ports,
            )

    # similarly, handle the decoders
    remainingTypes = []
    for decoder, config in cfg['decoder'].items():
        if isinstance(config, dict):
            if DECODER_CONFIGS[decoder].subs:
                for sub in DECODER_CONFIGS[decoder].subs:
                    deep_set(
                        cfg['decoder'],
                        [decoder, sub, 'enabled'],
                        DECODER_CONFIGS[decoder].enabled,
                    )
            else:
                deep_set(
                    cfg['decoder'],
                    [decoder, 'enabled'],
                    DECODER_CONFIGS[decoder].enabled,
                )
            if DECODER_CONFIGS[decoder].destination_ports is not None:
                deep_set(
                    cfg['decoder'],
                    [decoder, 'ports'],
                    DECODER_CONFIGS[decoder].destination_ports,
                )
        else:
            remainingTypes.append(decoder)

    for decoder in remainingTypes:
        cfg['decoder'].pop(decoder, None)
        deep_set(
            cfg['decoder'],
            [decoder, 'enabled'],
            DECODER_CONFIGS[decoder].enabled,
        )
        if DECODER_CONFIGS[decoder].destination_ports is not None:
            deep_set(
                cfg['decoder'],
                [decoder, 'ports'],
                DECODER_CONFIGS[decoder].destination_ports,
            )

    # remaining protocol-related settings and global-settings not in the eve-log section
    for cfgKey in (
        ['app-layer', 'protocols', 'ftp', 'memcap', 'FTP_MEMCAP'],
        ['app-layer', 'protocols', 'mqtt', 'max-msg-length', 'MQTT_MAX_MSG_LENGTH'],
        ['app-layer', 'protocols', 'modbus', 'stream-depth', 'MODBUS_STREAM_DEPTH'],
        ['app-layer', 'protocols', 'smb', 'stream-depth', 'SMB_STREAM_DEPTH'],
        ['app-layer', 'protocols', 'smtp', 'raw-extraction', 'SMTP_RAW_EXTRACTION'],
        ['app-layer', 'protocols', 'smtp', 'mime', 'decode-mime', 'SMTP_DECODE_MIME'],
        ['app-layer', 'protocols', 'smtp', 'mime', 'decode-base64', 'SMTP_DECODE_BASE64'],
        [
            'app-layer',
            'protocols',
            'smtp',
            'mime',
            'decode-quoted-printable',
            'SMTP_DECODE_QUOTED_PRINTABLE',
        ],
        ['app-layer', 'protocols', 'smtp', 'mime', 'header-value-depth', 'SMTP_HEADER_VALUE_DEPTH'],
        ['app-layer', 'protocols', 'smtp', 'mime', 'extract-urls', 'SMTP_EXTRACT_URLS'],
        ['app-layer', 'protocols', 'smtp', 'mime', 'body-md5', 'SMTP_BODY_MD5'],
        [
            'app-layer',
            'protocols',
            'smtp',
            'inspected-tracker',
            'content-limit',
            'SMTP_INSPECTED_TRACKER_CONTENT_LIMIT',
        ],
        [
            'app-layer',
            'protocols',
            'smtp',
            'inspected-tracker',
            'content-inspect-min-size',
            'SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_MIN_SIZE',
        ],
        [
            'app-layer',
            'protocols',
            'smtp',
            'inspected-tracker',
            'content-inspect-window',
            'SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_WINDOW',
        ],
        ['app-layer', 'protocols', 'ssh', 'hassh', 'SSH_HASSH'],
        ['app-layer', 'protocols', 'tls', 'ja3-fingerprints', 'TLS_JA3'],
        ['app-layer', 'protocols', 'tls', 'encryption-handling', 'TLS_ENCRYPTION_HANDLING'],
        ['runmode', 'RUNMODE'],
        ['autofp-scheduler', 'AUTOFP_SCHEDULER'],
        ['default-packet-size', 'PACKET_SIZE'],
        ['asn1-max-frames', 'ASN1_MAX_FRAMES'],
        ['pcre', 'match-limit', 'PCRE_MATCH_LIMIT'],
        ['pcre', 'match-limit-recursion', 'PCRE_RECURSION'],
        ['defrag', 'memcap', 'DEFRAG_MEMCAP'],
        ['defrag', 'hash-size', 'DEFRAG_HASH_SIZE'],
        ['defrag', 'trackers', 'DEFRAG_TRACKERS'],
        ['defrag', 'max-frags', 'DEFRAG_MAX_FRAGS'],
        ['defrag', 'prealloc', 'DEFRAG_PREALLOC'],
        ['defrag', 'timeout', 'DEFRAG_TIMEOUT'],
        ['flow', 'memcap', 'FLOW_MEMCAP'],
        ['flow', 'hash-size', 'FLOW_HASH_SIZE'],
        ['flow', 'prealloc', 'FLOW_PREALLOC'],
        ['flow', 'emergency-recovery', 'FLOW_EMERGENCY_RECOVERY'],
        ['vlan', 'use-for-tracking', 'VLAN_USE_FOR_TRACKING'],
        ['stream', 'memcap', 'STREAM_MEMCAP'],
        ['stream', 'checksum-validation', 'STREAM_CHECKSUM_VALIDATION'],
        ['stream', 'inline', 'STREAM_INLINE'],
        ['stream', 'reassembly', 'memcap', 'STREAM_REASSEMBLY_MEMCAP'],
        ['stream', 'reassembly', 'depth', 'STREAM_REASSEMBLY_DEPTH'],
        ['stream', 'reassembly', 'toserver-chunk-size', 'STREAM_REASSEMBLY_TOSERVER_CHUNK_SIZE'],
        ['stream', 'reassembly', 'toclient-chunk-size', 'STREAM_REASSEMBLY_TOCLIENT_CHUNK_SIZE'],
        ['stream', 'reassembly', 'randomize-chunk-size', 'STREAM_REASSEMBLY_RANDOMIZE_CHUNK_SIZE'],
        ['host', 'memcap', 'HOST_MEMCAP'],
        ['host', 'hash-size', 'HOST_HASH_SIZE'],
        ['host', 'prealloc', 'HOST_PREALLOC'],
        ['default-rule-path', 'MANAGED_RULES_DIR'],
    ):
        deep_set(
            cfg,
            cfgKey[:-1],
            DEFAULT_VARS[cfgKey[-1]],
        )

    cfg.pop('run-as', None)
    cfg.pop('coredump', None)
    deep_set(cfg, ['coredump', 'max-dump'], 0)

    if DEFAULT_VARS['SUPERVISOR_PATH'] is not None:
        cfg.pop('unix-command', None)
        deep_set(cfg, ['unix-command', 'enabled'], True)
        deep_set(
            cfg,
            ['unix-command', 'filename'],
            os.path.join(DEFAULT_VARS['SUPERVISOR_PATH'], os.path.join('suricata', 'suricata-command.socket')),
        )

    ##################################################################################################
    # write output YAML
    if os.path.isfile(args.output) and os.path.samefile(args.input, args.output):
        backupFile = inFileParts[0] + "_bak" + inFileParts[1]
        MoveFile(args.input, backupFile)

    with open(args.output, 'w') as outfile:
        outYaml = YAML(typ='rt')
        outYaml.preserve_quotes = False
        outYaml.representer.ignore_aliases = lambda x: True
        outYaml.boolean_representation = ['no', 'yes']
        outYaml.version = (1, 1)
        outYaml.dump(cfg, outfile)


###################################################################################################
if __name__ == '__main__':
    main()
