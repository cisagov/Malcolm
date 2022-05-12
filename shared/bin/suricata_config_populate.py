#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

# modify suricata.yaml according to many environment variables

#
# suricata.yaml: https://suricata.readthedocs.io/en/suricata-6.0.0/configuration/suricata-yaml.html
#                https://github.com/OISF/suricata/blob/master/suricata.yaml.in
#
#

import argparse
import contextlib
import fnmatch
import logging
import os
import sys
import time
import tempfile

from collections import defaultdict, namedtuple
from collections.abc import Iterable
from io import StringIO
from ruamel.yaml import YAML
from shutil import move as MoveFile, copyfile as CopyFile
from subprocess import PIPE, Popen

###################################################################################################
args = None
script_return_code = 0
script_name = os.path.basename(__file__)
script_path = os.path.dirname(os.path.realpath(__file__))
orig_path = os.getcwd()

###################################################################################################
YAML_VERSION = (1, 1)
BACKUP_FILES_MAX = 10

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
@contextlib.contextmanager
def pushd(directory):
    prevDir = os.getcwd()
    os.chdir(directory)
    try:
        yield
    finally:
        os.chdir(prevDir)


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
# run command with arguments and return its exit code, stdout, and stderr
def check_output_input(*popenargs, **kwargs):

    if 'stdout' in kwargs:
        raise ValueError('stdout argument not allowed, it will be overridden')

    if 'stderr' in kwargs:
        raise ValueError('stderr argument not allowed, it will be overridden')

    if 'input' in kwargs and kwargs['input']:
        if 'stdin' in kwargs:
            raise ValueError('stdin and input arguments may not both be used')
        inputdata = kwargs['input']
        kwargs['stdin'] = PIPE
    else:
        inputdata = None
    kwargs.pop('input', None)

    process = Popen(*popenargs, stdout=PIPE, stderr=PIPE, **kwargs)
    try:
        output, errput = process.communicate(input=inputdata)
    except:
        process.kill()
        process.wait()
        raise

    retcode = process.poll()

    return retcode, output, errput


###################################################################################################
# run command with arguments and return its exit code and output
def run_process(command, stdout=True, stderr=True, stdin=None, cwd=None, env=None):

    retcode = -1
    output = []

    try:
        # run the command
        retcode, cmdout, cmderr = check_output_input(command, input=stdin.encode() if stdin else None, cwd=cwd, env=env)

        # split the output on newlines to return a list
        if stderr and (len(cmderr) > 0):
            output.extend(cmderr.decode(sys.getdefaultencoding()).split('\n'))
        if stdout and (len(cmdout) > 0):
            output.extend(cmdout.decode(sys.getdefaultencoding()).split('\n'))

    except (FileNotFoundError, OSError, IOError) as e:
        if stderr:
            output.append("Command {} not found or unable to execute".format(command))

    logging.debug(
        "{}{} returned {}: {}".format(
            command, "({})".format(stdin[:80] + bool(stdin[80:]) * '...' if stdin else ""), retcode, output
        )
    )

    return retcode, output


###################################################################################################
# run command with arguments and return its exit code and output
class NullRepresenter:
    def __call__(self, repr, data):
        ret_val = repr.represent_scalar(u'tag:yaml.org,2002:null', u'')
        return ret_val


###################################################################################################
def ObjToYamlStrLines(obj, options=None):
    outputStr = None
    if options == None:
        options = {}

    yaml = YAML()
    yaml.preserve_quotes = False
    yaml.representer.ignore_aliases = lambda x: True
    yaml.representer.add_representer(type(None), NullRepresenter())
    yaml.boolean_representation = ['no', 'yes']
    yaml.version = YAML_VERSION

    with StringIO() as stringStream:
        yaml.dump(obj, stringStream, **options)
        outputStr = stringStream.getvalue()

    return outputStr.splitlines()


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
        'ANOMALY_ENABLED': False,
        'ANOMALY_EVE_ENABLED': False,
        'ANOMALY_PACKETHDR': False,
        'ANOMALY_STREAM': False,
        'ASN1_MAX_FRAMES': 256,
        'AUTOFP_SCHEDULER': 'hash',
        'CAPTURE_CHECKSUM_VALIDATION': 'none',
        'CAPTURE_DISABLE_OFFLOADING': True,
        'CUSTOM_RULES_ONLY': False,
        'DCERPC_ENABLED': True,
        'DCERPC_EVE_ENABLED': False,
        'DEFRAG_HASH_SIZE': 65536,
        'DEFRAG_MAX_FRAGS': 65535,
        'DEFRAG_MEMCAP': '32mb',
        'DEFRAG_PREALLOC': True,
        'DEFRAG_TIMEOUT': 60,
        'DEFRAG_TRACKERS': 65535,
        'DHCP_ENABLED': True,
        'DHCP_EVE_ENABLED': False,
        'DHCP_EXTENDED': False,
        'DNP3_ENABLED': True,
        'DNP3_EVE_ENABLED': False,
        'DNP3_PORTS': 20000,
        'DNS_ENABLED': True,
        'DNS_EVE_ENABLED': False,
        'DNS_PORTS': 53,
        'DNS_REQUESTS': True,
        'DNS_RESPONSES': True,
        'DNS_VERSION': 2,
        'ENIP_ENABLED': True,
        'ENIP_EVE_ENABLED': False,
        'ENIP_PORTS': 44818,
        'EXTERNAL_NET': '!$HOME_NET',
        'FILE_DATA_PORTS': "[$HTTP_PORTS,110,143]",
        'FILES_ENABLED': True,
        'FILES_EVE_ENABLED': False,
        'FILES_FORCE_MAGIC': False,
        'FLOW_EMERGENCY_RECOVERY': 30,
        'FLOW_ENABLED': False,
        'FLOW_EVE_ENABLED': False,
        'FLOW_HASH_SIZE': 65536,
        'FLOW_MEMCAP': '128mb',
        'FLOW_PREALLOC': 10000,
        'FTP_ENABLED': True,
        'FTP_EVE_ENABLED': False,
        'FTP_MEMCAP': '64mb',
        'FTP_PORTS': 21,
        'GENEVE_ENABLED': False,
        'GENEVE_EVE_ENABLED': False,
        'GENEVE_PORTS': 6081,
        'HOME_NET': "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]",
        'HOST_HASH_SIZE': 4096,
        'HOST_MEMCAP': '32mb',
        'HOST_PREALLOC': 1000,
        'HTTP2_ENABLED': False,
        'HTTP2_EVE_ENABLED': False,
        'HTTP_ENABLED': True,
        'HTTP_EVE_ENABLED': False,
        'HTTP_EXTENDED': False,
        'HTTP_PORTS': 80,
        'IKEV2_ENABLED': True,
        'IKEV2_EVE_ENABLED': False,
        'IMAP_ENABLED': 'detection-only',
        'IMAP_EVE_ENABLED': False,
        'KRB5_ENABLED': True,
        'KRB5_EVE_ENABLED': False,
        'MANAGED_RULES_DIR': '/var/lib/suricata/rules',
        'MODBUS_ENABLED': True,
        'MODBUS_EVE_ENABLED': False,
        'MODBUS_PORTS': 502,
        'MODBUS_STREAM_DEPTH': 0,
        'MQTT_ENABLED': True,
        'MQTT_EVE_ENABLED': False,
        'MQTT_MAX_MSG_LENGTH': '1mb',
        'MQTT_PASSWORDS': False,
        'NETFLOW_ENABLED': False,
        'NETFLOW_EVE_ENABLED': False,
        'NFS_ENABLED': True,
        'NFS_EVE_ENABLED': False,
        'NTP_ENABLED': True,
        'NTP_EVE_ENABLED': False,
        'ORACLE_PORTS': 1521,
        'PACKET_SIZE': 1514,
        'PCRE_MATCH_LIMIT': 3500,
        'PCRE_RECURSION': 1500,
        'RDP_ENABLED': True,
        'RDP_EVE_ENABLED': False,
        'RFB_ENABLED': True,
        'RFB_EVE_ENABLED': False,
        'RFB_PORTS': "[5900,5901,5902,5903,5904,5905,5906,5907,5908,5909]",
        'RUNMODE': 'autofp',
        'SHELLCODE_PORTS': '!80',
        'SIP_ENABLED': True,
        'SIP_EVE_ENABLED': False,
        'SMB_ENABLED': True,
        'SMB_EVE_ENABLED': False,
        'SMB_PORTS': "[139,445]",
        'SMB_STREAM_DEPTH': 0,
        'SMTP_BODY_MD5': False,
        'SMTP_DECODE_BASE64': False,
        'SMTP_DECODE_MIME': False,
        'SMTP_DECODE_QUOTED_PRINTABLE': False,
        'SMTP_ENABLED': True,
        'SMTP_EVE_ENABLED': False,
        'SMTP_EXTENDED': False,
        'SMTP_EXTRACT_URLS': True,
        'SMTP_HEADER_VALUE_DEPTH': 2000,
        'SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_MIN_SIZE': 32768,
        'SMTP_INSPECTED_TRACKER_CONTENT_INSPECT_WINDOW': 4096,
        'SMTP_INSPECTED_TRACKER_CONTENT_LIMIT': 100000,
        'SMTP_RAW_EXTRACTION': False,
        'SNMP_ENABLED': True,
        'SNMP_EVE_ENABLED': False,
        'SSH_ENABLED': True,
        'SSH_EVE_ENABLED': False,
        'SSH_HASSH': True,
        'SSH_PORTS': 22,
        'STREAM_CHECKSUM_VALIDATION': False,
        'STREAM_INLINE': 'auto',
        'STREAM_MEMCAP': '64mb',
        'STREAM_REASSEMBLY_DEPTH': '1mb',
        'STREAM_REASSEMBLY_MEMCAP': '256mb',
        'STREAM_REASSEMBLY_RANDOMIZE_CHUNK_SIZE': True,
        'STREAM_REASSEMBLY_TOCLIENT_CHUNK_SIZE': 2560,
        'STREAM_REASSEMBLY_TOSERVER_CHUNK_SIZE': 2560,
        'TEREDO_ENABLED': True,
        'TEREDO_EVE_ENABLED': False,
        'TEREDO_PORTS': 3544,
        'TEST_CONFIG_VERBOSITY': '',
        'TFTP_ENABLED': True,
        'TFTP_EVE_ENABLED': False,
        'TLS_ENABLED': True,
        'TLS_EVE_ENABLED': False,
        'TLS_ENCRYPTION_HANDLING': 'bypass',
        'TLS_EXTENDED': False,
        'TLS_JA3': 'auto',
        'TLS_PORTS': 443,
        'TLS_SESSION_RESUMPTION': False,
        'VLAN_USE_FOR_TRACKING': True,
        'VXLAN_ENABLED': True,
        'VXLAN_EVE_ENABLED': False,
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
ProtocolConfig = namedtuple(
    "ProtocolConfig", ["subs", "enabled", "eve_enabled", "in_eve", "destination_ports", "source_ports"], rename=False
)
PROTOCOL_CONFIGS = defaultdict(
    lambda: ProtocolConfig(
        [],
        True,
        False,
        True,
        None,
        None,
    )
)
PROTOCOL_CONFIGS.update(
    {
        'anomaly': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['ANOMALY_ENABLED']),
            val2bool(DEFAULT_VARS['ANOMALY_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'dcerpc': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['DCERPC_ENABLED']),
            val2bool(DEFAULT_VARS['DCERPC_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'dhcp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['DHCP_ENABLED']),
            val2bool(DEFAULT_VARS['DHCP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'dnp3': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['DNP3_ENABLED']),
            val2bool(DEFAULT_VARS['DNP3_EVE_ENABLED']),
            True,
            DEFAULT_VARS['DNP3_PORTS'],
            None,
        ),
        'dns': ProtocolConfig(
            ['tcp', 'udp'],
            val2bool(DEFAULT_VARS['DNS_ENABLED']),
            val2bool(DEFAULT_VARS['DNS_EVE_ENABLED']),
            True,
            DEFAULT_VARS['DNS_PORTS'],
            None,
        ),
        'enip': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['ENIP_ENABLED']),
            val2bool(DEFAULT_VARS['ENIP_EVE_ENABLED']),
            False,
            DEFAULT_VARS['ENIP_PORTS'],
            DEFAULT_VARS['ENIP_PORTS'],
        ),
        'files': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['FILES_ENABLED']),
            val2bool(DEFAULT_VARS['FILES_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'flow': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['FLOW_ENABLED']),
            val2bool(DEFAULT_VARS['FLOW_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'ftp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['FTP_ENABLED']),
            val2bool(DEFAULT_VARS['FTP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'http2': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['HTTP2_ENABLED']),
            val2bool(DEFAULT_VARS['HTTP2_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'http': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['HTTP_ENABLED']),
            val2bool(DEFAULT_VARS['HTTP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'ikev2': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['IKEV2_ENABLED']),
            val2bool(DEFAULT_VARS['IKEV2_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'imap': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['IMAP_ENABLED']),
            val2bool(DEFAULT_VARS['IMAP_EVE_ENABLED']),
            False,
            None,
            None,
        ),
        'krb5': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['KRB5_ENABLED']),
            val2bool(DEFAULT_VARS['KRB5_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'modbus': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['MODBUS_ENABLED']),
            val2bool(DEFAULT_VARS['MODBUS_EVE_ENABLED']),
            False,
            DEFAULT_VARS['MODBUS_PORTS'],
            None,
        ),
        'mqtt': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['MQTT_ENABLED']),
            val2bool(DEFAULT_VARS['MQTT_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'netflow': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['NETFLOW_ENABLED']),
            val2bool(DEFAULT_VARS['NETFLOW_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'nfs': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['NFS_ENABLED']),
            val2bool(DEFAULT_VARS['NFS_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'ntp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['NTP_ENABLED']),
            val2bool(DEFAULT_VARS['NTP_EVE_ENABLED']),
            False,
            None,
            None,
        ),
        'rdp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['RDP_ENABLED']),
            val2bool(DEFAULT_VARS['RDP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'rfb': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['RFB_ENABLED']),
            val2bool(DEFAULT_VARS['RFB_EVE_ENABLED']),
            True,
            DEFAULT_VARS['RFB_PORTS'],
            None,
        ),
        'sip': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['SIP_ENABLED']),
            val2bool(DEFAULT_VARS['SIP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'smb': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['SMB_ENABLED']),
            val2bool(DEFAULT_VARS['SMB_EVE_ENABLED']),
            True,
            DEFAULT_VARS['SMB_PORTS'],
            None,
        ),
        'smtp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['SMTP_ENABLED']),
            val2bool(DEFAULT_VARS['SMTP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'snmp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['SNMP_ENABLED']),
            val2bool(DEFAULT_VARS['SNMP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'ssh': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['SSH_ENABLED']),
            val2bool(DEFAULT_VARS['SSH_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'tftp': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['TFTP_ENABLED']),
            val2bool(DEFAULT_VARS['TFTP_EVE_ENABLED']),
            True,
            None,
            None,
        ),
        'tls': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['TLS_ENABLED']),
            val2bool(DEFAULT_VARS['TLS_EVE_ENABLED']),
            True,
            DEFAULT_VARS['TLS_PORTS'],
            None,
        ),
    }
)
DECODER_CONFIGS = defaultdict(lambda: ProtocolConfig([], True, False, False, None, None))
DECODER_CONFIGS.update(
    {
        'teredo': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['TEREDO_ENABLED']),
            False,
            False,
            DEFAULT_VARS['TEREDO_PORTS'],
            None,
        ),
        'vxlan': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['VXLAN_ENABLED']),
            False,
            False,
            DEFAULT_VARS['VXLAN_PORTS'],
            None,
        ),
        'geneve': ProtocolConfig(
            [],
            val2bool(DEFAULT_VARS['GENEVE_ENABLED']),
            False,
            False,
            DEFAULT_VARS['GENEVE_PORTS'],
            None,
        ),
    }
)

###################################################################################################
def GetRuleSources(requireRulesExist=False):
    global DEFAULT_VARS

    ruleSources = []

    if val2bool(DEFAULT_VARS['CUSTOM_RULES_ONLY']) == False:
        ruleSources.append('suricata.rules')

    customRuleFiles = (
        fnmatch.filter(os.listdir(DEFAULT_VARS['CUSTOM_RULES_DIR']), '*.rules')
        if DEFAULT_VARS['CUSTOM_RULES_DIR'] is not None
        else []
    )

    if (DEFAULT_VARS['CUSTOM_RULES_DIR'] is not None) and ((requireRulesExist == False) or (len(customRuleFiles) > 0)):
        ruleSources.append(os.path.join(DEFAULT_VARS['CUSTOM_RULES_DIR'], '*.rules'))

    return ruleSources


###################################################################################################
def main():
    global args
    global DEFAULT_VARS
    global PROTOCOL_CONFIGS
    global DECODER_CONFIGS

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
    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=1,
        help='Increase verbosity (e.g., -v, -vv, etc.)',
    )
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
            os.path.join(os.path.join(os.getenv('SUPERVISOR_PATH', '/etc'), 'suricata'), 'suricata.yaml'),
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

    argsOrigVerbose = args.verbose
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
    # back up the old YAML file if we need to first
    if os.path.isfile(args.output) and os.path.samefile(args.input, args.output):
        backupFile = inFileParts[0] + "_bak_" + str(int(round(time.time()))) + inFileParts[1]
        CopyFile(args.input, backupFile)
        backupFiles = sorted(fnmatch.filter(os.listdir(os.path.dirname(backupFile)), '*_bak_*'))
        while len(backupFiles) > BACKUP_FILES_MAX:
            toDeleteFileName = os.path.join(os.path.dirname(backupFile), backupFiles.pop(0))
            logging.debug(f'Removing old backup file "{toDeleteFileName}"')
            os.remove(toDeleteFileName)

    ##################################################################################################
    # load input YAML
    cfg = None
    if args.input and os.path.isfile(args.input):
        with open(args.input, 'r') as f:
            inYaml = YAML(typ='rt')
            inYaml.preserve_quotes = False
            inYaml.emitter.alt_null = None
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
                                    (dumperName == 'alert')
                                    or (
                                        PROTOCOL_CONFIGS[dumperName].enabled
                                        and PROTOCOL_CONFIGS[dumperName].eve_enabled
                                    ),
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
                                        [dumperName, 'version', 'DNS_VERSION'],
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
                            if (
                                (not PROTOCOL_CONFIGS[dumperName].enabled)
                                or (not PROTOCOL_CONFIGS[dumperName].eve_enabled)
                                or (not PROTOCOL_CONFIGS[dumperName].in_eve)
                            ):
                                # we "disable" these types by removing them from the list
                                del cfg['outputs'][outputIdx][name]['types'][dumperIdx]

                    # handle the eve.json alert types that weren't handled above (were probably
                    # commented-out/missing and need to be added back in)
                    for dumperName in [
                        x
                        for x in list(remainingTypes)
                        if PROTOCOL_CONFIGS[x].enabled
                        and PROTOCOL_CONFIGS[x].eve_enabled
                        and PROTOCOL_CONFIGS[x].in_eve
                    ]:
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
            os.path.join(os.path.join(DEFAULT_VARS['SUPERVISOR_PATH'], 'suricata'), 'suricata-command.socket'),
        )

    # validate suricata execution prior to calling it a day
    with tempfile.TemporaryDirectory() as tmpLogDir:
        with pushd(tmpLogDir):
            deep_set(cfg, ['stats', 'enabled'], True)
            cfg.pop('rule-files', None)
            deep_set(cfg, ['rule-files'], GetRuleSources(requireRulesExist=True))
            with open('suricata.yaml', 'w') as outTestFile:
                outTestYaml = YAML(typ='rt')
                outTestYaml.preserve_quotes = False
                outTestYaml.representer.ignore_aliases = lambda x: True
                outTestYaml.representer.add_representer(type(None), NullRepresenter())
                outTestYaml.boolean_representation = ['no', 'yes']
                outTestYaml.version = YAML_VERSION
                outTestYaml.dump(cfg, outTestFile)
            script_return_code, output = run_process(
                [
                    'suricata',
                    f"-{('v' * (argsOrigVerbose-1)) if (argsOrigVerbose > 1) else 'v'}",
                    '-c',
                    os.path.join(tmpLogDir, 'suricata.yaml'),
                    '-l',
                    tmpLogDir,
                    '-T',
                ]
            )
            logging.info(f'suricata configuration test returned {script_return_code}')
            if script_return_code != 0:
                logging.error(output)

    # final tweaks
    deep_set(cfg, ['stats', 'enabled'], False)
    cfg.pop('rule-files', None)
    deep_set(cfg, ['rule-files'], GetRuleSources(requireRulesExist=False))

    ##################################################################################################

    # write the new YAML file
    with open(args.output, 'w') as outfile:
        outYaml = YAML(typ='rt')
        outYaml.preserve_quotes = False
        outYaml.representer.ignore_aliases = lambda x: True
        outYaml.representer.add_representer(type(None), NullRepresenter())
        outYaml.boolean_representation = ['no', 'yes']
        outYaml.version = YAML_VERSION
        outYaml.dump(cfg, outfile)

    ##################################################################################################

    # remove the pidfile and command file for a new run (in case they weren't cleaned up before)
    if DEFAULT_VARS['SUPERVISOR_PATH'] is not None and os.path.isdir(
        os.path.join(DEFAULT_VARS['SUPERVISOR_PATH'], 'suricata')
    ):
        try:
            os.remove(os.path.join(os.path.join(DEFAULT_VARS['SUPERVISOR_PATH'], 'suricata'), 'suricata.pid'))
        except:
            pass
        try:
            os.remove(
                os.path.join(os.path.join(DEFAULT_VARS['SUPERVISOR_PATH'], 'suricata'), 'suricata-command.socket')
            )
        except:
            pass


###################################################################################################
if __name__ == '__main__':
    main()
    sys.exit(script_return_code)
