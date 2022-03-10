#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

import argparse
import datetime
import fileinput
import getpass
import glob
import json
import os
import platform
import pprint
import math
import re
import shutil
import sys
import tarfile
import tempfile
import time

try:
    from pwd import getpwuid
except ImportError:
    getpwuid = None
from collections import defaultdict, namedtuple

from malcolm_common import *

###################################################################################################
DOCKER_COMPOSE_INSTALL_VERSION = "1.27.4"

DEB_GPG_KEY_FINGERPRINT = '0EBFCD88'  # used to verify GPG key for Docker Debian repository

MAC_BREW_DOCKER_PACKAGE = 'docker-edge'
MAC_BREW_DOCKER_SETTINGS = '/Users/{}/Library/Group Containers/group.com.docker/settings.json'

###################################################################################################
ScriptName = os.path.basename(__file__)
origPath = os.getcwd()

###################################################################################################
args = None

###################################################################################################
# get interactive user response to Y/N question
def InstallerYesOrNo(question, default=None, forceInteraction=False):
    global args
    return YesOrNo(question, default=default, forceInteraction=forceInteraction, acceptDefault=args.acceptDefaults)


###################################################################################################
# get interactive user response
def InstallerAskForString(question, default=None, forceInteraction=False):
    global args
    return AskForString(question, default=default, forceInteraction=forceInteraction, acceptDefault=args.acceptDefaults)


def TrueOrFalseQuote(expression):
    return "'{}'".format('true' if expression else 'false')


###################################################################################################
class Installer(object):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, debug=False, configOnly=False):
        self.debug = debug
        self.configOnly = configOnly

        self.platform = platform.system()
        self.scriptUser = getpass.getuser()

        self.checkPackageCmds = []
        self.installPackageCmds = []
        self.requiredPackages = []

        self.pipCmd = 'pip3'
        if not Which(self.pipCmd, debug=self.debug):
            self.pipCmd = 'pip'

        self.tempDirName = tempfile.mkdtemp()

        self.totalMemoryGigs = 0.0
        self.totalCores = 0

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __del__(self):
        shutil.rmtree(self.tempDirName, ignore_errors=True)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def run_process(self, command, stdout=True, stderr=True, stdin=None, privileged=False, retry=0, retrySleepSec=5):

        # if privileged, put the sudo command at the beginning of the command
        if privileged and (len(self.sudoCmd) > 0):
            command = self.sudoCmd + command

        return run_process(
            command,
            stdout=stdout,
            stderr=stderr,
            stdin=stdin,
            retry=retry,
            retrySleepSec=retrySleepSec,
            debug=self.debug,
        )

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def package_is_installed(self, package):
        result = False
        for cmd in self.checkPackageCmds:
            ecode, out = self.run_process(cmd + [package])
            if ecode == 0:
                result = True
                break
        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_package(self, packages):
        result = False
        pkgs = []

        for package in packages:
            if not self.package_is_installed(package):
                pkgs.append(package)

        if len(pkgs) > 0:
            for cmd in self.installPackageCmds:
                ecode, out = self.run_process(cmd + pkgs, privileged=True)
                if ecode == 0:
                    result = True
                    break
        else:
            result = True

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_required_packages(self):
        if len(self.requiredPackages) > 0:
            eprint(f"Installing required packages: {self.requiredPackages}")
        return self.install_package(self.requiredPackages)

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker_images(self, docker_image_file):
        result = False
        if (
            docker_image_file
            and os.path.isfile(docker_image_file)
            and InstallerYesOrNo(
                f'Load Malcolm Docker images from {docker_image_file}', default=True, forceInteraction=True
            )
        ):
            ecode, out = self.run_process(['docker', 'load', '-q', '-i', docker_image_file], privileged=True)
            if ecode == 0:
                result = True
            else:
                eprint(f"Loading Malcolm Docker images failed: {out}")
        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_malcolm_files(self, malcolm_install_file):
        result = False
        installPath = None
        if (
            malcolm_install_file
            and os.path.isfile(malcolm_install_file)
            and InstallerYesOrNo(
                f'Extract Malcolm runtime files from {malcolm_install_file}', default=True, forceInteraction=True
            )
        ):

            # determine and create destination path for installation
            while True:
                defaultPath = os.path.join(origPath, 'malcolm')
                installPath = InstallerAskForString(
                    f'Enter installation path for Malcolm [{defaultPath}]', default=defaultPath, forceInteraction=True
                )
                if len(installPath) == 0:
                    installPath = defaultPath
                if os.path.isdir(installPath):
                    eprint(f"{installPath} already exists, please specify a different installation path")
                else:
                    try:
                        os.makedirs(installPath)
                    except:
                        pass
                    if os.path.isdir(installPath):
                        break
                    else:
                        eprint(f"Failed to create {installPath}, please specify a different installation path")

            # extract runtime files
            if installPath and os.path.isdir(installPath):
                if self.debug:
                    eprint(f"Created {installPath} for Malcolm runtime files")
                tar = tarfile.open(malcolm_install_file)
                try:
                    tar.extractall(path=installPath, numeric_owner=True)
                finally:
                    tar.close()

                # .tar.gz normally will contain an intermediate subdirectory. if so, move files back one level
                childDir = glob.glob(f'{installPath}/*/')
                if (len(childDir) == 1) and os.path.isdir(childDir[0]):
                    if self.debug:
                        eprint(f"{installPath} only contains {childDir[0]}")
                    for f in os.listdir(childDir[0]):
                        shutil.move(os.path.join(childDir[0], f), installPath)
                    shutil.rmtree(childDir[0], ignore_errors=True)

                # verify the installation worked
                if os.path.isfile(os.path.join(installPath, "docker-compose.yml")):
                    eprint(f"Malcolm runtime files extracted to {installPath}")
                    result = True
                    with open(os.path.join(installPath, "install_source.txt"), 'w') as f:
                        f.write(
                            f'{os.path.basename(malcolm_install_file)} (installed {str(datetime.datetime.now())})\n'
                        )
                else:
                    eprint(f"Malcolm install file extracted to {installPath}, but missing runtime files?")

        return result, installPath

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def tweak_malcolm_runtime(
        self,
        malcolm_install_path,
        expose_opensearch_default=False,
        expose_logstash_default=False,
        restart_mode_default=False,
    ):
        global args

        if not args.configFile:
            # get a list of all of the docker-compose files
            composeFiles = glob.glob(os.path.join(malcolm_install_path, 'docker-compose*.yml'))

        elif os.path.isfile(args.configFile):
            # single docker-compose file explicitly specified
            composeFiles = [os.path.realpath(args.configFile)]
            malcolm_install_path = os.path.dirname(composeFiles[0])

        # figure out what UID/GID to run non-rood processes under docker as
        puid = '1000'
        pgid = '1000'
        try:
            if self.platform == PLATFORM_LINUX:
                puid = str(os.getuid())
                pgid = str(os.getgid())
                if (puid == '0') or (pgid == '0'):
                    raise Exception('it is preferrable not to run Malcolm as root, prompting for UID/GID instead')
        except:
            puid = '1000'
            pgid = '1000'

        while (
            (not puid.isdigit())
            or (not pgid.isdigit())
            or (
                not InstallerYesOrNo(
                    f'Malcolm processes will run as UID {puid} and GID {pgid}. Is this OK?', default=True
                )
            )
        ):
            puid = InstallerAskForString('Enter user ID (UID) for running non-root Malcolm processes')
            pgid = InstallerAskForString('Enter group ID (GID) for running non-root Malcolm processes')

        # guestimate how much memory we should use based on total system memory

        if self.debug:
            eprint(f"{malcolm_install_path} contains {composeFiles}, system memory is {self.totalMemoryGigs} GiB")

        if self.totalMemoryGigs >= 63.0:
            osMemory = '30g'
            lsMemory = '6g'
        elif self.totalMemoryGigs >= 31.0:
            osMemory = '21g'
            lsMemory = '3500m'
        elif self.totalMemoryGigs >= 15.0:
            osMemory = '10g'
            lsMemory = '3g'
        elif self.totalMemoryGigs >= 11.0:
            osMemory = '6g'
            lsMemory = '2500m'
        elif self.totalMemoryGigs >= 7.0:
            eprint(f"Detected only {self.totalMemoryGigs} GiB of memory; performance will be suboptimal")
            osMemory = '4g'
            lsMemory = '2500m'
        elif self.totalMemoryGigs > 0.0:
            eprint(f"Detected only {self.totalMemoryGigs} GiB of memory; performance will be suboptimal")
            osMemory = '3500m'
            lsMemory = '2g'
        else:
            eprint("Failed to determine system memory size, using defaults; performance may be suboptimal")
            osMemory = '8g'
            lsMemory = '3g'

        # see Tuning and Profiling Logstash Performance
        # - https://www.elastic.co/guide/en/logstash/current/tuning-logstash.html
        # - https://www.elastic.co/guide/en/logstash/current/logstash-settings-file.html
        # - https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html
        # we don't want it too high, as in Malcolm Logstash also competes with OpenSearch, etc. for resources
        if self.totalCores > 16:
            lsWorkers = 12
        elif self.totalCores >= 12:
            lsWorkers = 8
        else:
            lsWorkers = 4

        while not InstallerYesOrNo(
            f'Setting {osMemory} for OpenSearch and {lsMemory} for Logstash. Is this OK?', default=True
        ):
            osMemory = InstallerAskForString('Enter memory for OpenSearch (e.g., 16g, 9500m, etc.)')
            lsMemory = InstallerAskForString('Enter memory for LogStash (e.g., 4g, 2500m, etc.)')

        while (not str(lsWorkers).isdigit()) or (
            not InstallerYesOrNo(f'Setting {lsWorkers} workers for Logstash pipelines. Is this OK?', default=True)
        ):
            lsWorkers = InstallerAskForString('Enter lsWorkers (e.g., 4, 8, etc.)')

        restartMode = None
        allowedRestartModes = ('no', 'on-failure', 'always', 'unless-stopped')
        if InstallerYesOrNo('Restart Malcolm upon system or Docker daemon restart?', default=restart_mode_default):
            while restartMode not in allowedRestartModes:
                restartMode = InstallerAskForString(
                    f'Select Malcolm restart behavior {allowedRestartModes}', default='unless-stopped'
                )
        else:
            restartMode = 'no'
        if restartMode == 'no':
            restartMode = '"no"'

        nginxSSL = InstallerYesOrNo('Require encrypted HTTPS connections?', default=True)
        if not nginxSSL:
            nginxSSL = not InstallerYesOrNo('Unencrypted connections are NOT recommended. Are you sure?', default=False)

        ldapStartTLS = False
        ldapServerType = 'winldap'
        useBasicAuth = not InstallerYesOrNo(
            'Authenticate against Lightweight Directory Access Protocol (LDAP) server?', default=False
        )
        if not useBasicAuth:
            allowedLdapModes = ('winldap', 'openldap')
            ldapServerType = None
            while ldapServerType not in allowedLdapModes:
                ldapServerType = InstallerAskForString(
                    f'Select LDAP server compatibility type {allowedLdapModes}', default='winldap'
                )
            ldapStartTLS = InstallerYesOrNo('Use StartTLS for LDAP connection security?', default=True)
            try:
                with open(
                    os.path.join(os.path.realpath(os.path.join(ScriptPath, "..")), ".ldap_config_defaults"), "w"
                ) as ldapDefaultsFile:
                    print(f"LDAP_SERVER_TYPE='{ldapServerType}'", file=ldapDefaultsFile)
                    print(
                        f"LDAP_PROTO='{'ldap://' if useBasicAuth or ldapStartTLS else 'ldaps://'}'",
                        file=ldapDefaultsFile,
                    )
                    print(f"LDAP_PORT='{3268 if ldapStartTLS else 3269}'", file=ldapDefaultsFile)
            except:
                pass

        indexSnapshotDir = None
        indexSnapshotCompressed = False
        indexSnapshotAge = '0'
        indexColdAge = '0'
        indexCloseAge = '0'
        indexDeleteAge = '0'
        indexPruneSizeLimit = '0'
        indexPruneNameSort = False

        if InstallerYesOrNo('Configure OpenSearch index state management?', default=False):

            # configure snapshots
            if InstallerYesOrNo('Configure index snapshots?', default=False):

                # snapshot repository directory and compression
                indexSnapshotDir = './opensearch-backup'
                if not InstallerYesOrNo(
                    'Store snapshots locally in {}?'.format(os.path.join(malcolm_install_path, 'opensearch-backup')),
                    default=True,
                ):
                    while True:
                        indexSnapshotDir = InstallerAskForString('Enter OpenSearch index snapshot directory')
                        if (len(indexSnapshotDir) > 1) and os.path.isdir(indexSnapshotDir):
                            indexSnapshotDir = os.path.realpath(indexSnapshotDir)
                            break
                indexSnapshotCompressed = InstallerYesOrNo('Compress index snapshots?', default=False)

                # index age for snapshot
                indexSnapshotAge = ''
                while (not re.match(r'^\d+[dhms]$', indexSnapshotAge)) and (indexSnapshotAge != '0'):
                    indexSnapshotAge = InstallerAskForString('Enter index age for snapshot (e.g., 1d)')

            # cold state age
            if InstallerYesOrNo('Mark indices read-only as they age?', default=False):
                indexColdAge = ''
                while (not re.match(r'^\d+[dhms]$', indexColdAge)) and (indexColdAge != '0'):
                    indexColdAge = InstallerAskForString('Enter index age for "read-only" transition (e.g., 30d)')

            # close state age
            if InstallerYesOrNo('Close indices as they age?', default=False):
                indexCloseAge = ''
                while (not re.match(r'^\d+[dhms]$', indexCloseAge)) and (indexCloseAge != '0'):
                    indexCloseAge = InstallerAskForString('Enter index age for "close" transition (e.g., 60d)')

            # delete state age
            if InstallerYesOrNo('Delete indices as they age?', default=False):
                indexDeleteAge = ''
                while (not re.match(r'^\d+[dhms]$', indexDeleteAge)) and (indexDeleteAge != '0'):
                    indexDeleteAge = InstallerAskForString('Enter index age for "delete" transition (e.g., 365d)')

            # delete based on index pattern size
            if InstallerYesOrNo('Delete the oldest indices when the database exceeds a certain size?', default=False):
                indexPruneSizeLimit = ''
                while (not re.match(r'^\d+(\.\d+)?\s*[kmgtp%]?b?$', indexPruneSizeLimit, flags=re.IGNORECASE)) and (
                    indexPruneSizeLimit != '0'
                ):
                    indexPruneSizeLimit = InstallerAskForString('Enter index threshold (e.g., 250GB, 1TB, 60%, etc.)')
                indexPruneNameSort = InstallerYesOrNo(
                    'Determine oldest indices by name (instead of creation time)?', default=True
                )

        autoZeek = InstallerYesOrNo('Automatically analyze all PCAP files with Zeek?', default=True)
        reverseDns = InstallerYesOrNo(
            'Perform reverse DNS lookup locally for source and destination IP addresses in Zeek logs?', default=False
        )
        autoOui = InstallerYesOrNo('Perform hardware vendor OUI lookups for MAC addresses?', default=True)
        autoFreq = InstallerYesOrNo('Perform string randomness scoring on some fields?', default=True)
        opensearchOpen = InstallerYesOrNo(
            'Expose OpenSearch port to external hosts?', default=expose_opensearch_default
        )
        logstashOpen = InstallerYesOrNo('Expose Logstash port to external hosts?', default=expose_logstash_default)
        logstashSsl = logstashOpen and InstallerYesOrNo(
            'Should Logstash require SSL for Zeek logs? (Note: This requires the forwarder to be similarly configured and a corresponding copy of the client SSL files.)',
            default=True,
        )
        externalEsForward = InstallerYesOrNo('Forward Logstash logs to external OpenSearch instance?', default=False)
        if externalEsForward:
            externalEsHost = InstallerAskForString('Enter external OpenSearch host:port (e.g., 10.0.0.123:9200)')
            externalEsSsl = InstallerYesOrNo(f'Connect to "{externalEsHost}" using SSL?', default=True)
            externalEsSslVerify = externalEsSsl and InstallerYesOrNo(
                f'Require SSL certificate validation for communication with "{externalEsHost}"?', default=False
            )
        else:
            externalEsHost = ""
            externalEsSsl = False
            externalEsSslVerify = False

        # input file extraction parameters
        allowedFileCarveModes = ('none', 'known', 'mapped', 'all', 'interesting')
        allowedFilePreserveModes = ('quarantined', 'all', 'none')

        fileCarveModeUser = None
        fileCarveMode = None
        filePreserveMode = None
        vtotApiKey = '0'
        yaraScan = False
        capaScan = False
        clamAvScan = False
        ruleUpdate = False

        if InstallerYesOrNo('Enable file extraction with Zeek?', default=False):
            while fileCarveMode not in allowedFileCarveModes:
                fileCarveMode = InstallerAskForString(
                    f'Select file extraction behavior {allowedFileCarveModes}', default=allowedFileCarveModes[0]
                )
            while filePreserveMode not in allowedFilePreserveModes:
                filePreserveMode = InstallerAskForString(
                    f'Select file preservation behavior {allowedFilePreserveModes}', default=allowedFilePreserveModes[0]
                )
            if fileCarveMode is not None:
                if InstallerYesOrNo('Scan extracted files with ClamAV?', default=False):
                    clamAvScan = True
                if InstallerYesOrNo('Scan extracted files with Yara?', default=False):
                    yaraScan = True
                if InstallerYesOrNo('Scan extracted PE files with Capa?', default=False):
                    capaScan = True
                if InstallerYesOrNo('Lookup extracted file hashes with VirusTotal?', default=False):
                    while len(vtotApiKey) <= 1:
                        vtotApiKey = InstallerAskForString('Enter VirusTotal API key')
                ruleUpdate = InstallerYesOrNo('Download updated scanner signatures periodically?', default=True)

        if fileCarveMode not in allowedFileCarveModes:
            fileCarveMode = allowedFileCarveModes[0]
        if filePreserveMode not in allowedFileCarveModes:
            filePreserveMode = allowedFilePreserveModes[0]
        if (vtotApiKey is None) or (len(vtotApiKey) <= 1):
            vtotApiKey = '0'

        # input packet capture parameters
        pcapNetSniff = False
        pcapTcpDump = False
        pcapIface = 'lo'
        if InstallerYesOrNo('Should Malcolm capture network traffic to PCAP files?', default=False):
            pcapIface = ''
            while len(pcapIface) <= 0:
                pcapIface = InstallerAskForString('Specify capture interface(s) (comma-separated)')
            pcapNetSniff = InstallerYesOrNo('Capture packets using netsniff-ng?', default=True)
            pcapTcpDump = InstallerYesOrNo('Capture packets using tcpdump?', default=(not pcapNetSniff))

        # modify specified values in-place in docker-compose files
        for composeFile in composeFiles:
            # save off owner of original files
            composeFileStat = os.stat(composeFile)
            origUid, origGuid = composeFileStat[4], composeFileStat[5]
            composeFileHandle = fileinput.FileInput(composeFile, inplace=True, backup=None)
            try:
                servicesSectionFound = False
                serviceIndent = None
                currentService = None

                for line in composeFileHandle:
                    line = line.rstrip("\n")
                    skipLine = False

                    # it would be cleaner to use something like PyYAML to do this, but I want to have as few dependencies
                    # as possible so we're going to do it janky instead

                    # determine indentation for each service section (assumes YML file is consistently indented)
                    if (not servicesSectionFound) and line.lower().startswith('services:'):
                        servicesSectionFound = True
                    elif servicesSectionFound and (serviceIndent is None):
                        indentMatch = re.search(r'^(\s+)\S+\s*:\s*$', line)
                        if indentMatch is not None:
                            serviceIndent = indentMatch.group(1)

                    # determine which service we're currently processing in the YML file
                    serviceStartLine = False
                    if servicesSectionFound and (serviceIndent is not None):
                        serviceMatch = re.search(fr'^{serviceIndent}(\S+)\s*:\s*$', line)
                        if serviceMatch is not None:
                            currentService = serviceMatch.group(1).lower()
                            serviceStartLine = True

                    if (
                        (currentService is not None)
                        and (restartMode is not None)
                        and re.match(r'^\s*restart\s*:.*$', line)
                    ):
                        # OpenSearch backup directory
                        line = f"{serviceIndent * 2}restart: {restartMode}"
                    elif 'PUID' in line:
                        # process UID
                        line = re.sub(r'(PUID\s*:\s*)(\S+)', fr"\g<1>{puid}", line)
                    elif 'PGID' in line:
                        # process GID
                        line = re.sub(r'(PGID\s*:\s*)(\S+)', fr"\g<1>{pgid}", line)
                    elif 'NGINX_SSL' in line:
                        # HTTPS (nginxSSL=True) vs unencrypted HTTP (nginxSSL=False)
                        line = re.sub(r'(NGINX_SSL\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(nginxSSL)}", line)
                    elif 'NGINX_BASIC_AUTH' in line:
                        # basic (useBasicAuth=True) vs ldap (useBasicAuth=False)
                        line = re.sub(
                            r'(NGINX_BASIC_AUTH\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(useBasicAuth)}", line
                        )
                    elif 'NGINX_LDAP_TLS_STUNNEL' in line:
                        # StartTLS vs. ldap:// or ldaps://
                        line = re.sub(
                            r'(NGINX_LDAP_TLS_STUNNEL\s*:\s*)(\S+)',
                            fr"\g<1>{TrueOrFalseQuote(((not useBasicAuth) and ldapStartTLS))}",
                            line,
                        )
                    elif 'ZEEK_EXTRACTOR_MODE' in line:
                        # zeek file extraction mode
                        line = re.sub(r'(ZEEK_EXTRACTOR_MODE\s*:\s*)(\S+)', fr"\g<1>'{fileCarveMode}'", line)
                    elif 'EXTRACTED_FILE_PRESERVATION' in line:
                        # zeek file preservation mode
                        line = re.sub(r'(EXTRACTED_FILE_PRESERVATION\s*:\s*)(\S+)', fr"\g<1>'{filePreserveMode}'", line)
                    elif 'VTOT_API2_KEY' in line:
                        # virustotal API key
                        line = re.sub(r'(VTOT_API2_KEY\s*:\s*)(\S+)', fr"\g<1>'{vtotApiKey}'", line)
                    elif 'EXTRACTED_FILE_ENABLE_YARA' in line:
                        # file scanning via yara
                        line = re.sub(
                            r'(EXTRACTED_FILE_ENABLE_YARA\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(yaraScan)}", line
                        )
                    elif 'EXTRACTED_FILE_ENABLE_CAPA' in line:
                        # PE file scanning via capa
                        line = re.sub(
                            r'(EXTRACTED_FILE_ENABLE_CAPA\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(capaScan)}", line
                        )
                    elif 'EXTRACTED_FILE_ENABLE_CLAMAV' in line:
                        # file scanning via clamav
                        line = re.sub(
                            r'(EXTRACTED_FILE_ENABLE_CLAMAV\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(clamAvScan)}", line
                        )
                    elif 'EXTRACTED_FILE_UPDATE_RULES' in line:
                        # rule updates (yara/capa via git, clamav via freshclam)
                        line = re.sub(
                            r'(EXTRACTED_FILE_UPDATE_RULES\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(ruleUpdate)}", line
                        )
                    elif 'PCAP_ENABLE_NETSNIFF' in line:
                        # capture pcaps via netsniff-ng
                        line = re.sub(
                            r'(PCAP_ENABLE_NETSNIFF\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(pcapNetSniff)}", line
                        )
                    elif 'PCAP_ENABLE_TCPDUMP' in line:
                        # capture pcaps via tcpdump
                        line = re.sub(
                            r'(PCAP_ENABLE_TCPDUMP\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(pcapTcpDump)}", line
                        )
                    elif 'PCAP_IFACE' in line:
                        # capture interface(s)
                        line = re.sub(r'(PCAP_IFACE\s*:\s*)(\S+)', fr"\g<1>'{pcapIface}'", line)
                    elif 'OPENSEARCH_JAVA_OPTS' in line:
                        # OpenSearch memory allowance
                        line = re.sub(r'(-Xm[sx])(\w+)', fr'\g<1>{osMemory}', line)
                    elif 'LS_JAVA_OPTS' in line:
                        # logstash memory allowance
                        line = re.sub(r'(-Xm[sx])(\w+)', fr'\g<1>{lsMemory}', line)
                    elif 'ZEEK_AUTO_ANALYZE_PCAP_FILES' in line:
                        # automatic pcap analysis with Zeek
                        line = re.sub(
                            r'(ZEEK_AUTO_ANALYZE_PCAP_FILES\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(autoZeek)}", line
                        )
                    elif 'LOGSTASH_REVERSE_DNS' in line:
                        # automatic local reverse dns lookup
                        line = re.sub(
                            r'(LOGSTASH_REVERSE_DNS\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(reverseDns)}", line
                        )
                    elif 'LOGSTASH_OUI_LOOKUP' in line:
                        # automatic MAC OUI lookup
                        line = re.sub(r'(LOGSTASH_OUI_LOOKUP\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(autoOui)}", line)
                    elif 'pipeline.workers' in line:
                        # logstash pipeline workers
                        line = re.sub(r'(pipeline\.workers\s*:\s*)(\S+)', fr"\g<1>{lsWorkers}", line)
                    elif 'FREQ_LOOKUP' in line:
                        # freq.py string randomness calculations
                        line = re.sub(r'(FREQ_LOOKUP\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(autoFreq)}", line)
                    elif 'BEATS_SSL' in line:
                        # enable/disable beats SSL
                        line = re.sub(
                            r'(BEATS_SSL\s*:\s*)(\S+)', fr"\g<1>{TrueOrFalseQuote(logstashOpen and logstashSsl)}", line
                        )
                    elif (
                        (currentService == 'opensearch')
                        and re.match(r'^\s*-.+:/opt/opensearch/backup(:.+)?\s*$', line)
                        and (indexSnapshotDir is not None)
                        and os.path.isdir(indexSnapshotDir)
                    ):
                        # OpenSearch backup directory
                        volumeParts = line.strip().lstrip('-').lstrip().split(':')
                        volumeParts[0] = indexSnapshotDir
                        line = "{}- {}".format(serviceIndent * 3, ':'.join(volumeParts))
                    elif 'ISM_SNAPSHOT_AGE' in line:
                        # OpenSearch index state management snapshot age
                        line = re.sub(r'(ISM_SNAPSHOT_AGE\s*:\s*)(\S+)', fr"\g<1>'{indexSnapshotAge}'", line)
                    elif 'ISM_COLD_AGE' in line:
                        # OpenSearch index state management cold (read-only) age
                        line = re.sub(r'(ISM_COLD_AGE\s*:\s*)(\S+)', fr"\g<1>'{indexColdAge}'", line)
                    elif 'ISM_CLOSE_AGE' in line:
                        # OpenSearch index state management close age
                        line = re.sub(r'(ISM_CLOSE_AGE\s*:\s*)(\S+)', fr"\g<1>'{indexCloseAge}'", line)
                    elif 'ISM_DELETE_AGE' in line:
                        # OpenSearch index state management close age
                        line = re.sub(r'(ISM_DELETE_AGE\s*:\s*)(\S+)', fr"\g<1>'{indexDeleteAge}'", line)
                    elif 'ISM_SNAPSHOT_COMPRESSED' in line:
                        # OpenSearch index state management snapshot compression
                        line = re.sub(
                            r'(ISM_SNAPSHOT_COMPRESSED\s*:\s*)(\S+)',
                            fr"\g<1>{TrueOrFalseQuote(indexSnapshotCompressed)}",
                            line,
                        )
                    elif 'OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT' in line:
                        # delete based on index pattern size
                        line = re.sub(
                            r'(OPENSEARCH_INDEX_SIZE_PRUNE_LIMIT\s*:\s*)(\S+)', fr"\g<1>'{indexPruneSizeLimit}'", line
                        )
                    elif 'OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT' in line:
                        # delete based on index pattern size (sorted by name vs. creation time)
                        line = re.sub(
                            r'(OPENSEARCH_INDEX_SIZE_PRUNE_NAME_SORT\s*:\s*)(\S+)',
                            fr"\g<1>{TrueOrFalseQuote(indexPruneNameSort)}",
                            line,
                        )
                    elif 'OS_EXTERNAL_HOSTS' in line:
                        # enable/disable forwarding Logstash to external OpenSearch instance
                        line = re.sub(r'(#\s*)?(OS_EXTERNAL_HOSTS\s*:\s*)(\S+)', fr"\g<2>'{externalEsHost}'", line)
                    elif 'OS_EXTERNAL_SSL_CERTIFICATE_VERIFICATION' in line:
                        # enable/disable SSL certificate verification for external OpenSearch instance
                        line = re.sub(
                            r'(#\s*)?(OS_EXTERNAL_SSL_CERTIFICATE_VERIFICATION\s*:\s*)(\S+)',
                            fr"\g<2>{TrueOrFalseQuote(externalEsSsl and externalEsSslVerify)}",
                            line,
                        )
                    elif 'OS_EXTERNAL_SSL' in line:
                        # enable/disable SSL certificate verification for external OpenSearch instance
                        line = re.sub(
                            r'(#\s*)?(OS_EXTERNAL_SSL\s*:\s*)(\S+)', fr"\g<2>{TrueOrFalseQuote(externalEsSsl)}", line
                        )
                    elif logstashOpen and serviceStartLine and (currentService == 'logstash'):
                        # exposing logstash port 5044 to the world
                        print(line)
                        line = f"{serviceIndent * 2}ports:"
                        print(line)
                        line = f'{serviceIndent * 3}- "0.0.0.0:5044:5044"'
                    elif (
                        (not serviceStartLine)
                        and (currentService == 'logstash')
                        and re.match(fr'^({serviceIndent * 2}ports:|{serviceIndent * 3}-.*5044:5044)"?\s*$', line)
                    ):
                        # remove previous/leftover/duplicate exposing logstash port 5044 to the world
                        skipLine = True
                    elif (
                        (not serviceStartLine)
                        and (currentService == 'nginx-proxy')
                        and re.match(r'^.*-.*\b9200:9200"?\s*$', line)
                    ):
                        # comment/uncomment port forwarding for OpenSearch based on opensearchOpen
                        leadingSpaces = len(line) - len(line.lstrip())
                        if leadingSpaces <= 0:
                            leadingSpaces = 6
                        line = (
                            f"{' ' * leadingSpaces}{'' if opensearchOpen else '# '}{line.lstrip().lstrip('#').lstrip()}"
                        )
                    elif (
                        (not serviceStartLine) and (currentService == 'nginx-proxy') and re.match(r'^\s*test\s*:', line)
                    ):
                        # set nginx-proxy health check based on whether they're using HTTPS or not
                        line = re.sub(
                            r'https?://localhost:\d+',
                            fr"{'https' if nginxSSL else 'http'}://localhost:{443 if nginxSSL else 80}",
                            line,
                        )
                    elif (
                        (not serviceStartLine)
                        and (currentService == 'nginx-proxy')
                        and re.match(r'^[\s#]*-\s*"([\d\.]+:)?\d+:\d+"\s*$', line)
                    ):
                        # set bind IP and HTTP port based on whether they're using HTTPS or not
                        line = re.sub(
                            r'^([\s#]*-\s*")([\d\.]+:)?(\d+:\d+"\s*)$',
                            fr"\g<1>{'0.0.0.0' if nginxSSL else '127.0.0.1'}:\g<3>",
                            line,
                        )
                        if (':80:' in line) and (nginxSSL == True):
                            line = line.replace(':80:', ':443:')
                        elif (':443"' in line) and (nginxSSL == False):
                            line = line.replace(':443:', ':80:')

                    if not skipLine:
                        print(line)

            finally:
                composeFileHandle.close()
                # restore ownership
                os.chown(composeFile, origUid, origGuid)

        # if the Malcolm dir is owned by root, see if they want to reassign ownership to a non-root user
        if (
            ((self.platform == PLATFORM_LINUX) or (self.platform == PLATFORM_MAC))
            and (self.scriptUser == "root")
            and (getpwuid(os.stat(malcolm_install_path).st_uid).pw_name == self.scriptUser)
            and InstallerYesOrNo(
                f'Set ownership of {malcolm_install_path} to an account other than {self.scriptUser}?',
                default=True,
                forceInteraction=True,
            )
        ):
            tmpUser = ''
            while len(tmpUser) == 0:
                tmpUser = InstallerAskForString('Enter user account').strip()
            err, out = self.run_process(['id', '-g', '-n', tmpUser], stderr=True)
            if (err == 0) and (len(out) > 0) and (len(out[0]) > 0):
                tmpUser = f"{tmpUser}:{out[0]}"
            err, out = self.run_process(['chown', '-R', tmpUser, malcolm_install_path], stderr=True)
            if err == 0:
                if self.debug:
                    eprint(f"Changing ownership of {malcolm_install_path} to {tmpUser} succeeded")
            else:
                eprint(f"Changing ownership of {malcolm_install_path} to {tmpUser} failed: {out}")


###################################################################################################
class LinuxInstaller(Installer):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, debug=False, configOnly=False):
        super().__init__(debug, configOnly)

        self.distro = None
        self.codename = None
        self.release = None

        # determine the distro (e.g., ubuntu) and code name (e.g., bionic) if applicable

        # check /etc/os-release values first
        if os.path.isfile('/etc/os-release'):
            osInfo = dict()

            with open("/etc/os-release", 'r') as f:
                for line in f:
                    try:
                        k, v = line.rstrip().split("=")
                        osInfo[k] = v.strip('"')
                    except:
                        pass

            if ('NAME' in osInfo) and (len(osInfo['NAME']) > 0):
                distro = osInfo['NAME'].lower().split()[0]

            if ('VERSION_CODENAME' in osInfo) and (len(osInfo['VERSION_CODENAME']) > 0):
                codename = osInfo['VERSION_CODENAME'].lower().split()[0]

            if ('VERSION_ID' in osInfo) and (len(osInfo['VERSION_ID']) > 0):
                release = osInfo['VERSION_ID'].lower().split()[0]

        # try lsb_release next
        if self.distro is None:
            err, out = self.run_process(['lsb_release', '-is'], stderr=False)
            if (err == 0) and (len(out) > 0):
                self.distro = out[0].lower()

        if self.codename is None:
            err, out = self.run_process(['lsb_release', '-cs'], stderr=False)
            if (err == 0) and (len(out) > 0):
                self.codename = out[0].lower()

        if self.release is None:
            err, out = self.run_process(['lsb_release', '-rs'], stderr=False)
            if (err == 0) and (len(out) > 0):
                self.release = out[0].lower()

        # try release-specific files
        if self.distro is None:
            if os.path.isfile('/etc/centos-release'):
                distroFile = '/etc/centos-release'
            if os.path.isfile('/etc/redhat-release'):
                distroFile = '/etc/redhat-release'
            elif os.path.isfile('/etc/issue'):
                distroFile = '/etc/issue'
            else:
                distroFile = None
            if distroFile is not None:
                with open(distroFile, 'r') as f:
                    distroVals = f.read().lower().split()
                    distroNums = [x for x in distroVals if x[0].isdigit()]
                    self.distro = distroVals[0]
                    if (self.release is None) and (len(distroNums) > 0):
                        self.release = distroNums[0]

        if self.distro is None:
            self.distro = "linux"

        if self.debug:
            eprint(
                f"distro: {self.distro}{f' {self.codename}' if self.codename else ''}{f' {self.release}' if self.release else ''}"
            )

        if not self.codename:
            self.codename = self.distro

        # determine packages required by Malcolm itself (not docker, those will be done later)
        if (self.distro == PLATFORM_LINUX_UBUNTU) or (self.distro == PLATFORM_LINUX_DEBIAN):
            self.requiredPackages.extend(['apache2-utils', 'make', 'openssl'])
        elif (self.distro == PLATFORM_LINUX_FEDORA) or (self.distro == PLATFORM_LINUX_CENTOS):
            self.requiredPackages.extend(['httpd-tools', 'make', 'openssl'])

        # on Linux this script requires root, or sudo, unless we're in local configuration-only mode
        if os.getuid() == 0:
            self.scriptUser = "root"
            self.sudoCmd = []
        else:
            self.sudoCmd = ["sudo", "-n"]
            err, out = self.run_process(['whoami'], privileged=True)
            if ((err != 0) or (len(out) == 0) or (out[0] != 'root')) and (not self.configOnly):
                raise Exception(f'{ScriptName} must be run as root, or {self.sudoCmd} must be available')

        # determine command to use to query if a package is installed
        if Which('dpkg', debug=self.debug):
            os.environ["DEBIAN_FRONTEND"] = "noninteractive"
            self.checkPackageCmds.append(['dpkg', '-s'])
        elif Which('rpm', debug=self.debug):
            self.checkPackageCmds.append(['rpm', '-q'])
        elif Which('dnf', debug=self.debug):
            self.checkPackageCmds.append(['dnf', 'list', 'installed'])
        elif Which('yum', debug=self.debug):
            self.checkPackageCmds.append(['yum', 'list', 'installed'])

        # determine command to install a package from the distro's repos
        if Which('apt-get', debug=self.debug):
            self.installPackageCmds.append(['apt-get', 'install', '-y', '-qq'])
        elif Which('apt', debug=self.debug):
            self.installPackageCmds.append(['apt', 'install', '-y', '-qq'])
        elif Which('dnf', debug=self.debug):
            self.installPackageCmds.append(['dnf', '-y', 'install', '--nobest'])
        elif Which('yum', debug=self.debug):
            self.installPackageCmds.append(['yum', '-y', 'install'])

        # determine total system memory
        try:
            totalMemBytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
            self.totalMemoryGigs = math.ceil(totalMemBytes / (1024.0**3))
        except:
            self.totalMemoryGigs = 0.0

        # determine total system memory a different way if the first way didn't work
        if self.totalMemoryGigs <= 0.0:
            err, out = self.run_process(['awk', '/MemTotal/ { printf "%.0f \\n", $2 }', '/proc/meminfo'])
            if (err == 0) and (len(out) > 0):
                totalMemKiloBytes = int(out[0])
                self.totalMemoryGigs = math.ceil(totalMemKiloBytes / (1024.0**2))

        # determine total system CPU cores
        try:
            self.totalCores = os.sysconf('SC_NPROCESSORS_ONLN')
        except:
            self.totalCores = 0

        # determine total system CPU cores a different way if the first way didn't work
        if self.totalCores <= 0:
            err, out = self.run_process(['grep', '-c', '^processor', '/proc/cpuinfo'])
            if (err == 0) and (len(out) > 0):
                self.totalCores = int(out[0])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker(self):
        result = False

        # first see if docker is already installed and runnable
        err, out = self.run_process(['docker', 'info'], privileged=True)

        if err == 0:
            result = True

        elif InstallerYesOrNo('"docker info" failed, attempt to install Docker?', default=True):

            if InstallerYesOrNo('Attempt to install Docker using official repositories?', default=True):

                # install required packages for repo-based install
                if self.distro == PLATFORM_LINUX_UBUNTU:
                    requiredRepoPackages = [
                        'apt-transport-https',
                        'ca-certificates',
                        'curl',
                        'gnupg-agent',
                        'software-properties-common',
                    ]
                elif self.distro == PLATFORM_LINUX_DEBIAN:
                    requiredRepoPackages = [
                        'apt-transport-https',
                        'ca-certificates',
                        'curl',
                        'gnupg2',
                        'software-properties-common',
                    ]
                elif self.distro == PLATFORM_LINUX_FEDORA:
                    requiredRepoPackages = ['dnf-plugins-core']
                elif self.distro == PLATFORM_LINUX_CENTOS:
                    requiredRepoPackages = ['yum-utils', 'device-mapper-persistent-data', 'lvm2']
                else:
                    requiredRepoPackages = []

                if len(requiredRepoPackages) > 0:
                    eprint(f"Installing required packages: {requiredRepoPackages}")
                    self.install_package(requiredRepoPackages)

                # install docker via repo if possible
                dockerPackages = []
                if ((self.distro == PLATFORM_LINUX_UBUNTU) or (self.distro == PLATFORM_LINUX_DEBIAN)) and self.codename:

                    # for debian/ubuntu, add docker GPG key and check its fingerprint
                    if self.debug:
                        eprint("Requesting docker GPG key for package signing")
                    dockerGpgKey = requests.get(
                        f'https://download.docker.com/linux/{self.distro}/gpg', allow_redirects=True
                    )
                    err, out = self.run_process(
                        ['apt-key', 'add'],
                        stdin=dockerGpgKey.content.decode(sys.getdefaultencoding()),
                        privileged=True,
                        stderr=False,
                    )
                    if err == 0:
                        err, out = self.run_process(
                            ['apt-key', 'fingerprint', DEB_GPG_KEY_FINGERPRINT], privileged=True, stderr=False
                        )

                    # add docker .deb repository
                    if err == 0:
                        if self.debug:
                            eprint("Adding docker repository")
                        err, out = self.run_process(
                            [
                                'add-apt-repository',
                                '-y',
                                '-r',
                                f'deb [arch=amd64] https://download.docker.com/linux/{self.distro} {self.codename} stable',
                            ],
                            privileged=True,
                        )
                        err, out = self.run_process(
                            [
                                'add-apt-repository',
                                '-y',
                                '-u',
                                f'deb [arch=amd64] https://download.docker.com/linux/{self.distro} {self.codename} stable',
                            ],
                            privileged=True,
                        )

                    # docker packages to install
                    if err == 0:
                        dockerPackages.extend(['docker-ce', 'docker-ce-cli', 'containerd.io'])

                elif self.distro == PLATFORM_LINUX_FEDORA:

                    # add docker fedora repository
                    if self.debug:
                        eprint("Adding docker repository")
                    err, out = self.run_process(
                        [
                            'dnf',
                            'config-manager',
                            '-y',
                            '--add-repo',
                            'https://download.docker.com/linux/fedora/docker-ce.repo',
                        ],
                        privileged=True,
                    )

                    # docker packages to install
                    if err == 0:
                        dockerPackages.extend(['docker-ce', 'docker-ce-cli', 'containerd.io'])

                elif self.distro == PLATFORM_LINUX_CENTOS:
                    # add docker centos repository
                    if self.debug:
                        eprint("Adding docker repository")
                    err, out = self.run_process(
                        [
                            'yum-config-manager',
                            '-y',
                            '--add-repo',
                            'https://download.docker.com/linux/centos/docker-ce.repo',
                        ],
                        privileged=True,
                    )

                    # docker packages to install
                    if err == 0:
                        dockerPackages.extend(['docker-ce', 'docker-ce-cli', 'containerd.io'])

                else:
                    err, out = None, None

                if len(dockerPackages) > 0:
                    eprint(f"Installing docker packages: {dockerPackages}")
                    if self.install_package(dockerPackages):
                        eprint("Installation of docker packages apparently succeeded")
                        result = True
                    else:
                        eprint("Installation of docker packages failed")

            # the user either chose not to use the official repos, the official repo installation failed, or there are not official repos available
            # see if we want to attempt using the convenience script at https://get.docker.com (see https://github.com/docker/docker-install)
            if not result and InstallerYesOrNo(
                'Docker not installed via official repositories. Attempt to install Docker via convenience script (please read https://github.com/docker/docker-install)?',
                default=False,
            ):
                tempFileName = os.path.join(self.tempDirName, 'docker-install.sh')
                if DownloadToFile("https://get.docker.com/", tempFileName, debug=self.debug):
                    os.chmod(tempFileName, 493)  # 493 = 0o755
                    err, out = self.run_process(([tempFileName]), privileged=True)
                    if err == 0:
                        eprint("Installation of docker apparently succeeded")
                        result = True
                    else:
                        eprint(f"Installation of docker failed: {out}")
                else:
                    eprint(f"Downloading {dockerComposeUrl} to {tempFileName} failed")

        if result and ((self.distro == PLATFORM_LINUX_FEDORA) or (self.distro == PLATFORM_LINUX_CENTOS)):
            # centos/fedora don't automatically start/enable the daemon, so do so now
            err, out = self.run_process(['systemctl', 'start', 'docker'], privileged=True)
            if err == 0:
                err, out = self.run_process(['systemctl', 'enable', 'docker'], privileged=True)
                if err != 0:
                    eprint(f"Enabling docker service failed: {out}")
            else:
                eprint(f"Starting docker service failed: {out}")

        # at this point we either have installed docker successfully or we have to give up, as we've tried all we could
        err, out = self.run_process(['docker', 'info'], privileged=True, retry=6, retrySleepSec=5)
        if result and (err == 0):
            if self.debug:
                eprint('"docker info" succeeded')

            # add non-root user to docker group if required
            usersToAdd = []
            if self.scriptUser == 'root':
                while InstallerYesOrNo(
                    f"Add {'a' if len(usersToAdd) == 0 else 'another'} non-root user to the \"docker\" group?"
                ):
                    tmpUser = InstallerAskForString('Enter user account')
                    if len(tmpUser) > 0:
                        usersToAdd.append(tmpUser)
            else:
                usersToAdd.append(self.scriptUser)

            for user in usersToAdd:
                err, out = self.run_process(['usermod', '-a', '-G', 'docker', user], privileged=True)
                if err == 0:
                    if self.debug:
                        eprint(f'Adding {user} to "docker" group succeeded')
                else:
                    eprint(f'Adding {user} to "docker" group failed')

        elif err != 0:
            result = False
            raise Exception(f'{ScriptName} requires docker, please see {DOCKER_INSTALL_URLS[self.distro]}')

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker_compose(self):
        result = False

        dockerComposeCmd = 'docker-compose'
        if not Which(dockerComposeCmd, debug=self.debug) and os.path.isfile('/usr/local/bin/docker-compose'):
            dockerComposeCmd = '/usr/local/bin/docker-compose'

        # first see if docker-compose is already installed and runnable (try non-root and root)
        err, out = self.run_process([dockerComposeCmd, 'version'], privileged=False)
        if err != 0:
            err, out = self.run_process([dockerComposeCmd, 'version'], privileged=True)

        if (err != 0) and InstallerYesOrNo(
            '"docker-compose version" failed, attempt to install docker-compose?', default=True
        ):

            if InstallerYesOrNo('Install docker-compose directly from docker github?', default=True):
                # download docker-compose from github and put it in /usr/local/bin

                # need to know some linux platform info
                unames = []
                err, out = self.run_process((['uname', '-s']))
                if (err == 0) and (len(out) > 0):
                    unames.append(out[0])
                err, out = self.run_process((['uname', '-m']))
                if (err == 0) and (len(out) > 0):
                    unames.append(out[0])
                if len(unames) == 2:
                    # download docker-compose from github and save it to a temporary file
                    tempFileName = os.path.join(self.tempDirName, dockerComposeCmd)
                    dockerComposeUrl = f"https://github.com/docker/compose/releases/download/{DOCKER_COMPOSE_INSTALL_VERSION}/docker-compose-{unames[0]}-{unames[1]}"
                    if DownloadToFile(dockerComposeUrl, tempFileName, debug=self.debug):
                        os.chmod(tempFileName, 493)  # 493 = 0o755, mark as executable
                        # put docker-compose into /usr/local/bin
                        err, out = self.run_process(
                            (['cp', '-f', tempFileName, '/usr/local/bin/docker-compose']), privileged=True
                        )
                        if err == 0:
                            eprint("Download and installation of docker-compose apparently succeeded")
                            dockerComposeCmd = '/usr/local/bin/docker-compose'
                        else:
                            raise Exception(f'Error copying {tempFileName} to /usr/local/bin: {out}')

                    else:
                        eprint(f"Downloading {dockerComposeUrl} to {tempFileName} failed")

            elif InstallerYesOrNo('Install docker-compose via pip (privileged)?', default=False):
                # install docker-compose via pip (as root)
                err, out = self.run_process([self.pipCmd, 'install', dockerComposeCmd], privileged=True)
                if err == 0:
                    eprint("Installation of docker-compose apparently succeeded")
                else:
                    eprint(f"Install docker-compose via pip failed with {err}, {out}")

            elif InstallerYesOrNo('Install docker-compose via pip (user)?', default=True):
                # install docker-compose via pip (regular user)
                err, out = self.run_process([self.pipCmd, 'install', dockerComposeCmd], privileged=False)
                if err == 0:
                    eprint("Installation of docker-compose apparently succeeded")
                else:
                    eprint(f"Install docker-compose via pip failed with {err}, {out}")

        # see if docker-compose is now installed and runnable (try non-root and root)
        err, out = self.run_process([dockerComposeCmd, 'version'], privileged=False)
        if err != 0:
            err, out = self.run_process([dockerComposeCmd, 'version'], privileged=True)

        if err == 0:
            result = True
            if self.debug:
                eprint('"docker-compose version" succeeded')

        else:
            raise Exception(
                f'{ScriptName} requires docker-compose, please see {DOCKER_COMPOSE_INSTALL_URLS[self.platform]}'
            )

        return result

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def tweak_system_files(self):

        # make some system configuration changes with permission

        ConfigLines = namedtuple("ConfigLines", ["distros", "filename", "prefix", "description", "lines"], rename=False)

        configLinesToAdd = [
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'fs.file-max=',
                'fs.file-max increases allowed maximum for file handles',
                ['# the maximum number of open file handles', 'fs.file-max=2097152'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'fs.inotify.max_user_watches=',
                'fs.inotify.max_user_watches increases allowed maximum for monitored files',
                ['# the maximum number of user inotify watches', 'fs.inotify.max_user_watches=131072'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'fs.inotify.max_queued_events=',
                'fs.inotify.max_queued_events increases queue size for monitored files',
                ['# the inotify event queue size', 'fs.inotify.max_queued_events=131072'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'fs.inotify.max_user_instances=',
                'fs.inotify.max_user_instances increases allowed maximum monitor file watchers',
                ['# the maximum number of user inotify monitors', 'fs.inotify.max_user_instances=512'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'vm.max_map_count=',
                'vm.max_map_count increases allowed maximum for memory segments',
                ['# the maximum number of memory map areas a process may have', 'vm.max_map_count=262144'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'net.core.somaxconn=',
                'net.core.somaxconn increases allowed maximum for socket connections',
                ['# the maximum number of incoming connections', 'net.core.somaxconn=65535'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'vm.swappiness=',
                'vm.swappiness adjusts the preference of the system to swap vs. drop runtime memory pages',
                ['# decrease "swappiness" (swapping out runtime memory vs. dropping pages)', 'vm.swappiness=1'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'vm.dirty_background_ratio=',
                'vm.dirty_background_ratio defines the percentage of system memory fillable with "dirty" pages before flushing',
                [
                    '# the % of system memory fillable with "dirty" pages before flushing',
                    'vm.dirty_background_ratio=40',
                ],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'vm.dirty_background_ratio=',
                'vm.dirty_background_ratio defines the percentage of dirty system memory before flushing',
                ['# maximum % of dirty system memory before committing everything', 'vm.dirty_background_ratio=40'],
            ),
            ConfigLines(
                [],
                '/etc/sysctl.conf',
                'vm.dirty_ratio=',
                'vm.dirty_ratio defines the maximum percentage of dirty system memory before committing everything',
                ['# maximum % of dirty system memory before committing everything', 'vm.dirty_ratio=80'],
            ),
            ConfigLines(
                ['centos', 'core'],
                '/etc/systemd/system.conf.d/limits.conf',
                '',
                '/etc/systemd/system.conf.d/limits.conf increases the allowed maximums for file handles and memlocked segments',
                ['[Manager]', 'DefaultLimitNOFILE=65535:65535', 'DefaultLimitMEMLOCK=infinity'],
            ),
            ConfigLines(
                [
                    'bionic',
                    'cosmic',
                    'disco',
                    'eoan',
                    'focal',
                    'groovy',
                    'hirsute',
                    'impish',
                    'jammy',
                    'stretch',
                    'buster',
                    'bookworm',
                    'bullseye',
                    'sid',
                    'fedora',
                ],
                '/etc/security/limits.d/limits.conf',
                '',
                '/etc/security/limits.d/limits.conf increases the allowed maximums for file handles and memlocked segments',
                ['* soft nofile 65535', '* hard nofile 65535', '* soft memlock unlimited', '* hard memlock unlimited'],
            ),
        ]

        for config in configLinesToAdd:

            if ((len(config.distros) == 0) or (self.codename in config.distros)) and (
                os.path.isfile(config.filename)
                or InstallerYesOrNo(
                    f'\n{config.description}\n{config.filename} does not exist, create it?', default=True
                )
            ):

                confFileLines = (
                    [line.rstrip('\n') for line in open(config.filename)] if os.path.isfile(config.filename) else []
                )

                if (
                    (len(confFileLines) == 0)
                    or (not os.path.isfile(config.filename) and (len(config.prefix) == 0))
                    or (
                        (len(list(filter(lambda x: x.startswith(config.prefix), confFileLines))) == 0)
                        and InstallerYesOrNo(
                            f'\n{config.description}\n{config.prefix} appears to be missing from {config.filename}, append it?',
                            default=True,
                        )
                    )
                ):

                    echoNewLineJoin = '\\n'
                    err, out = self.run_process(
                        [
                            'bash',
                            '-c',
                            f"mkdir -p {os.path.dirname(config.filename)} && echo -n -e '{echoNewLineJoin}{echoNewLineJoin.join(config.lines)}{echoNewLineJoin}' >> '{config.filename}'",
                        ],
                        privileged=True,
                    )


###################################################################################################
class MacInstaller(Installer):

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def __init__(self, debug=False, configOnly=False):
        super().__init__(debug, configOnly)

        self.sudoCmd = []

        # first see if brew is already installed and runnable
        err, out = self.run_process(['brew', 'info'])
        brewInstalled = err == 0

        if brewInstalled and InstallerYesOrNo('Homebrew is installed: continue with Homebrew?', default=True):
            self.useBrew = True

        else:
            self.useBrew = False
            eprint('Docker can be installed and maintained with Homebrew, or manually.')
            if (not brewInstalled) and (
                not InstallerYesOrNo('Homebrew is not installed: continue with manual installation?', default=False)
            ):
                raise Exception(
                    f'Follow the steps at {HOMEBREW_INSTALL_URLS[self.platform]} to install Homebrew, then re-run {ScriptName}'
                )

        if self.useBrew:
            # make sure we have brew cask
            err, out = self.run_process(['brew', 'info', 'cask'])
            if err != 0:
                self.install_package(['cask'])
                if err == 0:
                    if self.debug:
                        eprint('"brew install cask" succeeded')
                else:
                    eprint(f'"brew install cask" failed with {err}, {out}')

            err, out = self.run_process(['brew', 'tap', 'homebrew/cask-versions'])
            if err == 0:
                if self.debug:
                    eprint('"brew tap homebrew/cask-versions" succeeded')
            else:
                eprint(f'"brew tap homebrew/cask-versions" failed with {err}, {out}')

            self.checkPackageCmds.append(['brew', 'cask', 'ls', '--versions'])
            self.installPackageCmds.append(['brew', 'cask', 'install'])

        # determine total system memory
        try:
            totalMemBytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
            self.totalMemoryGigs = math.ceil(totalMemBytes / (1024.0**3))
        except:
            self.totalMemoryGigs = 0.0

        # determine total system memory a different way if the first way didn't work
        if self.totalMemoryGigs <= 0.0:
            err, out = self.run_process(['sysctl', '-n', 'hw.memsize'])
            if (err == 0) and (len(out) > 0):
                totalMemBytes = int(out[0])
                self.totalMemoryGigs = math.ceil(totalMemBytes / (1024.0**3))

        # determine total system CPU cores
        try:
            self.totalCores = os.sysconf('SC_NPROCESSORS_ONLN')
        except:
            self.totalCores = 0

        # determine total system CPU cores a different way if the first way didn't work
        if self.totalCores <= 0:
            err, out = self.run_process(['sysctl', '-n', 'hw.ncpu'])
            if (err == 0) and (len(out) > 0):
                self.totalCores = int(out[0])

    # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    def install_docker(self):
        result = False

        # first see if docker is already installed/runnable
        err, out = self.run_process(['docker', 'info'])

        if (err != 0) and self.useBrew and self.package_is_installed(MAC_BREW_DOCKER_PACKAGE):
            # if docker is installed via brew, but not running, prompt them to start it
            eprint(f'{MAC_BREW_DOCKER_PACKAGE} appears to be installed via Homebrew, but "docker info" failed')
            while True:
                response = InstallerAskForString(
                    'Starting Docker the first time may require user interaction. Please find and start Docker in the Applications folder, then return here and type YES'
                ).lower()
                if response == 'yes':
                    break
            err, out = self.run_process(['docker', 'info'], retry=12, retrySleepSec=5)

        # did docker info work?
        if err == 0:
            result = True

        elif InstallerYesOrNo('"docker info" failed, attempt to install Docker?', default=True):

            if self.useBrew:
                # install docker via brew cask (requires user interaction)
                dockerPackages = [MAC_BREW_DOCKER_PACKAGE]
                eprint(f"Installing docker packages: {dockerPackages}")
                if self.install_package(dockerPackages):
                    eprint("Installation of docker packages apparently succeeded")
                    while True:
                        response = InstallerAskForString(
                            'Starting Docker the first time may require user interaction. Please find and start Docker in the Applications folder, then return here and type YES'
                        ).lower()
                        if response == 'yes':
                            break
                else:
                    eprint("Installation of docker packages failed")

            else:
                # install docker via downloaded dmg file (requires user interaction)
                dlDirName = f'/Users/{self.scriptUser}/Downloads'
                if os.path.isdir(dlDirName):
                    tempFileName = os.path.join(dlDirName, 'Docker.dmg')
                else:
                    tempFileName = os.path.join(self.tempDirName, 'Docker.dmg')
                if DownloadToFile('https://download.docker.com/mac/edge/Docker.dmg', tempFileName, debug=self.debug):
                    while True:
                        response = InstallerAskForString(
                            f'Installing and starting Docker the first time may require user interaction. Please open Finder and install {tempFileName}, start Docker from the Applications folder, then return here and type YES'
                        ).lower()
                        if response == 'yes':
                            break

            # at this point we either have installed docker successfully or we have to give up, as we've tried all we could
            err, out = self.run_process(['docker', 'info'], retry=12, retrySleepSec=5)
            if err == 0:
                result = True
                if self.debug:
                    eprint('"docker info" succeeded')

            elif err != 0:
                raise Exception(f'{ScriptName} requires docker edge, please see {DOCKER_INSTALL_URLS[self.platform]}')

        elif err != 0:
            raise Exception(f'{ScriptName} requires docker edge, please see {DOCKER_INSTALL_URLS[self.platform]}')

        # tweak CPU/RAM usage for Docker in Mac
        settingsFile = MAC_BREW_DOCKER_SETTINGS.format(self.scriptUser)
        if (
            result
            and os.path.isfile(settingsFile)
            and InstallerYesOrNo(f'Configure Docker resource usage in {settingsFile}?', default=True)
        ):

            # adjust CPU and RAM based on system resources
            if self.totalCores >= 16:
                newCpus = 12
            elif self.totalCores >= 12:
                newCpus = 8
            elif self.totalCores >= 8:
                newCpus = 6
            elif self.totalCores >= 4:
                newCpus = 4
            else:
                newCpus = 2

            if self.totalMemoryGigs >= 64.0:
                newMemoryGiB = 32
            elif self.totalMemoryGigs >= 32.0:
                newMemoryGiB = 24
            elif self.totalMemoryGigs >= 24.0:
                newMemoryGiB = 16
            elif self.totalMemoryGigs >= 16.0:
                newMemoryGiB = 12
            elif self.totalMemoryGigs >= 8.0:
                newMemoryGiB = 8
            elif self.totalMemoryGigs >= 4.0:
                newMemoryGiB = 4
            else:
                newMemoryGiB = 2

            while not InstallerYesOrNo(
                f"Setting {newCpus if newCpus else '(unchanged)'} for CPU cores and {newMemoryGiB if newMemoryGiB else '(unchanged)'} GiB for RAM. Is this OK?",
                default=True,
            ):
                newCpus = InstallerAskForString('Enter Docker CPU cores (e.g., 4, 8, 16)')
                newMemoryGiB = InstallerAskForString('Enter Docker RAM MiB (e.g., 8, 16, etc.)')

            if newCpus or newMemoryMiB:
                with open(settingsFile, 'r+') as f:
                    data = json.load(f)
                    if newCpus:
                        data['cpus'] = int(newCpus)
                    if newMemoryGiB:
                        data['memoryMiB'] = int(newMemoryGiB) * 1024
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()

                # at this point we need to essentially update our system memory stats because we're running inside docker
                # and don't have the whole banana at our disposal
                self.totalMemoryGigs = newMemoryGiB

                eprint("Docker resource settings adjusted, attempting restart...")

                err, out = self.run_process(['osascript', '-e', 'quit app "Docker"'])
                if err == 0:
                    time.sleep(5)
                    err, out = self.run_process(['open', '-a', 'Docker'])

                if err == 0:
                    err, out = self.run_process(['docker', 'info'], retry=12, retrySleepSec=5)
                    if err == 0:
                        if self.debug:
                            eprint('"docker info" succeeded')

                else:
                    eprint(f"Restarting Docker automatically failed: {out}")
                    while True:
                        response = InstallerAskForString(
                            'Please restart Docker via the system taskbar, then return here and type YES'
                        ).lower()
                        if response == 'yes':
                            break

        return result


###################################################################################################
# main
def main():
    global args

    # extract arguments from the command line
    # print (sys.argv[1:]);
    parser = argparse.ArgumentParser(
        description='Malcolm install script', add_help=False, usage=f'{ScriptName} <arguments>'
    )
    parser.add_argument(
        '-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output"
    )
    parser.add_argument(
        '-m',
        '--malcolm-file',
        required=False,
        dest='mfile',
        metavar='<STR>',
        type=str,
        default='',
        help='Malcolm .tar.gz file for installation',
    )
    parser.add_argument(
        '-i',
        '--image-file',
        required=False,
        dest='ifile',
        metavar='<STR>',
        type=str,
        default='',
        help='Malcolm docker images .tar.gz file for installation',
    )
    parser.add_argument(
        '-c',
        '--configure',
        dest='configOnly',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Only do configuration (not installation)",
    )
    parser.add_argument(
        '-f',
        '--configure-file',
        required=False,
        dest='configFile',
        metavar='<STR>',
        type=str,
        default='',
        help='Single docker-compose YML file to configure',
    )
    parser.add_argument(
        '-d',
        '--defaults',
        dest='acceptDefaults',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Accept defaults to prompts without user interaction",
    )
    parser.add_argument(
        '-l',
        '--logstash-expose',
        dest='exposeLogstash',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Expose Logstash port to external hosts",
    )
    parser.add_argument(
        '-e',
        '--opensearch-expose',
        dest='exposeOpenSearch',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Expose OpenSearch port to external hosts",
    )
    parser.add_argument(
        '-r',
        '--restart-malcolm',
        dest='malcolmAutoRestart',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Restart Malcolm on system restart (unless-stopped)",
    )

    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    if args.debug:
        eprint(os.path.join(ScriptPath, ScriptName))
        eprint(f"Arguments: {sys.argv[1:]}")
        eprint(f"Arguments: {args}")
    else:
        sys.tracebacklimit = 0

    if not ImportRequests(debug=args.debug):
        exit(2)

    # If Malcolm and images tarballs are provided, we will use them.
    # If they are not provided, look in the pwd first, then in the script directory, to see if we
    # can locate the most recent tarballs
    malcolmFile = None
    imageFile = None

    if args.mfile and os.path.isfile(args.mfile):
        malcolmFile = args.mfile
    else:
        # find the most recent non-image tarball, first checking in the pwd then in the script path
        files = list(filter(lambda x: "_images" not in x, glob.glob(os.path.join(origPath, '*.tar.gz'))))
        if len(files) == 0:
            files = list(filter(lambda x: "_images" not in x, glob.glob(os.path.join(ScriptPath, '*.tar.gz'))))
        files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
        if len(files) > 0:
            malcolmFile = files[0]

    if args.ifile and os.path.isfile(args.ifile):
        imageFile = args.ifile

    if (malcolmFile and os.path.isfile(malcolmFile)) and (not imageFile or not os.path.isfile(imageFile)):
        # if we've figured out the malcolm tarball, the _images tarball should match it
        imageFile = malcolmFile.replace('.tar.gz', '_images.tar.gz')
        if not os.path.isfile(imageFile):
            imageFile = None

    if args.debug:
        if args.configOnly:
            eprint("Only doing configuration, not installation")
        else:
            eprint(f"Malcolm install file: {malcolmFile}")
            eprint(f"Docker images file: {imageFile}")

    installerPlatform = platform.system()
    if installerPlatform == PLATFORM_LINUX:
        installer = LinuxInstaller(debug=args.debug, configOnly=args.configOnly)
    elif installerPlatform == PLATFORM_MAC:
        installer = MacInstaller(debug=args.debug, configOnly=args.configOnly)
    elif installerPlatform == PLATFORM_WINDOWS:
        raise Exception(f'{ScriptName} is not yet supported on {installerPlatform}')
        installer = WindowsInstaller(debug=args.debug, configOnly=args.configOnly)

    success = False
    installPath = None

    if not args.configOnly:
        if hasattr(installer, 'install_required_packages'):
            success = installer.install_required_packages()
        if hasattr(installer, 'install_docker'):
            success = installer.install_docker()
        if hasattr(installer, 'install_docker_compose'):
            success = installer.install_docker_compose()
        if hasattr(installer, 'tweak_system_files'):
            success = installer.tweak_system_files()
        if hasattr(installer, 'install_docker_images'):
            success = installer.install_docker_images(imageFile)

    if args.configOnly or (args.configFile and os.path.isfile(args.configFile)):
        if not args.configFile:
            for testPath in [origPath, ScriptPath, os.path.realpath(os.path.join(ScriptPath, ".."))]:
                if os.path.isfile(os.path.join(testPath, "docker-compose.yml")):
                    installPath = testPath
        else:
            installPath = os.path.dirname(os.path.realpath(args.configFile))
        success = (installPath is not None) and os.path.isdir(installPath)
        if args.debug:
            eprint(f"Malcolm installation detected at {installPath}")

    elif hasattr(installer, 'install_malcolm_files'):
        success, installPath = installer.install_malcolm_files(malcolmFile)

    if (installPath is not None) and os.path.isdir(installPath) and hasattr(installer, 'tweak_malcolm_runtime'):
        installer.tweak_malcolm_runtime(
            installPath,
            expose_opensearch_default=args.exposeOpenSearch,
            expose_logstash_default=args.exposeLogstash,
            restart_mode_default=args.malcolmAutoRestart,
        )
        eprint(f"\nMalcolm has been installed to {installPath}. See README.md for more information.")
        eprint(
            f"Scripts for starting and stopping Malcolm and changing authentication-related settings can be found in {os.path.join(installPath, 'scripts')}."
        )


if __name__ == '__main__':
    main()
