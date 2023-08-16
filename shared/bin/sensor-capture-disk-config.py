#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

###################################################################################################
# Detect, partition, and format devices to be used for sensor packet/log captures.
#
# Run the script with --help for options
###################################################################################################

import os
import re
import glob
import sys
import uuid
import argparse
import fileinput
from collections import defaultdict
from fstab import Fstab

from malcolm_utils import remove_prefix, str2bool, sizeof_fmt, run_subprocess, eprint

MINIMUM_CAPTURE_DEVICE_BYTES = 100 * 1024 * 1024 * 1024  # 100GiB
CAPTURE_MOUNT_ROOT_PATH = "/capture"
CAPTURE_MOUNT_PCAP_DIR = "pcap"
CAPTURE_MOUNT_ZEEK_DIR = "bro"
FSTAB_FILE = "/etc/fstab"
CRYPTTAB_FILE = "/etc/crypttab"
CAPTURE_GROUP_OWNER = "netdev"
CAPTURE_USER_UID = 1000
CAPTURE_DIR_PERMS = 0o750
CAPTURE_SUBDIR_PERMS = 0o770
SENSOR_CAPTURE_CONFIG = '/opt/sensor/sensor_ctl/control_vars.conf'
CAPTURE_CRYPT_KEYFILE = '/etc/capture_crypt.key'
CAPTURE_CRYPT_KEYFILE_PERMS = 0o600
CAPTURE_CRYPT_DEV_PREFIX = 'capture_vault_'

debug = False


###################################################################################################
# used to map output of lsblk
class PartitionInfo:
    __slots__ = ('device', 'partition', 'mapper', 'uuid', 'mount')

    def __init__(self, device=None, partition=None, mapper=None, uuid=None, mount=None):
        self.device = device
        self.partition = partition
        self.mapper = mapper
        self.uuid = uuid
        self.mount = mount


###################################################################################################
# get interactive user response to Y/N question
def YesOrNo(question):
    reply = str(input(question + ' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    elif reply[0] == 'n':
        return False
    else:
        return YesOrNo(question)


###################################################################################################
# create a name we can use for a mapper device name for encryption
def CreateMapperName(device):
    return f"{CAPTURE_CRYPT_DEV_PREFIX}{''.join([c if c.isalnum() else '_' for c in remove_prefix(device, '/dev/')])}"


def CreateMapperDeviceName(device):
    return f"/dev/mapper/{CreateMapperName(device)}"


###################################################################################################


###################################################################################################
# determine if a device (eg., sda) is an internal (True) or removable (False) device
def IsInternalDevice(name):
    rootdir_pattern = re.compile(r'^.*?/devices')

    removableFlagFile = '/sys/block/%s/device/block/%s/removable' % (name, name)
    if not os.path.isfile(removableFlagFile):
        removableFlagFile = '/sys/block/%s/removable' % (name)
    if os.path.isfile(removableFlagFile):
        with open(removableFlagFile) as f:
            if f.read(1) == '1':
                return False

    path = rootdir_pattern.sub('', os.readlink('/sys/block/%s' % name))
    hotplug_buses = ("usb", "ieee1394", "mmc", "pcmcia", "firewire")
    for bus in hotplug_buses:
        if os.path.exists('/sys/bus/%s' % bus):
            for device_bus in os.listdir('/sys/bus/%s/devices' % bus):
                device_link = rootdir_pattern.sub('', os.readlink('/sys/bus/%s/devices/%s' % (bus, device_bus)))
                if re.search(device_link, path):
                    return False

    return True


###################################################################################################
# return a list of internal storage devices (eg., [sda, sdb])
def GetInternalDevices():
    devs = []
    for path in glob.glob('/sys/block/*/device'):
        name = re.sub('.*/(.*?)/device', r'\g<1>', path)
        if IsInternalDevice(name):
            devs.append(name)
    return devs


###################################################################################################
# given a device (any file descriptor, actually) return size in bytes by seeking to the end
def GetDeviceSize(device):
    fd = os.open(device, os.O_RDONLY)
    try:
        return os.lseek(fd, 0, os.SEEK_END)
    finally:
        os.close(fd)


###################################################################################################
# main
###################################################################################################
def main():
    # to parse fdisk output, look for partitions after partitions header line
    fdisk_pars_begin_pattern = re.compile(r'^Device\s+Start\s+End\s+Sectors\s+Size\s+Type\s*$')
    # to parse partitions from fdisk output after parted creates partition table
    fdisk_par_pattern = re.compile(
        r'^(?P<device>\S+)\s+(?P<start>\d+)\s+(?P<end>\d+)\s+(?P<sectors>\d+)\s+(?P<size>\S+)\s+(?P<type>.*)$'
    )

    # extract arguments from the command line
    parser = argparse.ArgumentParser(
        description='sensor-capture-disk-config.py', add_help=False, usage='sensor-capture-disk-config.py [options]'
    )
    parser.add_argument(
        '-i',
        '--interactive',
        dest='interactive',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Interactive",
    )
    parser.add_argument(
        '-u',
        '--umount',
        dest='umount',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Unmount capture directories before determining candidate drives",
    )
    parser.add_argument(
        '-v', '--verbose', dest='debug', type=str2bool, nargs='?', const=True, default=False, help="Verbose output"
    )
    parser.add_argument(
        '-n',
        '--dry-run',
        dest='dryrun',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Dry run (don't perform actions)",
    )
    parser.add_argument(
        '-c',
        '--crypto',
        dest='encrypt',
        type=str2bool,
        nargs='?',
        const=True,
        default=False,
        help="Encrypt formatted volumes",
    )
    try:
        parser.error = parser.exit
        args = parser.parse_args()
    except SystemExit:
        parser.print_help()
        exit(2)

    debug = args.debug
    if debug:
        eprint(f"Arguments: {sys.argv[1:]}")
    if debug:
        eprint(f"Arguments: {args}")

    # unmount existing mounts if requested
    if args.umount and (not args.dryrun):
        if (not args.interactive) or YesOrNo('Unmount any mounted capture path(s)?'):
            if debug:
                eprint("Attempting unmount of capture path(s)...")
            run_subprocess(f"umount {os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_PCAP_DIR)}")
            run_subprocess(f"umount {os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_ZEEK_DIR)}")
            run_subprocess(f"umount {CAPTURE_MOUNT_ROOT_PATH}")
            # also luksClose any luks volumes devices we might have set up
            for cryptDev in [
                remove_prefix(x, '/dev/mapper/') for x in glob.glob(f"/dev/mapper/{CAPTURE_CRYPT_DEV_PREFIX}*")
            ]:
                if debug:
                    eprint(f"Running crypsetup luksClose on {cryptDev}...")
                _, cryptOut = run_subprocess(
                    f"/sbin/cryptsetup --verbose luksClose {cryptDev}", stdout=True, stderr=True, timeout=300
                )
                if debug:
                    for line in cryptOut:
                        eprint(f"\t{line}")
            _, reloadOut = run_subprocess("systemctl daemon-reload")

    # check existing mounts, if the capture path(s) are already mounted, then abort
    with open('/proc/mounts', 'r') as f:
        for line in f.readlines():
            mountDetails = line.split()
            if len(mountDetails) >= 2:
                mountPoint = mountDetails[1]
                if mountPoint.startswith(CAPTURE_MOUNT_ROOT_PATH):
                    eprint(
                        f"It appears there is already a device mounted under {CAPTURE_MOUNT_ROOT_PATH} at {mountPoint}."
                    )
                    eprint(
                        "If you wish to continue, you may run this script with the '-u|--umount' option to umount first."
                    )
                    eprint()
                    parser.print_help()
                    exit(2)

    # get physical disks, partitions, device maps, and any mountpoints and UUID associated
    allDisks = defaultdict(list)
    if debug:
        eprint("Block devices:")
    for device in GetInternalDevices():
        ecode, deviceTree = run_subprocess(
            f'/bin/lsblk -o name,uuid,mountpoint --paths --noheadings /dev/{device}', stdout=True, stderr=False
        )
        if ecode == 0:
            currentDev = None
            currentPar = None
            currentMapper = None
            for line in deviceTree:
                line = line.rstrip()
                if len(line) > 0:
                    if debug:
                        eprint(f"\t{line}")
                    if line == f"/dev/{device}":
                        currentDev = line
                        currentPar = None
                        currentMapper = None
                        allDisks[currentDev].append(PartitionInfo(device=currentDev))
                    elif (currentDev is not None) and (line[2 : 2 + len(f"/dev/{device}")] == f"/dev/{device}"):
                        parInfo = f"/{line.split('/', 1)[-1]}".split()
                        if len(parInfo) >= 2:
                            currentPar = PartitionInfo(
                                device=currentDev,
                                partition=parInfo[0],
                                uuid=parInfo[1],
                                mount=parInfo[2] if (len(parInfo) > 2) else None,
                            )
                            currentMapper = None
                            allDisks[currentDev].append(currentPar)
                    elif (currentPar is not None) and ("/dev/mapper/" in line):
                        parInfo = f"/{line.split('/', 1)[-1]}".split()
                        if len(parInfo) >= 2:
                            currentMapper = PartitionInfo(
                                device=currentDev,
                                partition=currentPar.partition,
                                mapper=parInfo[0],
                                uuid=parInfo[1],
                                mount=parInfo[2] if (len(parInfo) > 2) else None,
                            )
                            allDisks[currentDev].append(currentMapper)

    # at this point allDisks might look like this:
    # defaultdict(<class 'list'>,
    #             {'/dev/sda': [PartitionInfo(device='/dev/sda', partition=None, mapper=None, uuid=None, mount=None),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda1', mapper=None, uuid='B42B-7414', mount=None),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda2', mapper=None, uuid='6DF8-D966', mount='/boot/efi'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda3', mapper=None, uuid='f6b575e4-0ec2-47ab-8d0a-9d677ac4fe3c', mount='/boot'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper=None, uuid='Lmx30A-U9qR-kDZF-WOju-zlOi-otrR-WNjh7j', mount=None),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-swap', uuid='00987200-7157-45d1-a233-90cbb22554aa', mount='[SWAP]'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-root', uuid='b53ea5c3-8771-4717-9d3d-ef9c5b18bbe4', mount='/'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-var', uuid='45aec3eb-68be-4eaa-bf79-de3f2a85c103', mount='/var'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-audit', uuid='339ee49c-0e45-4510-8447-55f46f2a3653', mount='/var/log/audit'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-tmp', uuid='b305d781-263f-4016-8422-301f61c11472', mount='/tmp'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-opt', uuid='5e7cbfb8-760e-4526-90d5-ab103ae626a5', mount='/opt'),
    #                           PartitionInfo(device='/dev/sda', partition='/dev/sda4', mapper='/dev/mapper/main-home', uuid='1b089fc0-f3a4-400b-955c-d3fa6b1e2a5f', mount='/home')],
    #              '/dev/sdb': [PartitionInfo(device='/dev/sdb', partition=None, mapper=None, uuid=None, mount=None)]})

    candidateDevs = []
    formattedDevs = []

    # determine candidate storage devices, which are any disks that do not have a mount point associated with
    # it in any way, (no partitions, mappings, etc. that are mounted) and is at least 100 gigabytes
    for device, entries in allDisks.items():
        deviceMounts = list(set([par.mount for par in entries if par.mount is not None]))
        if (len(deviceMounts) == 0) and (GetDeviceSize(device) >= MINIMUM_CAPTURE_DEVICE_BYTES):
            candidateDevs.append(device)

    # sort candidate devices largest to smallest
    candidateDevs = sorted(candidateDevs, key=lambda x: GetDeviceSize(x), reverse=True)
    if debug:
        eprint(f"Device candidates: {[(x, sizeof_fmt(GetDeviceSize(x))) for x in candidateDevs]}")

    if len(candidateDevs) > 0:
        if args.encrypt:
            # create keyfile (will be on the encrypted system drive, and used to automatically unlock the encrypted capture drives)
            with open(CAPTURE_CRYPT_KEYFILE, 'wb') as f:
                f.write(os.urandom(4096))
            os.chown(CAPTURE_CRYPT_KEYFILE, 0, 0)
            os.chmod(CAPTURE_CRYPT_KEYFILE, CAPTURE_CRYPT_KEYFILE_PERMS)

        # partition/format each candidate device
        for device in candidateDevs:
            # we only need at most two drives (one for pcap, one for zeek), or at least one
            if len(formattedDevs) >= 2:
                break

            if (not args.interactive) or YesOrNo(
                f'Partition and format {device}{" (dry-run)" if args.dryrun else ""}?'
            ):
                if args.dryrun:
                    eprint(f"Partitioning {device} (dry run only)...")
                    eprint(
                        f'\t/sbin/parted --script --align optimal {device} -- mklabel gpt \\\n\t\tunit mib mkpart primary 1 100%'
                    )
                    ecode = 0
                    partedOut = []

                else:
                    # use parted to create a gpt partition table with a single partition consuming 100% of the disk minus one megabyte at the beginning
                    if debug:
                        eprint(f"Partitioning {device}...")
                    ecode, partedOut = run_subprocess(
                        f'/sbin/parted --script --align optimal {device} -- mklabel gpt \\\n unit mib mkpart primary 1 100%',
                        stdout=True,
                        stderr=True,
                        timeout=300,
                    )
                    if debug:
                        eprint(partedOut)
                    if ecode == 0:
                        if debug:
                            eprint(f"Success partitioning {device}")

                        # get the list of partitions from the newly partitioned device (should be just one)
                        _, fdiskOut = run_subprocess(f'fdisk -l {device}')
                        pars = []
                        parsList = False
                        for line in fdiskOut:
                            if debug:
                                eprint(f"\t{line}")
                            if (not parsList) and fdisk_pars_begin_pattern.search(line):
                                parsList = True
                            elif parsList:
                                match = fdisk_par_pattern.search(line)
                                if match is not None:
                                    pars.append(match.group('device'))

                        if len(pars) == 1:
                            parDev = pars[0]
                            parUuid = str(uuid.uuid4())
                            parMapperDev = None
                            okToFormat = True

                            if args.encrypt:
                                okToFormat = False

                                # remove this device from /etc/crypttab
                                if os.path.isfile(CRYPTTAB_FILE):
                                    with fileinput.FileInput(CRYPTTAB_FILE, inplace=True, backup='.bak') as f:
                                        for line in f:
                                            line = line.rstrip("\n")
                                            if line.startswith(f"{CreateMapperName(parDev)}"):
                                                if debug:
                                                    eprint(f"removed {line} from {CRYPTTAB_FILE}")
                                            else:
                                                print(line)

                                _, reloadOut = run_subprocess("systemctl daemon-reload")

                                # for good measure, run luksErase in case it was a previous luks volume
                                if debug:
                                    eprint(f"Running crypsetup luksErase on {parDev}...")
                                _, cryptOut = run_subprocess(
                                    f"/sbin/cryptsetup --verbose --batch-mode luksErase {parDev}",
                                    stdout=True,
                                    stderr=True,
                                    timeout=600,
                                )
                                if debug:
                                    for line in cryptOut:
                                        eprint(f"\t{line}")

                                _, reloadOut = run_subprocess("systemctl daemon-reload")

                                # luks volume creation

                                # format device as a luks volume
                                if debug:
                                    eprint(f"Running crypsetup luksFormat on {device}...")
                                ecode, cryptOut = run_subprocess(
                                    f"/sbin/cryptsetup --verbose --batch-mode luksFormat {parDev} --uuid='{parUuid}' --key-file {CAPTURE_CRYPT_KEYFILE}",
                                    stdout=True,
                                    stderr=True,
                                    timeout=3600,
                                )
                                if debug or (ecode != 0):
                                    for line in cryptOut:
                                        eprint(f"\t{line}")
                                if ecode == 0:
                                    # open the luks volume in /dev/mapper/
                                    if debug:
                                        eprint(f"Running crypsetup luksOpen on {device}...")
                                    parMapperDev = CreateMapperDeviceName(parDev)
                                    ecode, cryptOut = run_subprocess(
                                        f"/sbin/cryptsetup --verbose luksOpen {parDev} {CreateMapperName(parDev)} --key-file {CAPTURE_CRYPT_KEYFILE}",
                                        stdout=True,
                                        stderr=True,
                                        timeout=180,
                                    )
                                    if debug or (ecode != 0):
                                        for line in cryptOut:
                                            eprint(f"\t{line}")
                                    if ecode == 0:
                                        # we have everything we need for luks
                                        okToFormat = True

                                    else:
                                        eprint(f"Error {ecode} opening LUKS on {parDev}, giving up on {device}")
                                else:
                                    eprint(f"Error {ecode} formatting LUKS on {parDev}, giving up on {device}")

                            # format the partition as an XFS file system
                            if okToFormat:
                                if debug:
                                    eprint(f'Created {parDev}, assigning {parUuid}')
                                if args.encrypt:
                                    formatCmd = f"/sbin/mkfs.xfs -f {parMapperDev}"
                                else:
                                    formatCmd = f"/sbin/mkfs.xfs -f -m uuid='{parUuid}' {parDev}"
                                if debug:
                                    eprint(f"Formatting: {formatCmd}")
                                ecode, mkfsOut = run_subprocess(formatCmd, stdout=True, stderr=True, timeout=3600)
                                if debug:
                                    for line in mkfsOut:
                                        eprint(f"\t{line}")
                                if ecode == 0:
                                    eprint(f"Success formatting {parMapperDev if args.encrypt else parDev}")
                                    formattedDevs.append(
                                        PartitionInfo(
                                            device=device,
                                            partition=parDev,
                                            mapper=parMapperDev,
                                            uuid=parUuid,
                                            mount=None,
                                        )
                                    )

                                else:
                                    eprint(
                                        f"Error {ecode} formatting {parMapperDev if args.encrypt else parDev}, giving up on {device}"
                                    )

                        else:
                            eprint(
                                f"Error partitioning {device}, unexpected partitions after running parted, giving up on {device}"
                            )

                    elif ecode != 0:
                        eprint(f"Error {ecode} partitioning {device}, giving up on {device}")

        # now that we have formatted our device(s), decide where they're going to mount (these are already sorted)
        if len(formattedDevs) >= 2:
            formattedDevs[0].mount = os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_PCAP_DIR)
            formattedDevs[1].mount = os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_ZEEK_DIR)

        elif len(formattedDevs) == 1:
            formattedDevs[0].mount = CAPTURE_MOUNT_ROOT_PATH

        if debug:
            eprint(formattedDevs)

        # mountpoints are probably not already mounted, but this will make sure
        run_subprocess(f"umount {os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_PCAP_DIR)}")
        run_subprocess(f"umount {os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_ZEEK_DIR)}")
        run_subprocess(f"umount {CAPTURE_MOUNT_ROOT_PATH}")

        _, reloadOut = run_subprocess("systemctl daemon-reload")

        # clean out any previous fstab entries that might be interfering from previous configurations
        if Fstab.remove_by_mountpoint(os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_PCAP_DIR), path=FSTAB_FILE):
            if debug:
                eprint(
                    f"Removed previous {os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_PCAP_DIR)} mount from {FSTAB_FILE}"
                )
        if Fstab.remove_by_mountpoint(os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_ZEEK_DIR), path=FSTAB_FILE):
            if debug:
                eprint(
                    f"Removed previous {os.path.join(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_MOUNT_ZEEK_DIR)} mount from {FSTAB_FILE}"
                )
        if Fstab.remove_by_mountpoint(CAPTURE_MOUNT_ROOT_PATH, path=FSTAB_FILE):
            if debug:
                eprint(f"Removed previous {CAPTURE_MOUNT_ROOT_PATH} mount from {FSTAB_FILE}")

        # reload tab files with systemctl
        _, reloadOut = run_subprocess("systemctl daemon-reload")

        # get the GID of the group of the user(s) that will be doing the capture
        try:
            ecode, guidGetOut = run_subprocess(f"getent group {CAPTURE_GROUP_OWNER}", stdout=True, stderr=True)
            if (ecode == 0) and (len(guidGetOut) > 0):
                netdevGuid = int(guidGetOut[0].split(':')[2])
            else:
                netdevGuid = -1
        except Exception:
            netdevGuid = -1

        # rmdir any mount directories that might be interfering from previous configurations
        if os.path.isdir(CAPTURE_MOUNT_ROOT_PATH):
            for root, dirs, files in os.walk(CAPTURE_MOUNT_ROOT_PATH, topdown=False):
                for name in dirs:
                    if debug:
                        eprint(f"Removing {os.path.join(root, name)}")
                    os.rmdir(os.path.join(root, name))
            if debug:
                eprint(f"Removing {CAPTURE_MOUNT_ROOT_PATH}")
            os.rmdir(CAPTURE_MOUNT_ROOT_PATH)
            if debug:
                eprint(f"Creating {CAPTURE_MOUNT_ROOT_PATH}")
            os.makedirs(CAPTURE_MOUNT_ROOT_PATH, exist_ok=True)
            os.chown(CAPTURE_MOUNT_ROOT_PATH, -1, netdevGuid)
            os.chmod(CAPTURE_MOUNT_ROOT_PATH, CAPTURE_DIR_PERMS)

        # add crypttab entries
        if args.encrypt:
            with open(CRYPTTAB_FILE, 'a' if os.path.isfile(CRYPTTAB_FILE) else 'w') as f:
                for par in formattedDevs:
                    crypttabLine = f"{CreateMapperName(par.partition)} UUID={par.uuid} {CAPTURE_CRYPT_KEYFILE} luks\n"
                    f.write(crypttabLine)
                    if debug:
                        eprint(f'Added "{crypttabLine}" to {CRYPTTAB_FILE}')

        # recreate mount directories and add fstab entries
        for par in formattedDevs:
            if debug:
                eprint(f"Creating {par.mount}")
            os.makedirs(par.mount, exist_ok=True)
            if args.encrypt:
                entry = Fstab.add(
                    device=f"{par.mapper}",
                    mountpoint=par.mount,
                    options="defaults,inode64,noatime,rw,auto,user,x-systemd.device-timeout=600s",
                    fs_passno=2,
                    filesystem='xfs',
                    path=FSTAB_FILE,
                )
            else:
                entry = Fstab.add(
                    device=f"UUID={par.uuid}",
                    mountpoint=par.mount,
                    options="defaults,inode64,noatime,rw,auto,user,x-systemd.device-timeout=600s",
                    fs_passno=2,
                    filesystem='xfs',
                    path=FSTAB_FILE,
                )
            eprint(f'Added "{entry}" to {FSTAB_FILE} for {par.partition}')

        # reload tab files with systemctl
        _, reloadOut = run_subprocess("systemctl daemon-reload")

        # mount the partitions and create a directory with user permissions
        for par in formattedDevs:
            ecode, mountOut = run_subprocess(f"mount {par.mount}")
            if ecode == 0:
                if debug:
                    eprint(f'Mounted {par.partition} at {par.mount}')

                userDirs = []
                if par.mount == CAPTURE_MOUNT_ROOT_PATH:
                    # only one drive, so we're mounted at /capture, create user directories for CAPTURE_MOUNT_ZEEK_DIR and CAPTURE_MOUNT_PCAP_DIR
                    userDirs.append(os.path.join(par.mount, CAPTURE_MOUNT_PCAP_DIR))
                    userDirs.append(os.path.join(par.mount, CAPTURE_MOUNT_ZEEK_DIR))
                else:
                    # we're mounted somewhere *underneath* /capture, so create a user-writeable subdirectory where we are
                    userDirs.append(os.path.join(par.mount, 'capture'))

                # set permissions on user dirs
                pcapDir = None
                zeekDir = None
                for userDir in userDirs:
                    os.makedirs(userDir, exist_ok=True)
                    os.chown(userDir, CAPTURE_USER_UID, netdevGuid)
                    os.chmod(userDir, CAPTURE_SUBDIR_PERMS)
                    if debug:
                        eprint(f'Created "{userDir}" for writing by capture user')
                    if f"{os.path.sep}{CAPTURE_MOUNT_PCAP_DIR}{os.path.sep}" in userDir:
                        pcapDir = userDir
                    elif f"{os.path.sep}{CAPTURE_MOUNT_ZEEK_DIR}{os.path.sep}" in userDir:
                        zeekDir = userDir

                # replace capture paths in-place in SENSOR_CAPTURE_CONFIG
                if os.path.isfile(SENSOR_CAPTURE_CONFIG):
                    capture_re = re.compile(r"\b(?P<key>PCAP_PATH|ZEEK_LOG_PATH)\s*=\s*.*?$")
                    with fileinput.FileInput(SENSOR_CAPTURE_CONFIG, inplace=True, backup='.bak') as f:
                        for line in f:
                            line = line.rstrip("\n")
                            log_path_match = capture_re.search(line)
                            if log_path_match is not None:
                                if (log_path_match.group('key') == 'PCAP_PATH') and (pcapDir is not None):
                                    print(capture_re.sub(r"\1=%s" % pcapDir, line))
                                elif (log_path_match.group('key') == 'ZEEK_LOG_PATH') and (zeekDir is not None):
                                    print(capture_re.sub(r"\1=%s" % zeekDir, line))
                                else:
                                    print(line)
                            else:
                                print(line)

            else:
                eprint(f"Error {ecode} mounting {par.partition}")

    else:
        eprint("Could not find any unmounted devices greater than 100GB, giving up")


if __name__ == '__main__':
    main()
