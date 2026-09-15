#!/usr/bin/python3

import re
import sys
import subprocess
import os

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
MALCOLM_DIR = os.path.dirname(SCRIPT_DIR)
MALCOLM_ISO_DIR = os.path.join(MALCOLM_DIR, 'malcolm-iso')

# pylint: disable=invalid-name

### Sanity/usage checks

if len(sys.argv) != 3:
    print("E: need 2 arguments", file=sys.stderr)
    sys.exit(1)

supported_suites = {
    "4": {"trixie", "forky"},
    "5": {"forky"},
}

version = sys.argv[1]
if version not in supported_suites:
    print(f"E: unsupported version {version}", file=sys.stderr)
    sys.exit(1)

suite = sys.argv[2]
if suite not in supported_suites[version]:
    print(
        f"E: unsupported suite/model combination: Raspberry Pi {version} with {suite}",
        file=sys.stderr,
    )
    sys.exit(1)

target_yaml = f"raspi_{version}_{suite}.yaml"


### Setting variables based on suite and version starts here

# Arch, kernel, DTB:
if version in ['4', '5']:
    arch = 'arm64'
    linux = 'linux-image-arm64'
    dtb = '/usr/lib/linux-image-*-arm64/broadcom/bcm*rpi*.dtb'

# Bookworm introduced the 'non-free-firmware' component¹; before that,
# raspi-firmware was in 'non-free'
#
# ¹ https://www.debian.org/vote/2022/vote_003
firmware_component = 'non-free-firmware'
firmware_component_old = 'non-free'

# wireless firmware:
wireless_firmware = 'firmware-brcm80211'

# bluetooth firmware:
bluetooth_firmware = 'bluez-firmware'

# We're pulling suricata from backports
backports_enable = False
backports_suite = '%s-backports' % suite

# Serial console:
if version in ['4', '5']:
    serial = 'ttyS1,115200'

# Model-specific recipe steps that must run before the initial kernel install.
extra_pre_apt_steps = []
if version == '5':
    extra_pre_apt_steps = [
        '# Pi 5 USB is provided through RP1. Include and preload the complete',
        '# controller and storage chain so the root filesystem can be on USB.',
        '- shell: |',
        '    mkdir -p "${ROOT?}/etc/dracut.conf.d"',
        '  root-fs: tag-root',
        '',
        '- create-file: /etc/dracut.conf.d/raspi-usb.conf',
        '  contents: |',
        '    hostonly="no"',
        '    force_drivers+=" irq_bcm2712_mip rp1_pci xhci_hcd xhci_plat_hcd usb_storage uas sd_mod scsi_mod "',
        '',
        '# Force the D-step Pi 5 device tree. Keeping this in raspi-firmware-custom',
        '# ensures later kernel and firmware updates preserve the setting.',
        '- create-file: /etc/default/raspi-firmware-custom',
        '  contents: |',
        '    device_tree=bcm2712-d-rpi-5-b.dtb',
    ]

extra_chroot_shell_cmds = []
final_chroot_shell_cmds = []

# raspi-firmware adds cma=64M by default. Remove it for Raspberry Pi 4,
# where Debian warns that explicitly setting CMA may prevent boot.
# Raspberry Pi 5 has been tested successfully with the default value.
if version == '4':
    extra_chroot_shell_cmds.append(
        "sed -E -i 's/(^|[[:space:]])cma=64M([[:space:]]|$)/\\1/' /boot/firmware/cmdline.txt"
    )

# Hostname:
hostname = 'Hedgehog-rpi-%s' % version

extra_root_shell_cmds = [
    'cp sensor_install.sh "${ROOT?}/root/"',
    '/bin/bash -c \'mkdir -p "${ROOT?}/opt/"{deps,hooks}\'',
    '/bin/bash -x -c \'pushd "%s/" ; git ls-files --exclude-standard | rsync -R --files-from=- ./ "${ROOT?}/opt/Malcolm/"; rsync -av ./.git/ "${ROOT?}/opt/Malcolm/.git/"; rsync -a ./hedgehog-raspi/shared/ ${ROOT?}/opt/buildshared/; popd\''
    % (MALCOLM_DIR),
]

extra_chroot_shell_cmds.extend(
    [
        'chmod 755 /root/sensor_install.sh',
        'bash -o pipefail -x /root/sensor_install.sh 2>&1 | tee -a /root/sensor_install_debug',
    ]
)

if version == '5':
    extra_chroot_shell_cmds.extend(
        [
            # Regenerate after all sensor packages and hooks have run so both
            # /boot and /boot/firmware contain the final RP1-capable initramfs.
            'update-initramfs -u -k all',
            "grep -Fxq 'device_tree=bcm2712-d-rpi-5-b.dtb' /boot/firmware/config.txt",
            "for initrd in /boot/initrd.img-*; do "
            "lsinitrd \"$initrd\" | grep -q '/irq-bcm2712-mip[.]ko' || exit 1; "
            "lsinitrd \"$initrd\" | grep -q '/rp1_pci[.]ko' || exit 1; "
            "done",
        ]
    )

# sensor_install.sh leaves these mounted so any final initramfs generation
# runs in a supported environment. Unmount them only after all chroot work.
final_chroot_shell_cmds = [
    'for target in /dev/pts /run /dev /sys /proc; do',
    '    if mountpoint -q "$target"; then',
    '        umount "$target"',
    '    fi',
    'done',
]

### The following prepares substitutions based on variables set earlier

# Enable backports with a reason, or add commented-out entry:
if backports_enable:
    backports_stanza = """
deb http://deb.debian.org/debian/ %s main contrib non-free %s
""" % (
        backports_suite,
        firmware_component,
    )
else:
    backports_stanza = """
# Backports are _not_ enabled by default.
# Enable them by uncommenting the following line:
# deb http://deb.debian.org/debian/ %s main contrib non-free %s
""" % (
        backports_suite,
        firmware_component,
    )

# gitcommit = subprocess.getoutput("git show -s --pretty='format:%C(auto)%h (%s, %ad)' --date=short ")
buildtime = subprocess.getoutput("date --utc +'%Y-%m-%d %H:%M'")

### Write results:


def align_replace(text, pattern, replacement):
    """
    This helper lets us keep the indentation of the matched pattern
    with the upcoming replacement, across multiple lines. Naive
    implementation, please make it more pythonic!
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r'^(\s+)%s' % pattern, line)
        if m:
            indent = m.group(1)
            del lines[i]
            for r in replacement:
                lines.insert(i, '%s%s' % (indent, r))
                i = i + 1
            break
    return '\n'.join(lines) + '\n'


with open('raspi_master.yaml', 'r') as in_file:
    with open(target_yaml, 'w') as out_file:
        in_text = in_file.read()
        out_text = (
            in_text.replace('__RELEASE__', suite)
            .replace('__ARCH__', arch)
            .replace('__FIRMWARE_COMPONENT__', firmware_component)
            .replace('__FIRMWARE_COMPONENT_OLD__', firmware_component_old)
            .replace('__LINUX_IMAGE__', linux)
            .replace('__DTB__', dtb)
            .replace('__WIRELESS_FIRMWARE__', wireless_firmware)
            .replace('__BLUETOOTH_FIRMWARE__', bluetooth_firmware)
            .replace('__SERIAL_CONSOLE__', serial)
            .replace('__HOST__', hostname)
            .replace('__BUILDTIME__', buildtime)
        )
        #            .replace('__GITCOMMIT__', gitcommit) \
        #            .replace('__BUILDTIME__', buildtime)

        out_text = align_replace(out_text, '- __EXTRA_PRE_APT_STEPS__', extra_pre_apt_steps)
        out_text = align_replace(out_text, '__EXTRA_ROOT_SHELL_CMDS__', extra_root_shell_cmds)
        out_text = align_replace(out_text, '__EXTRA_CHROOT_SHELL_CMDS__', extra_chroot_shell_cmds)
        out_text = align_replace(out_text, '__FINAL_CHROOT_SHELL_CMDS__', final_chroot_shell_cmds)
        out_text = align_replace(out_text, '__BACKPORTS__', backports_stanza.splitlines())

        # Try not to keep lines where the placeholder was replaced
        # with nothing at all (including on a "list item" line):
        filtered = [x for x in out_text.splitlines() if not re.match(r'^\s+$', x) and not re.match(r'^\s+-\s*$', x)]
        out_file.write('\n'.join(filtered) + "\n")
