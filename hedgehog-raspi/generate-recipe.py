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
    dtb = '/usr/lib/linux-image-*-arm64/broadcom/bcm*rpi*.dtb'

# Pi 4 uses Debian's generic arm64 kernel. Pi 5 uses a locally built package
# from Raspberry Pi's downstream kernel tree; the matching DTBs and RP1 PWM
# driver are required for temperature reporting and automatic fan control.
linux_packages = ['linux-image-arm64'] if version == '4' else ['dracut', 'linux-base']
rpi5_kernel_deb = 'build/rpi5-kernel.deb'

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
if version == '4':
    serial = 'ttyS1,115200'
else:
    serial = 'ttyAMA0,115200'

# Model-specific recipe steps that must run before the initial kernel install.
extra_pre_apt_steps = []
if version == '5':
    extra_pre_apt_steps = [
        '# Pi 5 USB is provided through RP1. Include and preload the complete',
        '# controller and storage chain so the root filesystem can be on USB.',
        '- shell: |',
        '    mkdir -p "${ROOT?}/etc/dracut.conf.d"',
        '    rm -f "${ROOT?}/etc/modprobe.d/hedgehog-vc4.conf"',
        '  root-fs: tag-root',
        '',
        '- create-file: /etc/dracut.conf.d/raspi-usb.conf',
        '  contents: |',
        '    hostonly="no"',
        '    force_drivers+=" irq_bcm2712_mip xhci_hcd xhci_plat_hcd usb_storage uas sd_mod scsi_mod "',
        '',
        '# Force the D-step Pi 5 device tree and downstream VC4/KMS display path.',
        '# Keeping these in raspi-firmware-custom makes raspi-firmware preserve',
        '# them when the kernel or firmware package is updated.',
        '- create-file: /etc/default/raspi-firmware-custom',
        '  contents: |',
        '    device_tree=bcm2712-d-rpi-5-b.dtb',
        '    upstream_kernel=1',
        '    dtoverlay=vc4-kms-v3d-pi5,cma-256',
        '    max_framebuffers=2',
        '    disable_fw_kms_setup=1',
        '    dtparam=cooling_fan=on',
    ]

extra_chroot_shell_cmds = []
final_chroot_shell_cmds = []

# raspi-firmware adds cma=64M by default. Remove it for Raspberry Pi 4,
# where Debian warns that explicitly setting CMA may prevent boot. Pi 5
# disables the command-line setting below and sizes a low-memory CMA pool
# through the vc4-kms-v3d-pi5 overlay instead.
if version == '4':
    extra_chroot_shell_cmds.append(
        "sed -E -i 's/(^|[[:space:]])cma=64M([[:space:]]|$)/\\1/' /boot/firmware/cmdline.txt"
    )

# Hostname:
hostname = 'Hedgehog-rpi-%s' % version

extra_root_shell_cmds = [
    'cp sensor_install.sh "${ROOT:?}/root/"',
    '/bin/bash -c \'mkdir -p "${ROOT:?}/opt/"{deps,hooks}\'',
    '/bin/bash -x -c \'set -euo pipefail; pushd "%s/"; git ls-files -z --exclude-standard | rsync -lR --from0 --files-from=- ./ "${ROOT:?}/opt/Malcolm/"; rsync -av ./.git/ "${ROOT:?}/opt/Malcolm/.git/"; rsync -a ./hedgehog-raspi/shared/ "${ROOT:?}/opt/buildshared/"; popd\''
    % (MALCOLM_DIR),
]

if version == '5':
    extra_root_shell_cmds.append(f'install -m 0644 {rpi5_kernel_deb} "${{ROOT?}}/root/rpi5-kernel.deb"')

extra_chroot_shell_cmds.extend(
    [
        'chmod 755 /root/sensor_install.sh',
        'bash -o pipefail -x /root/sensor_install.sh 2>&1 | tee -a /root/sensor_install_debug',
        # NetworkManager owns the interfaces. Prevent ifupdown from competing
        # with it and timing out during boot.
        'systemctl disable networking.service',
    ]
)

if version == '5':
    extra_chroot_shell_cmds.extend(
        [
            # A command-line cma= value bypasses the DT linux,cma node and its
            # alloc-ranges constraint. On a Pi 5 with more than 1 GiB of RAM,
            # that can place CMA above the firmware mailbox address limit.
            # Set this before dpkg installs the kernel so raspi-firmware never
            # writes cma= to the generated command line.
            "if grep -q '^CMA=' /etc/default/raspi-firmware; then",
            "    sed -i 's/^CMA=.*/CMA=0/' /etc/default/raspi-firmware",
            'else',
            "    printf '\\nCMA=0\\n' >> /etc/default/raspi-firmware",
            'fi',
            # Install the matched Raspberry Pi kernel, modules, and DTBs after
            # all other package hooks have run. Debian's generic kernel is not
            # installed for Pi 5, so raspi-firmware selects this kernel.
            'rpi_kernel_package="$(dpkg-deb -f /root/rpi5-kernel.deb Package)"',
            'rpi_kernel_release="${rpi_kernel_package#linux-image-}"',
            'case "$rpi_kernel_package" in linux-image-*) ;; *) echo "Unexpected Pi kernel package: $rpi_kernel_package" >&2; exit 1 ;; esac',
            'dpkg -i /root/rpi5-kernel.deb',
            # bindeb-pkg does not install the complete overlay set to the FAT
            # firmware partition. Copy the overlays packaged from the exact
            # same downstream source revision as the kernel and DTBs.
            'overlay_source="/usr/lib/linux-image-$rpi_kernel_release/broadcom/overlays"',
            'test -s "$overlay_source/vc4-kms-v3d-pi5.dtbo"',
            'install -d -m 0755 /boot/firmware/overlays',
            'cp -a "$overlay_source/." /boot/firmware/overlays/',
            'depmod "$rpi_kernel_release"',
            'if [ -e "/boot/initrd.img-$rpi_kernel_release" ]; then',
            '    update-initramfs -u -k "$rpi_kernel_release"',
            'else',
            '    update-initramfs -c -k "$rpi_kernel_release"',
            'fi',
            # Record the selected release for support and future update hooks.
            'printf "%s\\n" "$rpi_kernel_release" > /etc/hedgehog-rpi-kernel-release',
            'rm -f /root/rpi5-kernel.deb',
            # Validate the downstream configuration needed for USB-root boot,
            # temperature sensing, and the four-pin Pi 5 PWM fan connector.
            'kernel_config="/boot/config-$rpi_kernel_release"',
            "grep -Eq '^CONFIG_THERMAL=y$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_BCM2711_THERMAL=(y|m)$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_SENSORS_PWM_FAN=(y|m)$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_PWM_RP1=(y|m)$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_DRM_VC4=(y|m)$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_DRM_V3D=(y|m)$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_PCIE_BRCMSTB=y$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_MFD_RP1=y$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_ARM64_4K_PAGES=y$' \"$kernel_config\"",
            "grep -Eq '^CONFIG_FB_SIMPLE=y$' \"$kernel_config\"",
            'test -s "/usr/lib/linux-image-$rpi_kernel_release/broadcom/bcm2712-d-rpi-5-b.dtb"',
            'test -s "/boot/firmware/bcm2712-d-rpi-5-b.dtb"',
            'test -s "/boot/firmware/vmlinuz-$rpi_kernel_release"',
            'test -s "/boot/firmware/initrd.img-$rpi_kernel_release"',
            'test -s "/boot/firmware/overlays/vc4-kms-v3d-pi5.dtbo"',
            "grep -Fxq 'device_tree=bcm2712-d-rpi-5-b.dtb' /boot/firmware/config.txt",
            "grep -Fxq 'upstream_kernel=1' /boot/firmware/config.txt",
            "grep -Fxq 'dtoverlay=vc4-kms-v3d-pi5,cma-256' /boot/firmware/config.txt",
            "grep -Fxq 'max_framebuffers=2' /boot/firmware/config.txt",
            "grep -Fxq 'disable_fw_kms_setup=1' /boot/firmware/config.txt",
            'grep -Fxq "kernel=vmlinuz-$rpi_kernel_release" /boot/firmware/config.txt',
            'grep -Fxq "initramfs initrd.img-$rpi_kernel_release" /boot/firmware/config.txt',
            "grep -Fxq 'dtparam=cooling_fan=on' /boot/firmware/config.txt",
            "grep -Fxq 'CMA=0' /etc/default/raspi-firmware",
            "if tr ' ' '\\n' < /boot/firmware/cmdline.txt | grep -Eq '^cma='; then "
            "echo 'Final kernel command line unexpectedly contains cma=' >&2; "
            "cat /boot/firmware/cmdline.txt >&2; exit 1; fi",
            "for cmdline_file in /etc/default/raspi-extra-cmdline /boot/firmware/cmdline.txt; do "
            "if tr ' ' '\\n' < \"$cmdline_file\" | "
            "grep -Eq '^(module_blacklist|modprobe[.]blacklist|rd[.]driver[.]blacklist)=vc4$'; then "
            "echo \"Unexpected VC4 blacklist in $cmdline_file\" >&2; "
            "cat \"$cmdline_file\" >&2; exit 1; fi; done",
            "test ! -e /etc/modprobe.d/hedgehog-vc4.conf",
            "if grep -Eq 'omit_drivers.*vc4' /etc/dracut.conf.d/raspi-usb.conf; then "
            "echo 'VC4 is unexpectedly omitted from the initramfs' >&2; exit 1; fi",
            # Early drivers can be built into Image or supplied by initramfs.
            'modules_builtin="/lib/modules/$rpi_kernel_release/modules.builtin"',
            'grep -Eq "/irq[-_]bcm2712[-_]mip[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/irq[-_]bcm2712[-_]mip[.]ko"',
            'grep -Eq "/pcie[-_]brcmstb[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/pcie[-_]brcmstb[.]ko"',
            'grep -Eq "/rp1[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/rp1[.]ko"',
            'grep -Eq "/xhci[-_]hcd[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/xhci[-_]hcd[.]ko"',
            'grep -Eq "/xhci[-_]plat[-_]hcd[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/xhci[-_]plat[-_]hcd[.]ko"',
            'grep -Eq "/usb[-_]storage[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/usb[-_]storage[.]ko"',
            'grep -Eq "/uas[.]ko$" "$modules_builtin" || lsinitrd "/boot/initrd.img-$rpi_kernel_release" | grep -Eq "/uas[.]ko"',
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
        out_text = align_replace(out_text, '- __LINUX_PACKAGES__', [f'- {package}' for package in linux_packages])
        out_text = align_replace(out_text, '__EXTRA_ROOT_SHELL_CMDS__', extra_root_shell_cmds)
        out_text = align_replace(out_text, '__EXTRA_CHROOT_SHELL_CMDS__', extra_chroot_shell_cmds)
        out_text = align_replace(out_text, '__FINAL_CHROOT_SHELL_CMDS__', final_chroot_shell_cmds)
        out_text = align_replace(out_text, '__BACKPORTS__', backports_stanza.splitlines())

        # Try not to keep lines where the placeholder was replaced
        # with nothing at all (including on a "list item" line):
        filtered = [x for x in out_text.splitlines() if not re.match(r'^\s+$', x) and not re.match(r'^\s+-\s*$', x)]
        out_file.write('\n'.join(filtered) + "\n")
