#!/usr/bin/env bash

set -uo pipefail

if (( EUID != 0 )); then
    printf 'Run this validator with sudo: sudo %s\n' "$0" >&2
    exit 2
fi

failures=0
warnings=0

section() {
    printf '\n=== %s ===\n' "$1"
}

pass() {
    printf 'PASS: %s\n' "$1"
}

warn() {
    printf 'WARN: %s\n' "$1"
    warnings=$((warnings + 1))
}

fail() {
    printf 'FAIL: %s\n' "$1"
    failures=$((failures + 1))
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

show_file() {
    local label="$1"
    local path="$2"

    if [[ -r "$path" ]]; then
        printf '%s: %s\n' "$label" "$(tr -d '\000' < "$path")"
    else
        warn "$label is unavailable at $path"
    fi
}

require_config() {
    local symbol="$1"
    local value

    value="$(grep -E "^${symbol}=(y|m)$" "$kernel_config" 2>/dev/null || true)"
    if [[ -n "$value" ]]; then
        pass "$value"
    else
        fail "$symbol is not enabled in $kernel_config"
    fi
}

require_line() {
    local line="$1"
    local file="$2"

    if grep -Fxq "$line" "$file" 2>/dev/null; then
        pass "$line"
    else
        fail "$line is missing from $file"
    fi
}

model_text="$(tr -d '\000' < /proc/device-tree/model 2>/dev/null || true)"
case "$model_text" in
    *"Raspberry Pi 4"*|*"Raspberry Pi 400"*|*"Compute Module 4"*)
        pi_model=4
        ;;
    *"Raspberry Pi 5"*|*"Raspberry Pi 500"*|*"Compute Module 5"*)
        pi_model=5
        ;;
    *)
        printf 'FAIL: unsupported or unidentified hardware: %s\n' "${model_text:-unknown}" >&2
        exit 2
        ;;
esac

kernel_release="$(uname -r)"
kernel_config="/boot/config-$kernel_release"
kernel_log="$(dmesg 2>/dev/null || journalctl -k -b --no-pager 2>/dev/null || true)"
config_file=/boot/firmware/config.txt
cmdline_file=/boot/firmware/cmdline.txt
persistent_cmdline=/etc/default/raspi-extra-cmdline

section "hardware and kernel"
printf 'model: %s\n' "$model_text"
printf 'detected family: Raspberry Pi %s\n' "$pi_model"
printf 'release: %s\n' "$kernel_release"
printf 'architecture: %s\n' "$(uname -m)"
printf 'page size: %s\n' "$(getconf PAGESIZE)"

[[ "$(uname -m)" == "aarch64" ]] && pass "64-bit ARM kernel" || fail "kernel architecture is not aarch64"
[[ "$(getconf PAGESIZE)" == "4096" ]] && pass "4 KiB page size" || warn "page size differs from 4096 bytes"
[[ -r "$kernel_config" ]] && pass "$kernel_config is readable" || fail "$kernel_config is unavailable"

if (( pi_model == 5 )); then
    [[ "$kernel_release" == *hedgehog-rpi* ]] &&
        pass "Hedgehog Raspberry Pi kernel is running" ||
        fail "Pi 5 is not running the Hedgehog downstream kernel"
else
    [[ "$kernel_release" == *arm64* ]] &&
        pass "Pi 4 is running an ARM64 kernel package" ||
        fail "unexpected Pi 4 kernel release"
fi

for symbol in \
    CONFIG_THERMAL \
    CONFIG_BCM2711_THERMAL \
    CONFIG_PCIE_BRCMSTB \
    CONFIG_DRM_VC4 \
    CONFIG_DRM_V3D \
    CONFIG_FB_SIMPLE \
    CONFIG_USB_XHCI_HCD \
    CONFIG_USB_XHCI_PCI \
    CONFIG_USB_STORAGE \
    CONFIG_USB_UAS; do
    require_config "$symbol"
done

if (( pi_model == 5 )); then
    for symbol in \
        CONFIG_SENSORS_PWM_FAN \
        CONFIG_PWM_RP1 \
        CONFIG_MFD_RP1 \
        CONFIG_ARM64_4K_PAGES; do
        require_config "$symbol"
    done
fi

section "USB root and filesystems"
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS / || true
findmnt -no TARGET,SOURCE,FSTYPE,OPTIONS /boot/firmware || true
lsblk -o NAME,TRAN,SIZE,FSTYPE,LABEL,MOUNTPOINTS

root_source="$(findmnt -no SOURCE / 2>/dev/null || true)"
root_label="$(findmnt -no LABEL / 2>/dev/null || true)"
firmware_label="$(findmnt -no LABEL /boot/firmware 2>/dev/null || true)"
[[ "$root_label" == "RASPIROOT" ]] && pass "root label is RASPIROOT" || fail "root label is '${root_label:-unknown}'"
[[ "$firmware_label" == "RASPIFIRM" ]] && pass "firmware label is RASPIFIRM" || fail "firmware label is '${firmware_label:-unknown}'"

root_parent="$(lsblk -ndo PKNAME "$root_source" 2>/dev/null || true)"
root_transport=""
if [[ -n "$root_parent" ]]; then
    root_transport="$(lsblk -ndo TRAN "/dev/$root_parent" 2>/dev/null || true)"
fi
[[ "$root_transport" == "usb" ]] && pass "root filesystem is on USB storage" || fail "root transport is '${root_transport:-unknown}'"

section "boot configuration"
require_line 'upstream_kernel=1' "$config_file"

if (( pi_model == 5 )); then
    for entry in \
        'device_tree=bcm2712-d-rpi-5-b.dtb' \
        'dtoverlay=vc4-kms-v3d-pi5,cma-256' \
        'max_framebuffers=2' \
        'disable_fw_kms_setup=1' \
        'dtparam=cooling_fan=on'; do
        require_line "$entry" "$config_file"
    done
    [[ -s /boot/firmware/bcm2712-d-rpi-5-b.dtb ]] &&
        pass "Pi 5 D-step DTB is installed" ||
        fail "Pi 5 D-step DTB is missing"
    [[ -s /boot/firmware/overlays/vc4-kms-v3d-pi5.dtbo ]] &&
        pass "Pi 5 VC4 overlay is installed" ||
        fail "Pi 5 VC4 overlay is missing"
    require_line 'CMA=0' /etc/default/raspi-firmware
else
    [[ -s /boot/firmware/bcm2711-rpi-4-b.dtb ]] &&
        pass "Pi 4 DTB is installed" ||
        fail "Pi 4 DTB is missing"
fi

for boot_file in \
    "/boot/firmware/vmlinuz-$kernel_release" \
    "/boot/firmware/initrd.img-$kernel_release"; do
    [[ -s "$boot_file" ]] && pass "$boot_file" || fail "$boot_file is missing or empty"
done

disk_cmdline_has_cma=false
if tr ' ' '\n' < "$cmdline_file" 2>/dev/null | grep -Eq '^cma='; then
    disk_cmdline_has_cma=true
fi

for source in /proc/cmdline "$cmdline_file"; do
    if tr ' ' '\n' < "$source" 2>/dev/null | grep -Fxq 'root=LABEL=RASPIROOT'; then
        pass "$source selects RASPIROOT"
    else
        fail "$source does not select root=LABEL=RASPIROOT"
    fi

    cma_argument="$(tr ' ' '\n' < "$source" 2>/dev/null | grep -E '^cma=' | head -n1 || true)"
    if [[ -n "$cma_argument" ]]; then
        if (( pi_model == 4 )) && [[ "$source" == /proc/cmdline ]] && ! $disk_cmdline_has_cma; then
            warn "running kernel has $cma_argument, but cmdline.txt is repaired; reboot once before final validation"
        else
            fail "$source contains $cma_argument"
        fi
    else
        pass "$source has no cma= argument"
    fi
done

if (( pi_model == 5 )); then
    for source in /proc/cmdline "$cmdline_file" "$persistent_cmdline"; do
        if tr ' ' '\n' < "$source" 2>/dev/null |
            grep -Eq '^(module_blacklist|modprobe[.]blacklist|rd[.]driver[.]blacklist)=vc4$'; then
            fail "$source contains a VC4 blacklist"
        else
            pass "$source has no VC4 blacklist"
        fi
    done
    [[ ! -e /etc/modprobe.d/hedgehog-vc4.conf ]] &&
        pass "temporary VC4 modprobe restriction is absent" ||
        fail "/etc/modprobe.d/hedgehog-vc4.conf still exists"
fi

cmdline_lines="$(wc -l < "$cmdline_file" 2>/dev/null || printf '0')"
[[ "$cmdline_lines" == "1" ]] && pass "cmdline.txt contains one physical line" || fail "cmdline.txt contains $cmdline_lines lines"

if grep -Fxq "kernel=vmlinuz-$kernel_release" "$config_file" 2>/dev/null; then
    pass "config.txt selects the running kernel"
else
    fail "config.txt does not select vmlinuz-$kernel_release"
fi

if grep -Fxq "initramfs initrd.img-$kernel_release" "$config_file" 2>/dev/null; then
    pass "config.txt selects the matching initramfs"
else
    fail "config.txt does not select initrd.img-$kernel_release"
fi

section "CMA"
cma_total="$(awk '/^CmaTotal:/ {print $2}' /proc/meminfo)"
cma_free="$(awk '/^CmaFree:/ {print $2}' /proc/meminfo)"
printf 'CmaTotal: %s kB\n' "${cma_total:-unknown}"
printf 'CmaFree: %s kB\n' "${cma_free:-unknown}"

if (( pi_model == 5 )); then
    [[ "$cma_total" == "262144" ]] && pass "runtime CMA size is 256 MiB" || fail "runtime CMA size is not 256 MiB"

    live_cma_size=/proc/device-tree/reserved-memory/linux,cma/size
    if [[ -r "$live_cma_size" ]]; then
        live_cma_bytes="$(wc -c < "$live_cma_size")"
        live_cma_hex="$(od -An -tx1 -v "$live_cma_size" | tr -d ' \n')"
        printf 'DT linux,cma size: %s bytes, %s\n' "$live_cma_bytes" "$live_cma_hex"
        [[ "$live_cma_bytes" == "8" ]] && pass "live CMA size uses two cells" || fail "live CMA size is not eight bytes"
        [[ "$live_cma_hex" == "0000000010000000" ]] && pass "live DT requests 256 MiB CMA" || fail "unexpected live CMA size"
    else
        fail "live linux,cma size property is missing"
    fi

    cma_line="$(grep -m1 'created CMA memory pool at' <<< "$kernel_log" || true)"
    printf '%s\n' "${cma_line:-CMA allocation log line unavailable}"
    cma_address="$(sed -nE 's/.* at (0x[0-9a-fA-F]+),.*/\1/p' <<< "$cma_line")"
    if [[ "$cma_address" =~ ^0x[0-9a-fA-F]+$ ]] && (( cma_address < 0x40000000 )); then
        pass "CMA begins below the firmware mailbox 1 GiB limit"
    else
        fail "CMA address is missing or outside the first 1 GiB"
    fi
else
    pass "Pi 4 uses its device-tree CMA configuration"
fi

section "firmware mailbox, CPU scaling, and RTC"
mailbox_errors="$(grep -Ei \
    'returned status|mailbox.*(fail|error)|raspberrypi-clk.*failed|vc4_hvs.*Couldn.t get core clock|rpi-rtc.*failed' \
    <<< "$kernel_log" || true)"
if [[ -z "$mailbox_errors" ]]; then
    pass "no mailbox or firmware-clock errors were logged"
else
    fail "mailbox or firmware-dependent driver errors were logged"
    printf '%s\n' "$mailbox_errors"
fi

policy=/sys/devices/system/cpu/cpufreq/policy0
if [[ -d "$policy" ]]; then
    show_file scaling_driver "$policy/scaling_driver"
    show_file scaling_governor "$policy/scaling_governor"
    show_file scaling_cur_freq "$policy/scaling_cur_freq"
    show_file cpuinfo_min_freq "$policy/cpuinfo_min_freq"
    show_file cpuinfo_max_freq "$policy/cpuinfo_max_freq"
    scaling_driver="$(< "$policy/scaling_driver")"
    case "$pi_model:$scaling_driver" in
        5:cpufreq-dt|4:raspberrypi-cpufreq|4:cpufreq-dt)
            pass "CPU-frequency scaling driver is appropriate for Pi $pi_model"
            ;;
        *)
            fail "unexpected CPU-frequency scaling driver: $scaling_driver"
            ;;
    esac
else
    fail "CPU-frequency scaling policy0 is missing"
fi

if (( pi_model == 5 )); then
    if [[ -e /dev/rtc0 ]]; then
        pass "/dev/rtc0 exists"
        if has_cmd hwclock; then
            if rtc_value="$(hwclock --show --utc 2>&1)"; then
                printf 'RTC: %s\n' "$rtc_value"
                pass "RTC can be read"
            else
                fail "hwclock could not read the RTC: $rtc_value"
            fi
        else
            warn "hwclock is unavailable"
        fi
    else
        fail "/dev/rtc0 is missing"
    fi
else
    [[ -e /dev/rtc0 ]] && pass "an RTC device is available" || pass "Pi 4 has no required onboard RTC"
fi

if has_cmd vcgencmd; then
    if firmware_temp="$(vcgencmd measure_temp 2>&1)"; then
        printf '%s\n' "$firmware_temp"
        pass "vcgencmd can use the firmware mailbox"
    else
        fail "vcgencmd failed: $firmware_temp"
    fi
else
    printf 'INFO: vcgencmd is unavailable; kernel mailbox checks were used\n'
fi

section "display and console"
lsmod | grep -E '^(vc4|v3d|drm)' || true
for module in vc4 v3d; do
    grep -q "^$module " /proc/modules && pass "$module is loaded" || fail "$module is not loaded"
done
[[ -c /dev/fb0 ]] && pass "/dev/fb0 exists" || fail "/dev/fb0 is missing"
show_file framebuffer_name /sys/class/graphics/fb0/name
[[ -r /sys/class/graphics/fb0/name && "$(< /sys/class/graphics/fb0/name)" == "vc4drmfb" ]] &&
    pass "VC4 owns the framebuffer" ||
    fail "framebuffer is not vc4drmfb"
[[ -c /dev/dri/card0 ]] && pass "/dev/dri/card0 exists" || fail "/dev/dri/card0 is missing"
[[ -c /dev/dri/renderD128 ]] && pass "/dev/dri/renderD128 exists" || fail "/dev/dri/renderD128 is missing"
systemctl is-active --quiet getty@tty1.service && pass "tty1 login service is active" || fail "tty1 login service is not active"

display_errors="$(grep -Ei \
    'vc4.*(fail|error)|v3d.*(fail|error)|drm.*(fail|error)|Couldn.t stop firmware display driver|Couldn.t get core clock' \
    <<< "$kernel_log" || true)"
if [[ -z "$display_errors" ]]; then
    pass "no VC4, V3D, or DRM failures were logged"
else
    fail "display-driver errors were logged"
    printf '%s\n' "$display_errors"
fi

section "thermal sensor and cooling"
thermal_zone=""
for zone in /sys/class/thermal/thermal_zone*; do
    [[ -r "$zone/type" ]] || continue
    if [[ "$(< "$zone/type")" == "cpu-thermal" ]]; then
        thermal_zone="$zone"
        break
    fi
done

if [[ -n "$thermal_zone" ]]; then
    temperature="$(< "$thermal_zone/temp")"
    printf 'zone: %s\n' "$(< "$thermal_zone/type")"
    awk -v value="$temperature" 'BEGIN { printf "temperature: %.1f C\n", value / 1000 }'
    (( temperature > 0 && temperature < 110000 )) && pass "temperature is plausible" || fail "temperature is outside the expected range"
else
    fail "CPU thermal zone is missing"
fi

if (( pi_model == 5 )); then
    for module in pwm_rp1 pwm_fan; do
        grep -q "^$module " /proc/modules && pass "$module is loaded" || fail "$module is not loaded"
    done

    fan_device=""
    for device in /sys/class/thermal/cooling_device*; do
        [[ -r "$device/type" ]] || continue
        if [[ "$(< "$device/type")" == "pwm-fan" ]]; then
            fan_device="$device"
            break
        fi
    done
    if [[ -n "$fan_device" ]]; then
        printf 'fan device: %s\n' "$fan_device"
        printf 'fan state: %s/%s\n' "$(< "$fan_device/cur_state")" "$(< "$fan_device/max_state")"
        pass "pwm-fan cooling device is registered"
    else
        fail "pwm-fan cooling device is missing"
    fi

    fan_hwmon=""
    for hwmon in /sys/class/hwmon/hwmon*; do
        [[ -r "$hwmon/name" ]] || continue
        [[ "$(< "$hwmon/name")" == "pwmfan" ]] && fan_hwmon="$hwmon" && break
    done
    if [[ -n "$fan_hwmon" ]]; then
        show_file fan_pwm "$fan_hwmon/pwm1"
        show_file fan_pwm_enable "$fan_hwmon/pwm1_enable"
        [[ -r "$fan_hwmon/fan1_input" ]] && show_file fan_rpm "$fan_hwmon/fan1_input"
        pass "fan hwmon device is registered"
    else
        fail "fan hwmon device is missing"
    fi
else
    pass "onboard PWM fan checks do not apply to Pi 4"
fi

section "initramfs and USB-root drivers"
initrd="/boot/initrd.img-$kernel_release"
modules_builtin="/lib/modules/$kernel_release/modules.builtin"
if [[ -r "$initrd" && -r "$modules_builtin" ]] && (has_cmd lsinitrd || has_cmd lsinitramfs); then
    if has_cmd lsinitrd; then
        initrd_listing="$(lsinitrd "$initrd" 2>/dev/null || true)"
        pass "read initramfs contents with lsinitrd"
    else
        initrd_listing="$(lsinitramfs "$initrd" 2>/dev/null || true)"
        pass "read initramfs contents with lsinitramfs"
    fi
    builtin_listing="$(tr '_' '-' < "$modules_builtin")"
    normalized_initrd_listing="$(tr '_' '-' <<< "$initrd_listing")"

    drivers=(pcie-brcmstb xhci-hcd xhci-pci usb-storage uas sd-mod scsi-mod)
    if (( pi_model == 5 )); then
        drivers+=(irq-bcm2712-mip rp1 xhci-plat-hcd)
    fi

    for driver in "${drivers[@]}"; do
        if grep -Eq "/${driver}[.]ko([.]|$)" <<< "$builtin_listing" ||
            grep -Eq "/${driver}[.]ko([.]|$)" <<< "$normalized_initrd_listing"; then
            pass "$driver is built in or present in the initramfs"
        else
            fail "$driver is absent from both modules.builtin and the initramfs"
        fi
    done
else
    fail "no initramfs listing tool, initramfs, or modules.builtin is available"
fi

if [[ -r "/boot/firmware/initrd.img-$kernel_release" ]]; then
    root_hash="$(sha256sum "$initrd" | awk '{print $1}')"
    firmware_hash="$(sha256sum "/boot/firmware/initrd.img-$kernel_release" | awk '{print $1}')"
    [[ "$root_hash" == "$firmware_hash" ]] &&
        pass "/boot and firmware initramfs copies match" ||
        fail "/boot and firmware initramfs copies differ"
fi

section "Wi-Fi and Bluetooth"
for package in firmware-brcm80211 bluez-firmware raspi-firmware; do
    package_status="$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "$package" 2>/dev/null || true)"
    printf '%s: %s\n' "$package" "${package_status:-not installed}"
    [[ "$package_status" == ii\ * ]] && pass "$package is installed" || fail "$package is not installed"
done

if [[ -d /sys/class/net/wlan0 ]]; then
    pass "wlan0 exists"
    ip -brief link show wlan0 || true
else
    fail "wlan0 is missing"
fi

if grep -q 'brcmf_c_preinit_dcmds: Firmware:' <<< "$kernel_log"; then
    pass "Broadcom Wi-Fi firmware initialized"
else
    fail "successful Broadcom Wi-Fi firmware initialization was not logged"
fi

if [[ -d /sys/class/bluetooth/hci0 ]]; then
    pass "Bluetooth hci0 exists"
    if has_cmd bluetoothctl; then
        if bluetooth_status="$(bluetoothctl show 2>&1)"; then
            printf '%s\n' "$bluetooth_status"
            pass "Bluetooth controller responds to bluetoothctl"
        else
            warn "bluetoothctl could not query hci0: $bluetooth_status"
        fi
    fi
else
    fail "Bluetooth hci0 is missing"
fi

if grep -Eq 'Bluetooth: hci0: BCM' <<< "$kernel_log"; then
    pass "Broadcom Bluetooth firmware initialized"
elif [[ -d /sys/class/bluetooth/hci0 ]]; then
    warn "hci0 is operational, but its firmware initialization line is absent from the retained kernel log"
else
    fail "successful Broadcom Bluetooth firmware initialization was not logged"
fi

section "Ethernet"
if [[ -d /sys/class/net/eth0 ]]; then
    pass "eth0 exists"
    ip -brief link show eth0 || true
    if has_cmd ethtool; then
        ethtool eth0 2>/dev/null | grep -E 'Speed:|Duplex:|Link detected:' || true
    else
        warn "ethtool is unavailable"
    fi
else
    fail "eth0 is missing"
fi

section "memory, cgroups, and Docker"
free -h
printf 'online CPUs: %s\n' "$(nproc)"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] && pass "cgroup v2 is active" || fail "cgroup v2 is not active"
grep -wq memory /sys/fs/cgroup/cgroup.controllers && pass "cgroup memory controller is available" || fail "cgroup memory controller is missing"
if has_cmd docker; then
    if systemctl is-active --quiet docker; then
        pass "Docker service is active"
        docker info --format 'driver={{.Driver}} cgroup={{.CgroupDriver}} version={{.CgroupVersion}} cpus={{.NCPU}} memory={{.MemTotal}}' 2>/dev/null || warn "docker info failed"
    else
        fail "Docker service is not active"
    fi
else
    warn "Docker is unavailable"
fi

section "camera and hardware codecs"
if (( pi_model == 5 )); then
    for symbol in \
        CONFIG_VIDEO_RPI_HEVC_DEC \
        CONFIG_VIDEO_CODEC_BCM2835 \
        CONFIG_VIDEO_RASPBERRYPI_PISP_BE \
        CONFIG_VIDEO_RP1_CFE \
        CONFIG_VIDEO_RP1_CFE_DOWNSTREAM; do
        require_config "$symbol"
    done

    for module in rpi_hevc_dec pisp_be; do
        grep -q "^$module " /proc/modules && pass "$module is loaded" || fail "$module is not loaded"
    done

    video_names="$(for device in /sys/class/video4linux/video*; do [[ -r "$device/name" ]] && cat "$device/name"; done)"
    grep -Fxq 'rpi-hevc-dec' <<< "$video_names" && pass "HEVC decoder registered" || fail "HEVC decoder is missing"
    pisp_count="$(grep -Fxc 'pispbe-input' <<< "$video_names" || true)"
    [[ "$pisp_count" == "2" ]] && pass "both PiSP instances registered" || fail "expected two PiSP instances, found $pisp_count"

    if has_cmd media-ctl; then
        pisp_media_count=0
        hevc_media_count=0
        for media_device in /dev/media*; do
            [[ -c "$media_device" ]] || continue
            if ! topology="$(media-ctl --device="$media_device" --print-topology 2>&1)"; then
                fail "unable to read the topology for $media_device"
                printf '%s\n' "$topology"
                continue
            fi

            if grep -Eq '^driver[[:space:]]+pispbe$' <<< "$topology"; then
                pisp_media_count=$((pisp_media_count + 1))
                for entity in pispbe-input pispbe-output0 pispbe-output1 pispbe-config; do
                    grep -Fq "$entity" <<< "$topology" || fail "$media_device is missing $entity"
                done
            elif grep -Eq '^driver[[:space:]]+rpi-hevc-dec$' <<< "$topology"; then
                hevc_media_count=$((hevc_media_count + 1))
                for entity in rpi-hevc-dec-source rpi-hevc-dec-proc rpi-hevc-dec-sink; do
                    grep -Fq "$entity" <<< "$topology" || fail "$media_device is missing $entity"
                done
            fi
        done

        [[ "$pisp_media_count" == "2" ]] &&
            pass "two complete PiSP media graphs are registered" ||
            fail "expected two PiSP media controllers, found $pisp_media_count"
        [[ "$hevc_media_count" == "1" ]] &&
            pass "one complete HEVC media graph is registered" ||
            fail "expected one HEVC media controller, found $hevc_media_count"
    else
        warn "media-ctl is unavailable; topology checks were skipped"
    fi

    if grep -q '^rp1_cfe ' /proc/modules || grep -q '^rp1_cfe_downstream ' /proc/modules; then
        pass "RP1 camera front-end driver is loaded"
    else
        warn "RP1 CFE is idle; camera capture requires a connected sensor and overlay"
    fi
else
    codec_config="$(grep -E '^CONFIG_VIDEO_CODEC_BCM2835=(y|m)$' "$kernel_config" 2>/dev/null || true)"
    if [[ -n "$codec_config" ]]; then
        pass "$codec_config"
    else
        warn "Debian's generic Pi 4 kernel does not enable the downstream BCM2835 legacy codec"
    fi

    if grep -q '^bcm2835_codec ' /proc/modules; then
        pass "bcm2835-codec is loaded"
    elif [[ -n "$codec_config" ]]; then
        warn "bcm2835-codec is enabled but idle; runtime media devices depend on configuration and attached hardware"
    fi
fi

if has_cmd v4l2-ctl; then
    v4l2_devices="$(v4l2-ctl --list-devices 2>/dev/null || true)"
    printf '%s\n' "${v4l2_devices:-no V4L2 devices enumerated}"
else
    fail "v4l2-ctl is unavailable even though v4l-utils should be installed"
fi

section "system health"
failed_units="$(systemctl --failed --no-legend --plain 2>/dev/null || true)"
if [[ -z "$failed_units" ]]; then
    pass "systemd has no failed units"
else
    fail "systemd has failed units"
    printf '%s\n' "$failed_units"
fi

kernel_faults="$(grep -Ei \
    'kernel panic|BUG:|Oops:|Call Trace:|EXT4-fs error|I/O error|segfault|general protection fault' \
    <<< "$kernel_log" || true)"
if [[ -z "$kernel_faults" ]]; then
    pass "no serious kernel faults were found"
else
    fail "serious kernel messages were found"
    printf '%s\n' "$kernel_faults"
fi

perf_count="$(grep -Ec 'perf: interrupt took too long.*lowering kernel[.]perf_event_max_sample_rate' <<< "$kernel_log" || true)"
wifi_ps_count="$(grep -Fc 'brcmf_cfg80211_set_power_mgmt: power save enabled' <<< "$kernel_log" || true)"
printf 'INFO: perf sampling was automatically throttled %s time(s)\n' "$perf_count"
printf 'INFO: Wi-Fi power saving was enabled %s time(s)\n' "$wifi_ps_count"

section "result"
printf 'model: Raspberry Pi %s\n' "$pi_model"
printf 'failures: %d\n' "$failures"
printf 'warnings: %d\n' "$warnings"

if (( failures == 0 )); then
    printf 'OVERALL: PASS\n'
    exit 0
fi

printf 'OVERALL: FAIL\n'
exit 1

