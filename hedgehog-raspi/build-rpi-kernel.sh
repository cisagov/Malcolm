#!/bin/bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 OUTPUT_DEB" >&2
    exit 2
fi

output_deb="$(realpath -m "$1")"
output_dir="$(dirname "$output_deb")"
build_root="${output_dir}/rpi-kernel"
source_dir="${build_root}/linux"
package_dir="${build_root}/packages"
overlay_cache_dir="${package_dir}/overlays"

rpi_kernel_repo="${RPI_KERNEL_REPO:-https://github.com/raspberrypi/linux.git}"
rpi_kernel_ref="${RPI_KERNEL_REF:-rpi-6.18.y}"
rpi_kernel_jobs="${RPI_KERNEL_JOBS:-$(nproc)}"
reuse_packages="${RPI_KERNEL_REUSE_PACKAGES:-0}"

required_commands=(
    bc bison dpkg-buildpackage dpkg-deb dtc fdtget flex git make rsync
)

for command_name in "${required_commands[@]}"; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Missing Raspberry Pi kernel build command: $command_name" >&2
        exit 1
    fi
done

mkdir -p "$output_dir" "$build_root"

if [[ "$reuse_packages" == "1" ]]; then
    if [[ ! -d "$package_dir" ]]; then
        echo "No completed kernel packages found in $package_dir" >&2
        exit 1
    fi
else
    rm -rf "$source_dir" "$package_dir"
    mkdir -p "$package_dir"

    git clone --depth=1 --branch "$rpi_kernel_ref" "$rpi_kernel_repo" "$source_dir"

    pushd "$source_dir" >/dev/null

    make bcm2712_defconfig
    # Malcolm's native dependencies (fluent-bit) require a 4 KiB userspace page size.
    scripts/config --enable ARM64_4K_PAGES
    scripts/config --disable ARM64_16K_PAGES
    scripts/config --disable ARM64_64K_PAGES

    # Give the package a distinct release and guarantee the drivers used by the
    # Pi 5 temperature sensor, RP1 PWM controller, and four-pin fan connector.
    scripts/config --set-str LOCALVERSION "-hedgehog-rpi"
    scripts/config --disable LOCALVERSION_AUTO
    scripts/config --module BCM2711_THERMAL
    scripts/config --module SENSORS_PWM_FAN
    scripts/config --module PWM_RP1
    scripts/config --module DRM_VC4
    scripts/config --module DRM_V3D
    scripts/config --enable FB_SIMPLE
    make olddefconfig
    grep -Eq '^CONFIG_ARM64_4K_PAGES=y$' .config
    if grep -Eq '^CONFIG_ARM64_(16K|64K)_PAGES=y$' .config; then
        echo "Kernel configuration selected an unsupported page size" >&2
        exit 1
    fi
    grep -Eq '^CONFIG_THERMAL=y$' .config
    grep -Eq '^CONFIG_BCM2711_THERMAL=(y|m)$' .config
    grep -Eq '^CONFIG_SENSORS_PWM_FAN=(y|m)$' .config
    grep -Eq '^CONFIG_PWM_RP1=(y|m)$' .config
    grep -Eq '^CONFIG_DRM_VC4=(y|m)$' .config
    grep -Eq '^CONFIG_DRM_V3D=(y|m)$' .config
    grep -Eq '^CONFIG_FB_SIMPLE=y$' .config

    kernel_version="$(make -s kernelversion)"
    package_version="${kernel_version}-1hedgehog1"

    make -j"$rpi_kernel_jobs" bindeb-pkg KDEB_PKGVERSION="$package_version"

    popd >/dev/null

    find "$build_root" -maxdepth 1 -type f -name '*.deb' -exec mv -t "$package_dir" {} +
fi

# bindeb-pkg installs the board DTBs, but it does not reliably include the
# complete Raspberry Pi overlay set in linux-image. Cache the overlays built
# from the same source revision so reuse mode can repack them without another
# kernel compilation.
if [[ ! -s "$overlay_cache_dir/vc4-kms-v3d-pi5.dtbo" ]]; then
    overlay_source_dir=""
    for candidate in \
        "$source_dir/arch/arm64/boot/dts/overlays" \
        "$source_dir/arch/arm/boot/dts/overlays"; do
        if [[ -s "$candidate/vc4-kms-v3d-pi5.dtbo" ]]; then
            overlay_source_dir="$candidate"
            break
        fi
    done

    if [[ -z "$overlay_source_dir" ]]; then
        echo "Built Pi 5 KMS overlay not found in the kernel source tree" >&2
        exit 1
    fi

    mkdir -p "$overlay_cache_dir"
    rsync -a \
        --include='*.dtbo' \
        --include='README*' \
        --exclude='*' \
        "$overlay_source_dir/" "$overlay_cache_dir/"
fi

if [[ ! -s "$overlay_cache_dir/vc4-kms-v3d-pi5.dtbo" ]]; then
    echo "Missing required cached overlay: vc4-kms-v3d-pi5.dtbo" >&2
    exit 1
fi

if ! grep -aq 'cma-256' "$overlay_cache_dir/vc4-kms-v3d-pi5.dtbo"; then
    echo "Pi 5 KMS overlay does not support the required cma-256 parameter" >&2
    exit 1
fi

mapfile -t image_debs < <(
    find "$package_dir" -maxdepth 1 -type f \
        -name 'linux-image-*_*.deb' \
        ! -name '*-dbg_*' \
        -print
)

if [[ ${#image_debs[@]} -ne 1 ]]; then
    echo "Expected one linux-image package; found ${#image_debs[@]}" >&2
    printf '%s\n' "${image_debs[@]}" >&2
    exit 1
fi

image_deb="${image_debs[0]}"
package_name="$(dpkg-deb -f "$image_deb" Package)"

if [[ "$package_name" != linux-image-* ]]; then
    echo "Unexpected kernel package name: $package_name" >&2
    exit 1
fi

kernel_release="${package_name#linux-image-}"

package_root="$(mktemp -d -p "$build_root" package-check.XXXXXX)"
trap 'rm -rf "$package_root"' EXIT
dpkg-deb -R "$image_deb" "$package_root"

# Add the complete overlay set to the kernel package. The image recipe copies
# this directory to the firmware partition after dpkg installs the kernel.
package_overlay_dir="$package_root/usr/lib/linux-image-${kernel_release}/broadcom/overlays"
install -d -m 0755 "$package_overlay_dir"
rsync -a "$overlay_cache_dir/" "$package_overlay_dir/"

if [[ ! -s "$package_overlay_dir/vc4-kms-v3d-pi5.dtbo" ]]; then
    echo "Kernel package staging tree is missing vc4-kms-v3d-pi5.dtbo" >&2
    exit 1
fi

package_listing="$(find "$package_root" -printf '%P\n')"

require_package_entry() {
    local entry="$1"
    if ! grep -Fq -- "$entry" <<<"$package_listing"; then
        echo "Kernel package is missing required entry: $entry" >&2
        exit 1
    fi
}

require_package_entry "usr/lib/linux-image-${kernel_release}/broadcom/bcm2712-d-rpi-5-b.dtb"
require_package_entry "usr/lib/linux-image-${kernel_release}/broadcom/overlays/vc4-kms-v3d-pi5.dtbo"
require_package_entry "/bcm2711_thermal.ko"
require_package_entry "/pwm-fan.ko"
require_package_entry "/pwm-rp1.ko"
require_package_entry "/vc4.ko"
require_package_entry "/v3d.ko"

package_kernel_config="$package_root/boot/config-${kernel_release}"
if [[ ! -s "$package_kernel_config" ]]; then
    echo "Kernel package is missing configuration: boot/config-${kernel_release}" >&2
    exit 1
fi

require_builtin_driver() {
    local config_symbol="$1"
    local driver_name="$2"

    if ! grep -Fxq "CONFIG_${config_symbol}=y" "$package_kernel_config"; then
        echo "Kernel package is missing built-in driver: $driver_name (CONFIG_${config_symbol}=y)" >&2
        exit 1
    fi
}

require_builtin_driver BCM2712_MIP irq-bcm2712-mip
require_builtin_driver PCIE_BRCMSTB pcie-brcmstb
require_builtin_driver MFD_RP1 rp1
require_builtin_driver USB_XHCI_HCD xhci-hcd
require_builtin_driver USB_XHCI_PLATFORM xhci-plat-hcd
require_builtin_driver USB_STORAGE usb-storage
require_builtin_driver USB_UAS uas

require_kernel_driver() {
    local module_file="$1"
    local module_file_alt
    local modules_dir="$package_root/lib/modules/$kernel_release"

    if [[ "$module_file" == *-* ]]; then
        module_file_alt="${module_file//-/_}"
    else
        module_file_alt="${module_file//_/-}"
    fi

    if find "$modules_dir" -type f \
        \( -name "${module_file}.ko" -o -name "${module_file}.ko.*" \
           -o -name "${module_file_alt}.ko" -o -name "${module_file_alt}.ko.*" \) \
        -print -quit | grep -q .; then
        return
    fi

    if [[ -f "$modules_dir/modules.builtin" ]] &&
        grep -Eq "/(${module_file}|${module_file_alt})[.]ko$" \
            "$modules_dir/modules.builtin"; then
        return
    fi

    echo "Kernel package has neither modular nor built-in driver: $module_file" >&2
    exit 1
}

# The downstream bcm2712_defconfig uses the RP1 MFD driver. Its Pi 5 PCIe,
# RP1, and USB-root path is built into Image and recorded in modules.builtin.
require_kernel_driver "irq-bcm2712-mip"
require_kernel_driver "pcie-brcmstb"
require_kernel_driver "rp1"
require_kernel_driver "xhci-hcd"
require_kernel_driver "xhci-pci"
require_kernel_driver "xhci-plat-hcd"
require_kernel_driver "usb-storage"
require_kernel_driver "uas"

dtb_path="$package_root/usr/lib/linux-image-${kernel_release}/broadcom/bcm2712-d-rpi-5-b.dtb"

root_size_cells="$(fdtget -t x "$dtb_path" / '#size-cells')"
if [[ "$root_size_cells" != "2" ]]; then
    echo "Pi 5 device tree has invalid root #size-cells: $root_size_cells" >&2
    exit 1
fi

cma_size_bytes="$(fdtget -t bx "$dtb_path" /reserved-memory/linux,cma size)"
case "$cma_size_bytes" in
    # Raspberry Pi's base DTB may encode its 64 MiB default in one cell or
    # two. The required cma-256 overlay replaces it with the final two-cell
    # 256 MiB value before Linux parses the device tree.
    "4 0 0 0" | "0 0 0 0 4 0 0 0") ;;
    *)
        echo "Pi 5 device tree has an unexpected linux,cma size: $cma_size_bytes" >&2
        exit 1
        ;;
esac

cma_alloc_ranges_bytes="$(fdtget -t bx "$dtb_path" /reserved-memory/linux,cma alloc-ranges)"
if [[ "$cma_alloc_ranges_bytes" != "0 0 0 0 0 0 0 0 0 0 0 0 40 0 0 0" ]]; then
    echo "Pi 5 device tree has an unsafe linux,cma alloc-ranges value: $cma_alloc_ranges_bytes" >&2
    exit 1
fi

dts_path="$package_root/bcm2712-d-rpi-5-b.dts"
if ! dtc -I dtb -O dts "$dtb_path" >"$dts_path" 2>/dev/null; then
    echo "Unable to decompile required device tree: $dtb_path" >&2
    exit 1
fi

require_dts_entry() {
    local entry="$1"
    if ! grep -Fq -- "$entry" "$dts_path"; then
        echo "Pi 5 device tree is missing required entry: $entry" >&2
        exit 1
    fi
}

require_dts_entry 'cooling_fan'
require_dts_entry 'compatible = "pwm-fan"'
require_dts_entry 'thermal-zones'
rm -f "$dts_path"

# Refresh package checksums after adding the overlays, then build the final
# artifact consumed by vmdb2.
(
    cd "$package_root"
    find . -path './DEBIAN' -prune -o -type f -printf '%P\0' \
        | sort -z \
        | xargs -0 md5sum >DEBIAN/md5sums
)
dpkg-deb --build --root-owner-group "$package_root" "$output_deb"

echo "Built $output_deb ($kernel_release)"
