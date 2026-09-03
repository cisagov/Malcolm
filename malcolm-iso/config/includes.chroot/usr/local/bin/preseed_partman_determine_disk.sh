#!/bin/sh

# Find non-USB fixed-disk candidates. find's -name predicates do the device-type
# filtering (SATA/SAS/IDE sd*/hd*, virtio vd*, Xen xvd*, NVMe nvme*); sed
# extracts the symlink name (between the last '/' and ' -> ') instead of
# re-matching device-name patterns. This avoids partial-name mis-captures such
# as 'vda' from 'xvda', or 'nvme0' from 'nvme0n1'.
NON_USB_DEVICES="$(
  find /sys/block -mindepth 1 -maxdepth 1 -type l \
      \( -name '[hs]d*' -o -name 'vd*' -o -name 'xvd*' -o -name 'nvme*' \) \
      -exec ls -l '{}' ';' |
    grep -v "usb" |
    sed 's@^.*/\([^/ ]*\) -> .*$@/dev/\1@' |
    sed -e :a -e '$!N; s/\n/|/; ta'
)"

if [ -z "$NON_USB_DEVICES" ]; then
  echo "No non-USB installation target found; refusing to select installer media" >&2
  echo "/dev/__malcolm_no_install_target__"
  exit 1
fi

# parted_devices output is tab-separated:
# device<TAB>size-in-bytes<TAB>model<TAB>disk-label-type
#
# Anchor each device match on trailing whitespace so /dev/sda cannot also
# match a /dev/sdab line. Select the smallest eligible device.
SELECTED_DEVICE="$(
  parted_devices |
    grep -E "^(${NON_USB_DEVICES})[[:space:]]" |
    sort -k2,2n |
    head -1 |
    cut -f1
)"

if [ -z "$SELECTED_DEVICE" ]; then
  echo "No eligible installation target reported by parted_devices" >&2
  echo "/dev/__malcolm_no_install_target__"
  exit 1
fi

echo "$SELECTED_DEVICE"
