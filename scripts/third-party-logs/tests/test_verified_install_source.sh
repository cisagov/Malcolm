#!/usr/bin/env bash
set -euo pipefail

# Exercise download, verification and sourcing with a local script.
source "$(dirname "$0")/../verified_install_source.sh"

test_dir="$(mktemp -d /tmp/malcolm-installer-test-XXXXXX)"
trap 'rm -rf "$test_dir"' EXIT
printf 'VERIFIED_INSTALLER_TEST_VALUE=installed\n' > "$test_dir/install.sh"
if command -v sha256sum >/dev/null 2>&1; then
  checksum="$(sha256sum "$test_dir/install.sh" | awk '{print $1}')"
else
  checksum="$(shasum -a 256 "$test_dir/install.sh" | awk '{print $1}')"
fi

verified_source_installer "file://$test_dir/install.sh" "$checksum"
[[ "$VERIFIED_INSTALLER_TEST_VALUE" == installed ]] ||
  { echo 'Verified installer was not sourced' >&2; exit 1; }

VERIFIED_INSTALLER_TEST_VALUE=''
if verified_source_installer "file://$test_dir/install.sh" \
   "0000000000000000000000000000000000000000000000000000000000000000" 2>/dev/null; then
  echo 'Mismatched checksum was accepted' >&2
  exit 1
fi
[[ -z "$VERIFIED_INSTALLER_TEST_VALUE" ]] ||
  { echo 'Tampered installer executed' >&2; exit 1; }

if verified_source_installer "file://$test_dir/missing.sh" "$checksum" 2>/dev/null; then
  echo 'Missing installer was accepted' >&2
  exit 1
fi
if verified_source_installer "file://$test_dir/install.sh" "not-a-hash" 2>/dev/null; then
  echo 'Invalid checksum format was accepted' >&2
  exit 1
fi

printf 'return 7\n' > "$test_dir/failed.sh"
if command -v sha256sum >/dev/null 2>&1; then
  failed_hash="$(sha256sum "$test_dir/failed.sh" | awk '{print $1}')"
else
  failed_hash="$(shasum -a 256 "$test_dir/failed.sh" | awk '{print $1}')"
fi
if verified_source_installer "file://$test_dir/failed.sh" "$failed_hash"; then
  echo 'Sourced installer failure was ignored' >&2
  exit 1
fi

echo '5 verified installer checks passed'
