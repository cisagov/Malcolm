#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

set -e

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

CONTROL_VARS_FILE="control_vars.conf"
source "$CONTROL_VARS_FILE"

if [ -n "$PCAP_PATH" ] && [ "$PCAP_PATH" != "/" ] && [ -d "$PCAP_PATH" ] ; then
  PCAP_SIZE="$(du -sh "$PCAP_PATH"/ 2>/dev/null | cut -f1)"
  rm -rf "$PCAP_PATH"/* && echo "Removed $PCAP_SIZE from packet capture path"
fi
if [ -n "$ZEEK_LOG_PATH" ] && [ "$ZEEK_LOG_PATH" != "/" ] && [ -d "$ZEEK_LOG_PATH" ] ; then
  ZEEK_SIZE="$(du -sh "$ZEEK_LOG_PATH"/ 2>/dev/null | cut -f1)"
  rm -rf "$ZEEK_LOG_PATH"/* && echo "Removed $ZEEK_SIZE from Zeek log path"
fi

popd >/dev/null 2>&1
