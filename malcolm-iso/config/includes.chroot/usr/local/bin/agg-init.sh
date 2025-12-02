#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

SCRIPT_PATH="$(dirname $(realpath -e "${BASH_SOURCE[0]}"))"

echo "aggregator" > /etc/installer

if [[ -r "$SCRIPT_PATH"/common-init.sh ]]; then
  . "$SCRIPT_PATH"/common-init.sh

  # remove default accounts/groups we don't want, create/set directories for non-user users for stig to not complain
  CleanDefaultAccounts

  FIRST_RUN=0
  MAIN_USER="$(id -nu 1000)"
  if [[ -n $MAIN_USER ]]; then

    # setup initial user's home directory if it hasn't been done
    InjectSkeleton "$MAIN_USER"

    # fix some permisions to make sure things belong to the right person
    FixPermissions "$MAIN_USER"

    MAIN_USER_HOME="$(getent passwd "$MAIN_USER" | cut -d: -f6)"
    [[ -r "$MAIN_USER_HOME"/Malcolm/.os-info ]] && \
      VARIANT_ID="$(awk -F= '/^VARIANT_ID=/{gsub(/"/,""); print $2}' "$MAIN_USER_HOME"/Malcolm/.os-info)" || \
      VARIANT_ID=

    # if Malcolm's config file has never been touched, configure it now
    if [[ -f "$MAIN_USER_HOME"/Malcolm/firstrun ]]; then
      FIRST_RUN=1
      if [[ -r "$MAIN_USER_HOME"/Malcolm/scripts/install.py ]]; then
        # export the existing config
        SETTINGS_FILE="$(mktemp --suffix=.json)"
        /usr/bin/env python3 "$MAIN_USER_HOME"/Malcolm/scripts/install.py \
          --configure --dry-run --non-interactive --export-malcolm-config-file "${SETTINGS_FILE}"
        # set the restart policy to "unless-stopped" then re-apply the config
        jq '.configuration.malcolmRestartPolicy = "unless-stopped"' < "${SETTINGS_FILE}" | sponge "${SETTINGS_FILE}"
        # set the run profile based on the ISO variant
        if [[ -n "$VARIANT_ID" ]]; then
          if [[ "$VARIANT_ID" == "hedgehog" ]]; then
            LOGSTASH_HOST=malcolm.home.arpa:5044
            OPENSEARCH_URL=https://malcolm.home.arpa:9200
            OPENSEARCH_PRIMARY=opensearch-remote
            ARKIME_WISE_URL=https://malcolm.home.arpa/wise/
            ARKIME_EXPOSE_WISE=false
          else
            LOGSTASH_HOST=logstash:5044
            OPENSEARCH_URL=https://opensearch:9200
            OPENSEARCH_PRIMARY=opensearch-local
            ARKIME_WISE_URL=http://arkime:8081
            ARKIME_EXPOSE_WISE=true
          fi
          JQ_SETTINGS=$(cat <<EOF
.configuration.malcolmProfile = "$VARIANT_ID" |
.configuration.opensearchPrimaryMode = "$OPENSEARCH_PRIMARY" |
.configuration.opensearchPrimaryUrl = "$OPENSEARCH_URL" |
.configuration.logstashHost = "$LOGSTASH_HOST" |
.configuration.arkimeWiseUrl = "$ARKIME_WISE_URL" |
.configuration.arkimeExposeWise = $ARKIME_EXPOSE_WISE
EOF
)
          jq "$JQ_SETTINGS" < "${SETTINGS_FILE}" | sponge "${SETTINGS_FILE}"
        fi
        /usr/bin/env python3 "$MAIN_USER_HOME"/Malcolm/scripts/install.py \
          --configure --non-interactive --import-malcolm-config-file "${SETTINGS_FILE}"
        rm -f "${SETTINGS_FILE}"
      fi
      rm -f "$MAIN_USER_HOME"/Malcolm/firstrun "$MAIN_USER_HOME"/Malcolm/.configured
      chown -R 1000:1000 "$MAIN_USER_HOME"/Malcolm
    fi

    # make sure read permission is set correctly for the nginx worker processes
    chmod 644 "$MAIN_USER_HOME"/Malcolm/nginx/htpasswd "$MAIN_USER_HOME"/Malcolm/htadmin/metadata >/dev/null 2>&1
  fi

  # set the default wallpaper based on ISO variant
  if [[ "$VARIANT_ID" == malcolm ]] && [[ -f /usr/share/images/desktop-base/Malcolm_background.png ]] ; then
    ln -s -f -r /usr/share/images/desktop-base/Malcolm_background.png /usr/share/images/desktop-base/default
  elif [[ "$VARIANT_ID" == hedgehog ]] && [[ -f /usr/share/images/desktop-base/hedgehog-wallpaper.png ]] ; then
    ln -s -f -r /usr/share/images/desktop-base/hedgehog-wallpaper.png /usr/share/images/desktop-base/default
  fi

  # we're going to let wicd manage networking on the aggregator, so remove physical interfaces from /etc/network/interfaces
  InitializeAggregatorNetworking

  # disable automatic running of some services
  [[ "$FIRST_RUN" == 1 ]] && DisableServices

  # block some call-homes
  BadTelemetry

  # if we need to import prebuilt Malcolm docker images, do so now (but not if we're in a live-usb boot)
  DOCKER_DRIVER="$(docker info -f json 2>/dev/null | jq -r '.Driver')"
  if [[ -n $DOCKER_DRIVER ]] && [[ "$DOCKER_DRIVER" != "vfs" ]] && ! grep -q boot=live /proc/cmdline; then
    docker load -q -i /malcolm_images.tar.xz && rm -f /malcolm_images.tar.xz
  fi

  exit 0
else
  exit 1
fi
