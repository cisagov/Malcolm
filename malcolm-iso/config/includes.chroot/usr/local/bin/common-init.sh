#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

declare -A IFACES

# read all non-virtual interfaces and their speeds into an associative array
function PopulateInterfaces()
{
  IFACE_RESULT=""
  SPEED_MAX=0
  while IFS='' read -r -d ' ' IFACE_NAME && IFS='' read -r -d '' IFACE_LINK; do
    if [[ "${IFACE_LINK}" != *"virtual"* ]]; then
      IFACE_SPEED="$(cat /sys/class/net/$IFACE_NAME/speed 2>/dev/null)"
      if [[ -n $IFACE_SPEED ]]; then
        IFACES[$IFACE_NAME]+=$IFACE_SPEED
      else
        IFACES[$IFACE_NAME]+=0
      fi
    fi
  done < <(find /sys/class/net/ -mindepth 1 -maxdepth 1 -type l -printf '%P %l\0' 2>/dev/null)
}

# the capture interface is the one with the highest "speed"
function DetermineCaptureInterface()
{
  for IFACE_NAME in "${!IFACES[@]}"; do
    echo "$IFACE_NAME" "${IFACES["$IFACE_NAME"]}"
  done | sort -rn -k2 | head -n 1 | cut -d' ' -f1
}

# remove default accounts/groups we don't want, create/set directories for non-user users for stig to not complain
function CleanDefaultAccounts() {
  for systemuser in games gnats irc list lp news www-data
  do
    deluser $systemuser 2>/dev/null || true
  done
  [ ! -d /var/lib/nobody ] && ((mkdir -p /var/lib/nobody && chown nobody:nogroup /var/lib/nobody && chmod 700 /var/lib/nobody && usermod -m -d /var/lib/nobody nobody) || true)
  [ ! -d /var/lib/_apt ] && ((mkdir -p /var/lib/_apt && chown _apt:nogroup /var/lib/_apt && chmod 700 /var/lib/_apt && usermod -m -d /var/lib/_apt _apt) || true)
  [ ! -d /run/systemd/resolve ] && ((mkdir -p /run/systemd/resolve && chown systemd-resolve:systemd-resolve /run/systemd/resolve && chmod 700 /run/systemd/resolve) || true)
  [ ! -d /var/lib/usbmux ] && ((mkdir -p /var/lib/usbmux && chown usbmux:plugdev /var/lib/usbmux && chmod 700 /var/lib/usbmux) || true)
  [ ! -d /var/lib/ntp ] && ((mkdir -p /var/lib/ntp && chown ntp:ntp /var/lib/ntp && chmod 700 /var/lib/ntp) || true)
  chmod 600 "/etc/crontab" >/dev/null 2>&1 || true
  chmod 644 "/etc/passwd-" "/etc/group-" >/dev/null 2>&1 || true
  chmod 640 "/etc/shadow-" "/etc/gshadow-" >/dev/null 2>&1 || true
  chmod 700 "/etc/cron.hourly" "/etc/cron.daily" "/etc/cron.weekly" "/etc/cron.monthly" "/etc/cron.d" >/dev/null 2>&1 || true
}

# disable automatic running of some services
# disable automatic running of some services
function DisableServices() {
  local service
  local -a services=(
    apt-daily-upgrade.service
    apt-daily-upgrade.timer
    apt-daily.service
    apt-daily.timer
    clamav-clamonacc.service
    clamav-daemon.socket
    clamav-daemon.service
    clamav-freshclam-once.service
    clamav-freshclam-once.timer
    clamav-freshclam.service
    ctrl-alt-del.target
    fluent-bit.service
    htpdate.service
    ModemManager.service
    ntpsec.service
    sendmail.service
  )

  local -a networkd_units=(
    systemd-networkd.service
    systemd-networkd-wait-online.service
    systemd-networkd.socket
    systemd-networkd-varlink.socket
    systemd-networkd-varlink-metrics.socket
    systemd-networkd-resolve-hook.socket
  )

  for service in "${services[@]}"; do
    systemctl stop "$service" >/dev/null 2>&1 || true
    systemctl disable "$service" >/dev/null 2>&1 || true
    systemctl reset-failed "$service" >/dev/null 2>&1 || true
  done

  for service in clamav-daemon clamav-freshclam; do
    update-rc.d -f "$service" remove >/dev/null 2>&1 || true
  done

  for service in "${networkd_units[@]}"; do
    systemctl disable --now "$service" >/dev/null 2>&1 || true
    systemctl mask "$service" >/dev/null 2>&1 || true
    systemctl reset-failed "$service" >/dev/null 2>&1 || true
  done
}

# setup initially-created user's directory based on /etc/skel
function InjectSkeleton() {
  if [ -n "$1" ]; then
    USER_TO_FIX="$1"
    USER_HOME="$(getent passwd "$USER_TO_FIX" | cut -d: -f6)"
    if [ -d "$USER_HOME" ] && [ -d /etc/skel ] && [ ! -f "$USER_HOME"/.config/skel.synced ]; then
      rsync -a --ignore-existing --chown="$(id -u "$USER_TO_FIX"):$(id -g "$USER_TO_FIX")" /etc/skel/ "$USER_HOME"/
      date -Iseconds > "$USER_HOME"/.config/skel.synced
      chown $(id -u "$USER_TO_FIX"):$(id -g "$USER_TO_FIX") "$USER_HOME"/.config/skel.synced
    fi
  fi
}

function SetNetworkingServiceTimeout() {
  local wants_path='/etc/systemd/system/network-online.target.wants/networking.service'
  local dropin_dir='/etc/systemd/system/networking.service.d'
  local dropin_file="${dropin_dir}/timeout.conf"
  local changed=false

  # Remove an incorrectly created regular file. A .wants entry must be a symlink.
  if [[ -e "$wants_path" ]] && [[ ! -L "$wants_path" ]]; then
    rm -f "$wants_path"
    changed=true
  fi

  mkdir -p "$dropin_dir"

  if [[ ! -f "$dropin_file" ]] ||
     ! grep --quiet '^TimeoutStartSec=1min$' "$dropin_file"; then
    cat >"$dropin_file" <<'EOF'
[Service]
TimeoutStartSec=1min
EOF
    changed=true
  fi

  if "$changed"; then
    systemctl daemon-reload
  fi

  return 0
}

function InitializeAggregatorNetworking() {
  unset NEED_NETWORKING_RESTART

  # we're going to let Network Manager manage networking on the aggregator, so remove physical interfaces from /etc/network/interfaces
  NET_IFACES_LINES=$(wc -l /etc/network/interfaces | awk '{print $1}')
  if [ $NET_IFACES_LINES -gt 4 ] ; then
    echo -e "source /etc/network/interfaces.d/*\n\nauto lo\niface lo inet loopback" > /etc/network/interfaces
    NEED_NETWORKING_RESTART=0
  fi

  SetNetworkingServiceTimeout

  [[ -n $NEED_NETWORKING_RESTART ]] && systemctl restart networking
}

# fix some permissions to make sure things belong to the right person
function FixPermissions() {
  if [ -n "$1" ]; then
    USER_TO_FIX="$1"
    USER_HOME="$(getent passwd "$USER_TO_FIX" | cut -d: -f6)"
    [ -d "$USER_HOME" ] && find "$USER_HOME" \( -type d -o -type f \) -exec chmod o-rwx "{}" \;
    [ -d "$USER_HOME" ] && find "$USER_HOME" -type f -name ".*" -exec chmod g-wx "{}" \;
    if [ ! -f /etc/cron.allow ] || ! grep -q "$USER_TO_FIX" /etc/cron.allow; then
      echo "$USER_TO_FIX" >> /etc/cron.allow
    fi
    if [ ! -f /etc/at.allow ] || ! grep -q "$USER_TO_FIX" /etc/at.allow; then
      echo "$USER_TO_FIX" >> /etc/at.allow
    fi
    chmod 644 /etc/cron.allow /etc/at.allow
    if [[ -d /etc/NetworkManager/system-connections ]]; then
      chmod 755 /etc/NetworkManager/system-connections 2>/dev/null || true
      find /etc/NetworkManager/system-connections -type f -name "*.nmconnection" -exec chmod 600 "{}" \;
    fi
    loginctl enable-linger "$USER_TO_FIX" 2>/dev/null || true
  fi
}

# block some call-homes
function BadTelemetry() {
  if ! grep -q google /etc/hosts; then
    echo >> /etc/hosts
    echo '127.0.0.1 _googlecast._tcp.local' >> /etc/hosts
    echo '127.0.0.1 accounts.google.com' >> /etc/hosts
    echo '127.0.0.1 census.netbox.dev' >> /etc/hosts
    echo '127.0.0.1 clients.l.google.com' >> /etc/hosts
    echo '127.0.0.1 connectivitycheck.gstatic.com' >> /etc/hosts
    echo '127.0.0.1 detectportal.firefox.com' >> /etc/hosts
    echo '127.0.0.1 detectportal.prod.mozaws.net' >> /etc/hosts
    echo '127.0.0.1 fonts.googleapis.com' >> /etc/hosts
    echo '127.0.0.1 incoming.telemetry.mozilla.org' >> /etc/hosts
    echo '127.0.0.1 prod.detectportal.prod.cloudops.mozgcp.net' >> /etc/hosts
    echo '127.0.0.1 safebrowsing-cache.google.com' >> /etc/hosts
    echo '127.0.0.1 safebrowsing.clients.google.com' >> /etc/hosts
    echo '127.0.0.1 update.googleapis.com' >> /etc/hosts
    echo '127.0.0.1 www.google-analytics.com' >> /etc/hosts
    echo '127.0.0.1 www.gstatic.com' >> /etc/hosts
  fi
}
