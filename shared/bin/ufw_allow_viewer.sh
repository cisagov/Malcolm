#!/bin/bash

# Copyright (c) 2019 Battelle Energy Alliance, LLC.  All rights reserved.

# manage a UFW rule for allowing a remote Moloch viewer instance (on the same host
# to which moloch-capture is forwarding session logs) to connect to and
# retrieve PCAP segments from the local Moloch viewer instance

# works with a comma-separated list of IP addresses in $MOLOCH_PACKET_ACL, or
# if that variable is not set, a single IP address in $ES_HOST

[[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
[[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
  echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
  exit 1
fi
export SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"

# control_vars.conf file must be specified as argument to script or be found in an expected place
# source configuration variables file if found (precedence: pwd, script directory, /opt/sensor/sensor_ctl)
if [[ -n "$1" ]]; then
  source "$1"
else
  CONTROL_VARS_FILE="control_vars.conf"
  if [[ -r ./"$CONTROL_VARS_FILE" ]]; then
    source ./"$CONTROL_VARS_FILE"
  elif [[ -r "$SCRIPT_PATH"/"$CONTROL_VARS_FILE" ]]; then
    source "$SCRIPT_PATH"/"$CONTROL_VARS_FILE"
  elif [[ -r /opt/sensor/sensor_ctl/"$CONTROL_VARS_FILE" ]]; then
    source /opt/sensor/sensor_ctl/"$CONTROL_VARS_FILE"
  fi
fi

if [[ -z $MOLOCH_VIEWER_PORT ]] || ( [[ -z $MOLOCH_PACKET_ACL ]] && [[ -z $ES_HOST ]] ); then
  echo "Either the remote Moloch viewer host (\$MOLOCH_PACKET_ACL or \$ES_HOST) or the local Moloch viewer port (\$MOLOCH_VIEWER_PORT) is undefined"
  exit 1
elif [[ ! -x /usr/sbin/ufw ]]; then
  echo "/usr/sbin/ufw does not exist or is not executable"
  exit 1
fi

# delete previous UFW rule(s)
while read LINE; do
  if [[ -n $LINE ]] && [[ "$LINE" =~ ^[0-9]+$ ]]; then
    /usr/sbin/ufw --force delete $LINE
  fi
done <<< "$(/usr/sbin/ufw status numbered | tac | grep "${MOLOCH_VIEWER_PORT}/tcp" | sed "s/].*//" | sed "s/[^0-9]*//g")"

# add new UFW rule(s)
if [[ -n $MOLOCH_PACKET_ACL ]]; then
  IFS=","
  for IP in $MOLOCH_PACKET_ACL; do
    /usr/sbin/ufw allow proto tcp from $IP/32 to any port $MOLOCH_VIEWER_PORT
  done
  unset IFS
elif [[ -n $ES_HOST ]]; then
  /usr/sbin/ufw allow proto tcp from $ES_HOST/32 to any port $MOLOCH_VIEWER_PORT
fi

# output status of rule
/usr/sbin/ufw status | grep "${MOLOCH_VIEWER_PORT}/tcp"
