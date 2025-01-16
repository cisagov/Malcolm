#!/bin/bash

# Copyright (c) 2025 Battelle Energy Alliance, LLC.  All rights reserved.

# manage a UFW rule for allowing a remote Malcolm instance to connect to
# services hosted on the sensor

# works with a comma-separated list of IP addresses in $MALCOLM_REQUEST_ACL, or
# if that variable is not set, a single IP address in $OS_HOST

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

if [[ -z $MALCOLM_REQUEST_PORTS ]] || ( [[ -z $MALCOLM_REQUEST_ACL ]] && [[ -z $OS_HOST ]] ); then
  echo "Either the remote host (\$MALCOLM_REQUEST_ACL or \$OS_HOST) or the request ports (\$MALCOLM_REQUEST_PORTS) is undefined"
  exit 1
elif [[ ! -x /usr/sbin/ufw ]]; then
  echo "/usr/sbin/ufw does not exist or is not executable"
  exit 1
fi

while read SERVICE_PORT; do

  # delete previous UFW rule(s)
  while read LINE; do
    if [[ -n $LINE ]] && [[ "$LINE" =~ ^[0-9]+$ ]]; then
      /usr/sbin/ufw --force delete $LINE
    fi
  done <<< "$(/usr/sbin/ufw status numbered | tac | grep "${SERVICE_PORT}/tcp" | sed "s/].*//" | sed "s/[^0-9]*//g")"

  # add new UFW rule(s)
  if [[ -n $MALCOLM_REQUEST_ACL ]]; then
    # loop over ACL IP addresses
    IFS=","
    for IP in $MALCOLM_REQUEST_ACL; do
      /usr/sbin/ufw allow proto tcp from $IP to any port $SERVICE_PORT
    done
    unset IFS
  elif [[ -n $OS_HOST ]]; then
    # ACL not defined, create a rule for $OS_HOST
    /usr/sbin/ufw allow proto tcp from $OS_HOST to any port $SERVICE_PORT
  fi

  # output status of rule
  /usr/sbin/ufw status | grep "${SERVICE_PORT}/tcp"

done < <(echo "${MALCOLM_REQUEST_PORTS}" | tr ',' '\n') # loop over ',' separated MALCOLM_REQUEST_PORTS values