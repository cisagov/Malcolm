#!/bin/bash

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

CONTROL_VARS_FILE=${CONTROL_VARS_FILE:-/opt/sensor/sensor_ctl/control_vars.conf}

if [ -e ./pyenv/bin/activate ]; then
  source ./pyenv/bin/activate
fi
if [ -e "${CONTROL_VARS_FILE}" ]; then
  source "${CONTROL_VARS_FILE}"
fi

gunicorn --bind=127.0.0.1:5000 sensor_interface.routes:app

popd >/dev/null 2>&1
