#!/bin/bash

SCRIPT_PATH="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd "$SCRIPT_PATH" >/dev/null 2>&1

[[ -e ./pyenv/bin/activate ]] && source ./pyenv/bin/activate

gunicorn --bind=127.0.0.1:5000 sensor_interface.routes:app

popd >/dev/null 2>&1
