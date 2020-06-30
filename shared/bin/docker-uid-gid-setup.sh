#!/bin/bash

set -e

unset ENTRYPOINT_CMD
unset ENTRYPOINT_ARGS
[ "$#" -ge 1 ] && ENTRYPOINT_CMD="$1" && [ "$#" -gt 1 ] && shift 1 && ENTRYPOINT_ARGS=( "$@" )

usermod --non-unique --uid ${PUID:-${DEFAULT_UID}} ${PUSER} 2>&1
groupmod --non-unique --gid ${PGID:-${DEFAULT_GID}} ${PGROUP} 2>&1

if [[ "$PUSER_PRIV_DROP" == "true" ]]; then
  EXEC_USER="${PUSER}"
  USER_HOME="$(getent passwd ${PUSER} | cut -d: -f6)"
else
  EXEC_USER="${USER:-root}"
  USER_HOME="${HOME:-/root}"
fi

su --shell /bin/bash --preserve-environment ${EXEC_USER} << EOF
export USER="${EXEC_USER}"
export HOME="${USER_HOME}"
whoami
id
if [ ! -z "${ENTRYPOINT_CMD}" ]; then
  if [ -z "${ENTRYPOINT_ARGS}" ]; then
    "${ENTRYPOINT_CMD}"
  else
    "${ENTRYPOINT_CMD}" $(printf "%q " "${ENTRYPOINT_ARGS[@]}")
  fi
fi
EOF
