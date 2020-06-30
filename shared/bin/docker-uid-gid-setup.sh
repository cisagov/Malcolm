#!/bin/bash

set -e

unset ENTRYPOINT_CMD
unset ENTRYPOINT_ARGS
[ "$#" -ge 1 ] && ENTRYPOINT_CMD="$1" && [ "$#" -gt 1 ] && shift 1 && ENTRYPOINT_ARGS=( "$@" )
USER_HOME="$(getent passwd ${PUSER} | cut -d: -f6)"

usermod --non-unique --uid ${PUID:-${DEFAULT_UID}} ${PUSER} 2>&1
groupmod --non-unique --gid ${PGID:-${DEFAULT_GID}} ${PGROUP} 2>&1

su --shell /bin/bash --preserve-environment ${PUSER} << EOF
export USER="${PUSER}"
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
