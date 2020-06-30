#!/bin/sh

set -e

ENTRYPOINT_ARGS=("$@")
USER_HOME="$(getent passwd ${PUSER} | cut -d: -f6)"

usermod --non-unique --uid ${PUID:-${DEFAULT_UID}} ${PUSER} 2>&1
groupmod --non-unique --gid ${PGID:-${DEFAULT_GID}} ${PGROUP} 2>&1

su --shell $(readlink /proc/$$/exe) --preserve-environment ${PUSER} << EOF
export USER="${PUSER}"
export HOME="${USER_HOME}"
whoami
id
"${ENTRYPOINT_ARGS[@]}"
EOF
