#!/bin/sh

# todo: in case I need to add distro detection
#
# detect_linux_distro() {
#   if [ $(command -v lsb_release) ]; then
#     DISTRO=$(lsb_release -is)
#   elif [ -f /etc/os-release ]; then
#     DISTRO=$(sed -n -e 's/^NAME="\(.*\)\"/\1/p' /etc/os-release)
#   else
#     DISTRO=''
#   fi
#   echo $DISTRO
# }

set -e

usermod --non-unique --uid ${PUID:-${DEFAULT_UID}} ${PUSER}
groupmod --non-unique --gid ${PGID:-${DEFAULT_GID}} ${PGROUP}

su - ${PUSER}

exec "$@"
