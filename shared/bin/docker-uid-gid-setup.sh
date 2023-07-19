#!/bin/bash

# attempt to set ulimits (as root)
if [[ "${PUSER_RLIMIT_UNLOCK:-false}" == "true" ]] && command -v ulimit >/dev/null 2>&1; then
  ulimit -c 0 >/dev/null 2>&1
  ulimit -l unlimited >/dev/null 2>&1
  ulimit -m unlimited >/dev/null 2>&1
  ulimit -v unlimited >/dev/null 2>&1
  ulimit -x unlimited >/dev/null 2>&1
  ulimit -n 65535 >/dev/null 2>&1
  ulimit -u 262144 >/dev/null 2>&1
fi

set -e

unset ENTRYPOINT_CMD
unset ENTRYPOINT_ARGS
[ "$#" -ge 1 ] && ENTRYPOINT_CMD="$1" && [ "$#" -gt 1 ] && shift 1 && ENTRYPOINT_ARGS=( "$@" )

# modify the UID/GID for the default user/group (for example, 1000 -> 1001)
usermod --non-unique --uid ${PUID:-${DEFAULT_UID}} ${PUSER}
groupmod --non-unique --gid ${PGID:-${DEFAULT_GID}} ${PGROUP}

# Any directory named with the value of CONFIG_MAP_DIR will have its contents rsync'ed into
#   the parent directory as the container starts up. This is mostly for convenience for
#   Kubernetes configmap objects, which, because the directory into which they are
#   copied is made read-only, doesn't play nicely if you're using it for configuration
#   files which exist in a directory which may need to do read-write operations on other files.
#   This works for nested subdirectories, but don't nest CONFIG_MAP_DIR directories
#   inside of other CONFIG_MAP_DIR directories. More than one CONFIG_MAP_DIR can be specified
#   in this variable, separated by ';' (for example, "CONFIG_MAP_DIR=configmap;secretmap").
#
# TODO: else with cpio, tar, cp?

CONFIG_MAP_FIND_PRUNE_ARGS=()
if [[ -n ${CONFIG_MAP_DIR} ]] && command -v rsync >/dev/null 2>&1; then
  while read MAP_DIR; do

    find / -type d -name "${MAP_DIR}" -print -o -path /sys -prune -o -path /proc -prune 2>/dev/null | \
    awk '{print gsub("/","/"), $0}' | sort -n | cut -d' ' -f2- | \
    while read CMDIR; do

      rsync --recursive --copy-links \
            "--usermap=*:${PUID:-${DEFAULT_UID}}" \
            "--groupmap=*:${PGID:-${DEFAULT_GID}}" \
            --exclude='..*' --exclude="${MAP_DIR}"/ --exclude=.dockerignore --exclude=.gitignore \
            "${CMDIR}"/ "${CMDIR}"/../

        # TODO - regarding ownership and permissions:
        #
        # I *think* what we want to do here is change the ownership of
        #   these configmap-copied files to be owned by the user specified by PUID
        #   (falling back to DEFAULT_UID) and PGID (falling back to DEFAULT_GID).
        #   The other option would be to preserve the ownership of the source
        #   fine with --owner --group, but I don't think that's what we want, as
        #   if we were doing this with a docker bind mount they'd likely have the
        #   permissions of the original user on the host, anyway, which is
        #   supposed to match up to PUID/PGID.
        #
        # For permissions, rsync says that "existing files retain their existing permissions"
        #   and "new files get their normal permission bits set to the source file's
        #   permissions masked with the receiving directory's default permissions"
        #   (either via umask or ACL) which I think is what we want. The other alternative
        #   would be to do something like --chmod=D2755,F644

    done # loop over found MAP_DIR directories
    CONFIG_MAP_FIND_PRUNE_ARGS+=(-o -name "${MAP_DIR}" -prune)

  done < <(echo "${CONFIG_MAP_DIR}" | tr ';' '\n') # loop over ';' separated CONFIG_MAP_DIR values
fi # check for CONFIG_MAP_DIR and rsync

set +e

# if there are semicolon-separated PUSER_CHOWN entries explicitly specified, chown them first
if [[ -n ${PUSER_CHOWN} ]]; then
  IFS=';' read -ra ENTITIES <<< "${PUSER_CHOWN}"
  for ENTITY in "${ENTITIES[@]}"; do
    chown -R ${PUSER}:${PGROUP} "${ENTITY}" 2>/dev/null
  done
fi

# change user/group ownership of any other files/directories belonging to the original IDs
if [[ -n ${PUID} ]] && [[ "${PUID}" != "${DEFAULT_UID}" ]]; then
  find / -path /sys -prune -o -path /proc -prune -o -user ${DEFAULT_UID} -exec chown -f ${PUID} "{}" \; 2>/dev/null
fi
if [[ -n ${PGID} ]] && [[ "${PGID}" != "${DEFAULT_GID}" ]]; then
  find / -path /sys -prune -o -path /proc -prune -o -group ${DEFAULT_GID} -exec chown -f :${PGID} "{}" \; 2>/dev/null
fi

# If there are subdirectories that need to be created that are explicitly specified, make them here. format of $PUSER_MKDIR is:
#   required_path:subdirectory_to_mkdir,subdirectory_to_mkdir,subdirectory_to_mkdir
# Multiple entries can be separated by semicolon
# Ownership of these directories will be set to PUID/PGID
#
# e.g.,
#   For the entry: /data/zeek-logs:current,upload,extract_files/quarantined,extract_files/preserved
#   If /data/zeek-logs exists, will mkdir -p /data/zeek-logs /data/zeek-logs/upload /data/zeek-logs/extract_files/quarantined /data/zeek-logs/extract_files/preserved
if [[ -n ${PUSER_MKDIR} ]]; then
  IFS=';' read -ra ENTITIES <<< "${PUSER_MKDIR}"
  for ENTITY in "${ENTITIES[@]}"; do
    REQ_DIR="$(echo "${ENTITY}" | cut -d: -f1)"
    if [[ -n ${REQ_DIR} ]] && [[ -d "${REQ_DIR}" ]]; then
      IFS=',' read -ra MKDIR_DIRS <<< "$(echo "${ENTITY}" | cut -d: -f2-)"
      for NEW_DIR in "${MKDIR_DIRS[@]}"; do
        [[ ! -d "${REQ_DIR}"/"${NEW_DIR}" ]] && \
          mkdir -p "${REQ_DIR}"/"${NEW_DIR}" 2>/dev/null && \
          ( ( [[ -n ${PUID} ]] && chown -R -f ${PUID} "${REQ_DIR}$(echo /"${NEW_DIR}" | awk -F/ '{print FS $2}')" 2>/dev/null ) ; ( [[ -n ${PGID} ]] && chown -R -f :${PGID} "${REQ_DIR}$(echo /"${NEW_DIR}" | awk -F/ '{print FS $2}')" 2>/dev/null ) )
      done
    fi
  done
fi

# if there is a trusted CA file or directory specified and openssl is available, handle it
if [[ -n ${PUSER_CA_TRUST} ]] && command -v openssl >/dev/null 2>&1; then
  declare -a CA_FILES
  if [[ -d "${PUSER_CA_TRUST}" ]]; then
    while read -r -d ''; do
      CA_FILES+=("$REPLY")
    done < <(find "${PUSER_CA_TRUST}" -type f -size +31c -print0 "${CONFIG_MAP_FIND_PRUNE_ARGS[@]}" 2>/dev/null)
  elif [[ -f "${PUSER_CA_TRUST}" ]]; then
    CA_FILES+=("${PUSER_CA_TRUST}")
  fi
  for CA_FILE in "${CA_FILES[@]}"; do
    CA_NAME_ORIG="$(basename "$CA_FILE")"
    CA_NAME_CRT="${CA_NAME_ORIG%.*}.crt"
    DEST_FILE=
    CONCAT_FILE=
    HASH_FILE="$(openssl x509 -hash -noout -in "$CA_FILE")".0
    if command -v update-ca-certificates >/dev/null 2>&1; then
      if [[ -d /usr/local/share/ca-certificates ]]; then
        DEST_FILE=/usr/local/share/ca-certificates/"$CA_NAME_CRT"
      elif [[ -d /usr/share/ca-certificates ]]; then
        DEST_FILE=/usr/share/ca-certificates/"$CA_NAME_CRT"
      elif [[ -d /etc/ssl/certs ]]; then
        DEST_FILE==/etc/ssl/certs/"$HASH_FILE"
      fi
    elif command -v update-ca-trust >/dev/null 2>&1; then
      if [[ -d /usr/share/pki/ca-trust-source/anchors ]]; then
        DEST_FILE=/usr/share/pki/ca-trust-source/anchors/"$CA_NAME_CRT"
      elif [[ -d /etc/pki/ca-trust/source/anchors ]]; then
        DEST_FILE=/etc/pki/ca-trust/source/anchors/"$CA_NAME_CRT"
      fi
    else
      if [[ -d /etc/ssl/certs ]]; then
        DEST_FILE=/etc/ssl/certs/"$HASH_FILE"
        CONCAT_FILE=/etc/ssl/certs/ca-certificates.crt
      fi
      if [[ -f /etc/ssl/certs/ca-certificates.crt ]]; then
        CONCAT_FILE=/etc/ssl/certs/ca-certificates.crt
      elif [[ -f /etc/pki/tls/certs/ca-bundle.crt ]]; then
        CONCAT_FILE=/etc/pki/tls/certs/ca-bundle.crt
      elif [[ -f /usr/share/ssl/certs/ca-bundle.crt ]]; then
        CONCAT_FILE=/usr/share/ssl/certs/ca-bundle.crt
      elif [[ -f /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem ]]; then
        CONCAT_FILE=/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
      fi
    fi
    [[ -n "$DEST_FILE" ]] && ( cp "$CA_FILE" "$DEST_FILE" && chmod 644 "$DEST_FILE" )
    [[ -n "$CONCAT_FILE" ]] && \
      ( echo "" >> "$CONCAT_FILE" && \
        echo "# $CA_NAME_ORIG" >> "$CONCAT_FILE" \
        && cat "$CA_FILE" >> "$CONCAT_FILE" )
  done
  command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1
  command -v update-ca-trust >/dev/null 2>&1 && update-ca-trust extract >/dev/null 2>&1
fi

# determine if we are now dropping privileges to exec ENTRYPOINT_CMD
if [[ "$PUSER_PRIV_DROP" == "true" ]]; then
  EXEC_USER="${PUSER}"
  USER_HOME="$(getent passwd ${PUSER} | cut -d: -f6)"
else
  EXEC_USER="${USER:-root}"
  USER_HOME="${HOME:-/root}"
fi

# attempt to set ulimits (as user) and execute the entrypoint command specified
su -s /bin/bash -p ${EXEC_USER} << EOF
export USER="${EXEC_USER}"
export HOME="${USER_HOME}"
whoami
id
if [[ "${PUSER_RLIMIT_UNLOCK:-false}" == "true" ]] && command -v ulimit >/dev/null 2>&1; then
  ulimit -c 0 >/dev/null 2>&1
  ulimit -l unlimited >/dev/null 2>&1
  ulimit -m unlimited >/dev/null 2>&1
  ulimit -v unlimited >/dev/null 2>&1
  ulimit -x unlimited >/dev/null 2>&1
  ulimit -n 65535 >/dev/null 2>&1
  ulimit -u 262144 >/dev/null 2>&1
fi
if [[ ! -z "${ENTRYPOINT_CMD}" ]]; then
  if [[ -z "${ENTRYPOINT_ARGS}" ]]; then
    "${ENTRYPOINT_CMD}"
  else
    "${ENTRYPOINT_CMD}" $(printf "%q " "${ENTRYPOINT_ARGS[@]}")
  fi
fi
EOF
