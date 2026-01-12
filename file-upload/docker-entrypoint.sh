#!/bin/bash

# Copyright (c) 2026 Battelle Energy Alliance, LLC.  All rights reserved.

if [[ -z $MALCOLM_USERNAME || -z $MALCOLM_PASSWORD ]]; then
  echo "Please set the SSH username and (openssl-encrypted then base64-encoded) password by adding the following arguments to docker run/create:"
  echo "  -e MALCOLM_USERNAME='...'"
  echo "  -e MALCOLM_PASSWORD='...'"
  exit 1
fi

if ! getent passwd "$MALCOLM_USERNAME" >/dev/null; then
  # Make sure every container gets its own SSH host keys the first time around
  rm -f /etc/ssh/ssh_host_*
  dpkg-reconfigure openssh-server

  useradd -g $PGROUP -d /var/www/upload/server/php/chroot -s /sbin/nologin "$MALCOLM_USERNAME"
  usermod --password "$(echo -n "$MALCOLM_PASSWORD" | base64 -d)" "$MALCOLM_USERNAME"
  chown :$PGROUP /var/www/upload/server/php/chroot/files
  chown :$PGROUP /var/www/upload/server/php/chroot/files/{tmp,variants} 2>/dev/null || true
  chown :$PGROUP /var/www/upload/server/php/chroot/files/tmp/spool 2>/dev/null || true
  chmod 775 /var/www/upload/server/php/chroot/files
  chmod 775 /var/www/upload/server/php/chroot/files/{tmp,variants} 2>/dev/null || true
  chmod 775 /var/www/upload/server/php/chroot/files/tmp/spool 2>/dev/null || true

else
  echo "skipping one-time setup tasks" 1>&2
fi

if [[ -n "${PCAP_UPLOAD_MAX_FILE_GB:-}" && "$PCAP_UPLOAD_MAX_FILE_GB" =~ ^[0-9]+$ ]]; then
  [[ -f /etc/nginx/sites-available/default ]] && sed -i -E "s/^(\s*client_max_body_size)\s+.*;/\1 ${PCAP_UPLOAD_MAX_FILE_GB}G;/" /etc/nginx/sites-available/default
  find /etc/php -type f -wholename "*/fpm/php.ini" -print0 | xargs -0 -r -l sed -i -E "s/^(\s*upload_max_filesize)\s*=.*/\1 = ${PCAP_UPLOAD_MAX_FILE_GB}G/"
  if [[ -f /var/www/upload/index.html ]]; then
    PCAP_UPLOAD_MAX_FILE_MB=$((PCAP_UPLOAD_MAX_FILE_GB * 1000))
    sed -i -E "s/^(\s*maxFileSize)\s*:.*,\s*$/\1: '${PCAP_UPLOAD_MAX_FILE_MB}MB',/" /var/www/upload/index.html
    sed -i -E "s/(Ready for file uploads)/\1 (up to ${PCAP_UPLOAD_MAX_FILE_GB}GB each)/" /var/www/upload/index.html
  fi
fi

exec "$@"
