#!/bin/bash

# Copyright (c) 2023 Battelle Energy Alliance, LLC.  All rights reserved.

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

exec "$@"
