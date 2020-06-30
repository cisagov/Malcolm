#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

chown -R ${PUSER}:${PGROUP} /var/www/html

exec "$@"
