#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.

/usr/local/bin/elastic_search_status.sh -w && /usr/local/bin/register-elasticsearch-snapshot-repo.sh

/usr/local/bin/supercronic -split-logs "${SUPERCRONIC_CRONTAB:-/etc/crontab}" >/dev/null