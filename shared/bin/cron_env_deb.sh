#!/bin/bash

# Copyright (c) 2020 Battelle Energy Alliance, LLC.  All rights reserved.


printenv | sed -r "s/'/\\\'/gm" | sed -r "s/^([^=]+=)(.*)\$/\1'\2'/gm" > /etc/environment
cron -f -L 0
