#!/bin/bash

# Copyright (c) 2022 Battelle Energy Alliance, LLC.  All rights reserved.

AVG_TEMP="$(sensors 2>/dev/null | grep '^Core\s[[:digit:]]\+:' | sed -e 's/[[:space:]]\+/,/g' | cut -d',' -f3 | sed "s/^\+//" | sed "s/°.*//" | awk '{ total += $1; count++ } END { if (count > 0) { print total/count } }')"
HDD_TEMP="$(hddtemp /dev/sd? 2>/dev/null | grep -v "S\.M\.A\.R\.T\. not available" | sed 's/^/\[/' | sed 's/$/\]/' | tr '\n' ',' | sed 's/,$//')"
if [ -n "$AVG_TEMP" ] || [ -n "$HDD_TEMP" ] ; then
  logger "CPUs: ${AVG_TEMP}°C, HDDs: ${HDD_TEMP}"
fi
