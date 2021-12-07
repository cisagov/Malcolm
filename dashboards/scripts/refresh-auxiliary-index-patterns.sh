#!/bin/bash

for IDX in auditbeat filebeat metricbeat packetbeat; do
  echo "Attempting to refresh \"${IDX}-*\"..."
  /data/index-refresh.py -i "${IDX}-*" 2>/dev/null
done
