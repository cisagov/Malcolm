#!/bin/bash
find /var/log/suricata/ -type f -name "*.json" -mmin +30 -delete