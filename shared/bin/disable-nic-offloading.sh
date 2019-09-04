#!/bin/bash

[[ -n "$1" ]] && /sbin/ethtool -K "$1" rx off tx off sg off tso off ufo off gso off gro off lro off
