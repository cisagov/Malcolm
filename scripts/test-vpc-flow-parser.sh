#!/bin/bash
# Unit tests for AWS VPC Flow Logs parser
# Tests the Logstash parser with various VPC Flow Log formats

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER_PATH="${SCRIPT_DIR}/../logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf"
TEST_RESULTS=0

echo "========================================="
echo "VPC Flow Logs Parser Unit Tests"
echo "========================================="

# Test 1: Valid ACCEPT log
echo ""
echo "Test 1: Valid ACCEPT log"
TEST_INPUT="2 123456789012 eni-1a2b3c4d 10.0.1.5 172.31.16.21 49153 443 6 25 20000 1418530010 1418530070 ACCEPT OK"
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf \
  -e 'input { stdin { } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "event.outcome.*success" && echo "✓ PASS: ACCEPT parsed correctly" || { echo "✗ FAIL: ACCEPT not parsed"; TEST_RESULTS=1; }

# Test 2: Valid REJECT log
echo ""
echo "Test 2: Valid REJECT log"
TEST_INPUT="2 123456789012 eni-5e6f7g8h 192.168.1.100 203.0.113.42 54321 22 6 10 5000 1418530080 1418530090 REJECT OK"
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf \
  -e 'input { stdin { } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "event.outcome.*failure" && echo "✓ PASS: REJECT parsed correctly" || { echo "✗ FAIL: REJECT not parsed"; TEST_RESULTS=1; }

# Test 3: High volume transfer detection
echo ""
echo "Test 3: High volume transfer (>10MB)"
TEST_INPUT="2 123456789012 eni-9a8b7c6d 10.0.2.10 52.94.76.1 33445 80 6 150 50000000 1418530100 1418530160 ACCEPT OK"
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf \
  -e 'input { stdin { } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "high_volume_transfer" && echo "✓ PASS: High volume detected" || { echo "✗ FAIL: High volume not detected"; TEST_RESULTS=1; }

# Test 4: TCP protocol mapping
echo ""
echo "Test 4: TCP protocol mapping"
TEST_INPUT="2 123456789012 eni-1a2b3c4d 10.0.1.5 172.31.16.21 49153 443 6 25 20000 1418530010 1418530070 ACCEPT OK"
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf \
  -e 'input { stdin { } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "network.transport.*tcp" && echo "✓ PASS: TCP protocol mapped" || { echo "✗ FAIL: TCP not mapped"; TEST_RESULTS=1; }

# Test 5: UDP protocol mapping
echo ""
echo "Test 5: UDP protocol mapping"
TEST_INPUT="2 123456789012 eni-1a2b3c4d 10.0.1.5 8.8.8.8 54321 53 17 5 500 1418530010 1418530015 ACCEPT OK"
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf \
  -e 'input { stdin { } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "network.transport.*udp" && echo "✓ PASS: UDP protocol mapped" || { echo "✗ FAIL: UDP not mapped"; TEST_RESULTS=1; }

# Test 6: Cloud metadata fields
echo ""
echo "Test 6: Cloud provider metadata"
TEST_INPUT="2 123456789012 eni-1a2b3c4d 10.0.1.5 172.31.16.21 49153 443 6 25 20000 1418530010 1418530070 ACCEPT OK"
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/15_cloud_logs_vpc_flow.conf \
  -e 'input { stdin { } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "cloud.provider.*aws" && echo "✓ PASS: Cloud metadata set" || { echo "✗ FAIL: Cloud metadata missing"; TEST_RESULTS=1; }

echo ""
echo "========================================="
if [ $TEST_RESULTS -eq 0 ]; then
  echo "All tests PASSED ✓"
  echo "========================================="
  exit 0
else
  echo "Some tests FAILED ✗"
  echo "========================================="
  exit 1
fi
