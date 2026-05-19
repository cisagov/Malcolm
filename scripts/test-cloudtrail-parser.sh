#!/bin/bash
# Unit tests for AWS CloudTrail parser
# Tests the Logstash parser with various CloudTrail event types

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER_PATH="${SCRIPT_DIR}/../logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf"
TEST_RESULTS=0

echo "========================================="
echo "CloudTrail Parser Unit Tests"
echo "========================================="

# Test 1: Successful API call
echo ""
echo "Test 1: Successful API call"
TEST_INPUT='{"eventVersion":"1.08","eventTime":"2026-01-21T00:00:00Z","eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","sourceIPAddress":"203.0.113.42","userIdentity":{"type":"IAMUser","userName":"test-user","accountId":"123456789012"},"awsRegion":"us-east-1"}'
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf \
  -e 'input { stdin { codec => json } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "event.outcome.*success" && echo "✓ PASS: Successful event parsed" || { echo "✗ FAIL: Success not detected"; TEST_RESULTS=1; }

# Test 2: Failed API call (AccessDenied)
echo ""
echo "Test 2: Failed API call (AccessDenied)"
TEST_INPUT='{"eventVersion":"1.08","eventTime":"2026-01-21T00:00:00Z","eventName":"TerminateInstances","eventSource":"ec2.amazonaws.com","sourceIPAddress":"203.0.113.42","userIdentity":{"type":"IAMUser","userName":"test-user","accountId":"123456789012"},"awsRegion":"us-east-1","errorCode":"AccessDenied","errorMessage":"User is not authorized"}'
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf \
  -e 'input { stdin { codec => json } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "unauthorized_access_attempt" && echo "✓ PASS: Unauthorized access detected" || { echo "✗ FAIL: Unauthorized not tagged"; TEST_RESULTS=1; }

# Test 3: High-risk action
echo ""
echo "Test 3: High-risk action (DeleteBucket)"
TEST_INPUT='{"eventVersion":"1.08","eventTime":"2026-01-21T00:00:00Z","eventName":"DeleteBucket","eventSource":"s3.amazonaws.com","sourceIPAddress":"203.0.113.42","userIdentity":{"type":"IAMUser","userName":"admin-user","accountId":"123456789012"},"awsRegion":"us-east-1"}'
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf \
  -e 'input { stdin { codec => json } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "high_risk_action" && echo "✓ PASS: High-risk action detected" || { echo "✗ FAIL: High-risk not tagged"; TEST_RESULTS=1; }

# Test 4: Root account usage
echo ""
echo "Test 4: Root account usage"
TEST_INPUT='{"eventVersion":"1.08","eventTime":"2026-01-21T00:00:00Z","eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","sourceIPAddress":"203.0.113.42","userIdentity":{"type":"Root","accountId":"123456789012"},"awsRegion":"us-east-1"}'
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf \
  -e 'input { stdin { codec => json } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "root_account_usage" && echo "✓ PASS: Root usage detected" || { echo "✗ FAIL: Root usage not tagged"; TEST_RESULTS=1; }

# Test 5: Failed console login
echo ""
echo "Test 5: Failed console login"
TEST_INPUT='{"eventVersion":"1.08","eventTime":"2026-01-21T00:00:00Z","eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","sourceIPAddress":"203.0.113.42","userIdentity":{"type":"IAMUser","userName":"test-user","accountId":"123456789012"},"awsRegion":"us-east-1","responseElements":{"ConsoleLogin":"Failure"}}'
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf \
  -e 'input { stdin { codec => json } } output { stdout { codec => rubydebug } }' 2>&1 | \
  grep -q "failed_authentication" && echo "✓ PASS: Failed login detected" || { echo "✗ FAIL: Failed login not tagged"; TEST_RESULTS=1; }

# Test 6: Cloud metadata fields
echo ""
echo "Test 6: Cloud provider metadata"
TEST_INPUT='{"eventVersion":"1.08","eventTime":"2026-01-21T00:00:00Z","eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","sourceIPAddress":"203.0.113.42","userIdentity":{"type":"IAMUser","userName":"test-user","accountId":"123456789012"},"awsRegion":"us-east-1"}'
echo "$TEST_INPUT" | docker exec -i malcolm-logstash-1 \
  /usr/share/logstash/bin/logstash \
  -f /usr/share/logstash/pipelines/enrichment/16_cloud_logs_cloudtrail.conf \
  -e 'input { stdin { codec => json } } output { stdout { codec => rubydebug } }' 2>&1 | \
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
