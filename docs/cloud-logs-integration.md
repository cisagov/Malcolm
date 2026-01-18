# Cloud Infrastructure Logs Integration

Malcolm now supports ingesting and analyzing cloud infrastructure logs from AWS and Azure, enabling comprehensive monitoring of hybrid cloud + on-prem environments.

## Overview

Cloud infrastructure logs provide visibility into:
- **Network traffic** in cloud environments (VPC Flow Logs, NSG Flow Logs)
- **API activity** and access control (CloudTrail, Azure Activity Logs)
- **Application traffic** (Load balancer logs)
- **Data access** (S3/Blob storage access logs)

This integration extends Malcolm's network traffic analysis capabilities to cloud platforms, allowing security teams to correlate on-premises network activity with cloud infrastructure events in a single platform.

## Supported Log Types

### AWS

| Log Type | Description | Status |
|----------|-------------|--------|
| VPC Flow Logs | Network traffic metadata for VPCs | ✅ Implemented |
| CloudTrail | API activity and access logs | ✅ Implemented |
| ELB/ALB Logs | Load balancer access logs | 🚧 Planned |
| S3 Access Logs | S3 bucket access logs | 🚧 Planned |
| Route 53 Logs | DNS query logs | 🚧 Planned |

### Azure

| Log Type | Description | Status |
|----------|-------------|--------|
| NSG Flow Logs | Network Security Group flow logs | 🚧 Planned |
| Activity Logs | Azure resource activity logs | 🚧 Planned |
| App Gateway Logs | Application Gateway logs | 🚧 Planned |

## Architecture

```
Cloud Platform (AWS/Azure)
    ↓
S3 Bucket / Blob Storage
    ↓
aws_log_collector.py (automated collection)
    ↓
/var/log/malcolm/cloud-logs/
    ↓
Filebeat → Logstash → OpenSearch → Dashboards
```

Cloud logs are automatically enriched with:
- GeoIP location data
- ASN (Autonomous System Number) information
- Network direction classification
- NetBox asset correlation (if configured)

## Setup

### Prerequisites

- Malcolm 25.12.0 or later
- AWS account with appropriate IAM permissions (for AWS logs)
- S3 bucket configured for log export
- Python 3.8+ with boto3 library

### AWS VPC Flow Logs Setup

#### 1. Enable VPC Flow Logs

In the AWS Console:
1. Navigate to **VPC** → **Your VPCs**
2. Select your VPC
3. Click **Actions** → **Create flow log**
4. Configure:
   - **Filter**: All (or Accept/Reject as needed)
   - **Destination**: Send to an S3 bucket
   - **S3 bucket ARN**: `arn:aws:s3:::my-vpc-flow-logs`
   - **Log format**: AWS default format

#### 2. Configure IAM Permissions

Create an IAM policy for Malcolm to read logs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-vpc-flow-logs",
        "arn:aws:s3:::my-vpc-flow-logs/*"
      ]
    }
  ]
}
```

Attach this policy to an IAM user or role that Malcolm will use.

#### 3. Configure Malcolm

Create a configuration file for cloud logs:

```bash
# Create config directory
mkdir -p /opt/malcolm/config

# Create cloud logs configuration
cat > /opt/malcolm/config/cloud-logs.env << EOF
# AWS Configuration
AWS_REGION=us-east-1
AWS_VPC_FLOW_LOGS_BUCKET=my-vpc-flow-logs
AWS_VPC_FLOW_LOGS_PREFIX=AWSLogs/123456789012/vpcflowlogs/
AWS_LOG_COLLECTION_ENABLED=true
AWS_LOG_COLLECTION_INTERVAL=300

# Storage
CLOUD_LOGS_OUTPUT_DIR=/var/log/malcolm/cloud-logs
CLOUD_LOGS_RETENTION_DAYS=90
EOF
```

#### 4. Set Up AWS Credentials

```bash
# Configure AWS credentials
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
EOF
```

**Security Note**: For production, use IAM roles instead of access keys.

#### 5. Run Log Collector

```bash
# Manual collection
python3 /opt/malcolm/shared/bin/aws_log_collector.py \
  --bucket my-vpc-flow-logs \
  --log-type vpc-flow \
  --output-dir /var/log/malcolm/cloud-logs/vpc-flow \
  --region us-east-1 \
  --prefix "AWSLogs/123456789012/vpcflowlogs/" \
  --max-files 100

# Or set up as a cron job for automated collection
crontab -e
# Add: */5 * * * * /usr/bin/python3 /opt/malcolm/shared/bin/aws_log_collector.py --bucket my-vpc-flow-logs --log-type vpc-flow --output-dir /var/log/malcolm/cloud-logs/vpc-flow --region us-east-1
```

### AWS CloudTrail Setup

#### 1. Enable CloudTrail

In the AWS Console:
1. Navigate to **CloudTrail** → **Trails**
2. Click **Create trail**
3. Configure:
   - **Trail name**: malcolm-cloudtrail
   - **Storage location**: Use existing S3 bucket or create new
   - **Log file SSE-KMS encryption**: Optional
4. Enable for all regions (recommended)

#### 2. Configure Log Collection

```bash
python3 /opt/malcolm/shared/bin/aws_log_collector.py \
  --bucket my-cloudtrail-bucket \
  --log-type cloudtrail \
  --output-dir /var/log/malcolm/cloud-logs/cloudtrail \
  --region us-east-1 \
  --prefix "AWSLogs/123456789012/CloudTrail/"
```

## Viewing Cloud Logs in Malcolm

### OpenSearch Dashboards

Cloud logs are indexed with the following dataset identifiers:
- `event.dataset: aws.vpcflowlogs` - VPC Flow Logs
- `event.dataset: aws.cloudtrail` - CloudTrail logs

#### Searching VPC Flow Logs

```
event.dataset: "aws.vpcflowlogs" AND aws.vpc.action: "REJECT"
```

#### Searching CloudTrail Logs

```
event.dataset: "aws.cloudtrail" AND tags: "high_risk_action"
```

### Arkime Sessions

Cloud network flows (VPC Flow Logs) appear in Arkime's Sessions view alongside traditional PCAP sessions, allowing unified analysis of cloud and on-prem traffic.

## Security Event Detection

The cloud logs parsers automatically tag security-relevant events:

### VPC Flow Logs

| Tag | Description |
|-----|-------------|
| `rejected_traffic` | Connections blocked by security groups |
| `high_volume_transfer` | Data transfers exceeding 10MB |
| `potential_port_scan` | Multiple rejected connections |

### CloudTrail

| Tag | Description |
|-----|-------------|
| `unauthorized_access_attempt` | AccessDenied or UnauthorizedOperation errors |
| `high_risk_action` | Destructive operations (DeleteBucket, TerminateInstances, etc.) |
| `root_account_usage` | Root user activity (security best practice violation) |
| `failed_authentication` | Failed console login attempts |

## Dashboards

### VPC Flow Overview Dashboard

Visualizations include:
- Traffic volume over time
- Top source/destination IPs
- Accepted vs. rejected traffic ratio
- Geographic distribution of traffic
- Protocol breakdown
- High-volume transfers

### CloudTrail Activity Dashboard

Visualizations include:
- API call timeline
- Top users and services
- Failed authentication attempts
- High-risk actions
- Error rate trends
- Geographic source of API calls

## Troubleshooting

### Logs Not Appearing in Malcolm

1. **Check log collector output**:
   ```bash
   python3 /opt/malcolm/shared/bin/aws_log_collector.py --debug ...
   ```

2. **Verify files in output directory**:
   ```bash
   ls -lh /var/log/malcolm/cloud-logs/vpc-flow/
   ```

3. **Check Filebeat is monitoring the directory**:
   ```bash
   docker logs malcolm-filebeat-1 | grep cloud-logs
   ```

4. **Check Logstash parsing**:
   ```bash
   docker logs malcolm-logstash-1 | grep vpc_flow
   ```

5. **Query OpenSearch directly**:
   ```bash
   curl -X GET "localhost:9200/malcolm-*/_search?pretty" \
     -H 'Content-Type: application/json' \
     -d '{"query": {"match": {"event.dataset": "aws.vpcflowlogs"}}}'
   ```

### AWS Permissions Issues

If you see `AccessDenied` errors:
1. Verify IAM policy allows `s3:GetObject` and `s3:ListBucket`
2. Check bucket policy doesn't deny access
3. Ensure AWS credentials are correctly configured

### High Memory Usage

For high-volume VPC Flow Logs:
1. Increase Logstash heap size in `docker-compose.yml`:
   ```yaml
   environment:
     - LS_JAVA_OPTS=-Xms4g -Xmx4g
   ```
2. Reduce collection frequency
3. Implement log filtering at the source

## Performance Considerations

- **VPC Flow Logs** can generate significant volume in busy environments
- Consider filtering at the VPC level (e.g., only rejected traffic)
- Use separate OpenSearch indices for cloud logs with different retention policies
- Monitor Logstash throughput and adjust resources as needed

## Best Practices

1. **Use IAM roles** instead of access keys when running on EC2
2. **Enable CloudTrail** for all regions to capture all API activity
3. **Filter VPC Flow Logs** to reduce volume (e.g., only log rejected traffic)
4. **Set up alerts** for high-risk CloudTrail events
5. **Correlate** cloud logs with on-prem network traffic for comprehensive analysis
6. **Regular cleanup** of old log files to manage disk usage

## Future Enhancements

- Azure NSG Flow Logs support
- Azure Activity Logs support
- ELB/ALB access logs parser
- S3 access logs parser
- Route 53 query logs parser
- Automated dashboard provisioning
- Real-time log streaming (vs. S3 polling)
- CloudWatch Logs integration

## Related Documentation

- [Malcolm Documentation](https://idaholab.github.io/Malcolm/)
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [ECS Field Reference](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html)

## Support

For issues or questions:
- [GitHub Issues](https://github.com/cisagov/Malcolm/issues)
- [Community Discussions](https://github.com/cisagov/Malcolm/discussions)
