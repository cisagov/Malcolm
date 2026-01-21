# Cloud Logs Integration - Dashboard Import Guide

## Overview

This guide explains how to import the AWS cloud logs dashboards into Malcolm's OpenSearch Dashboards.

## Dashboards Included

1. **AWS VPC Flow Logs Overview** (`aws-vpc-flow-overview.ndjson`)
   - Traffic volume over time
   - Accept vs Reject ratio
   - Top source/destination IPs
   - Protocol breakdown
   - Geographic distribution

2. **AWS CloudTrail Activity** (`aws-cloudtrail-activity.ndjson`)
   - API calls timeline
   - Success vs Failure ratio
   - Top users and actions
   - Security events breakdown
   - Geographic source of API calls

## Import Instructions

### Method 1: Via OpenSearch Dashboards UI

1. Access Malcolm's OpenSearch Dashboards:
   ```
   https://your-malcolm-instance/dashboards
   ```

2. Navigate to **Management** → **Stack Management** → **Saved Objects**

3. Click **Import**

4. Select the dashboard file:
   - `dashboards/dashboards/aws-vpc-flow-overview.ndjson` OR
   - `dashboards/dashboards/aws-cloudtrail-activity.ndjson`

5. Click **Import**

6. If prompted about conflicts, choose **Overwrite** or **Skip**

7. Navigate to **Dashboards** to view the imported dashboard

### Method 2: Via API

```bash
# Import VPC Flow dashboard
curl -X POST "https://localhost/dashboards/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  --form file=@dashboards/dashboards/aws-vpc-flow-overview.ndjson \
  -u admin:admin

# Import CloudTrail dashboard
curl -X POST "https://localhost/dashboards/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: multipart/form-data" \
  --form file=@dashboards/dashboards/aws-cloudtrail-activity.ndjson \
  -u admin:admin
```

## Prerequisites

- Malcolm must be running
- Cloud logs must be ingested (VPC Flow Logs and/or CloudTrail)
- Malcolm index pattern must exist (`malcolm-*`)

## Viewing Dashboards

After import:

1. Go to **Dashboards** in OpenSearch Dashboards
2. Search for:
   - "AWS VPC Flow Logs Overview"
   - "AWS CloudTrail Activity Dashboard"
3. Click to open and view

## Customization

You can customize these dashboards:

1. Click **Edit** in the dashboard
2. Modify visualizations:
   - Change time ranges
   - Adjust aggregations
   - Add/remove panels
3. Click **Save** to keep changes

## Troubleshooting

### Dashboard shows "No results found"

- Verify cloud logs are being ingested:
  ```
  curl -X GET "localhost:9200/malcolm-*/_search?q=event.dataset:aws.vpcflowlogs"
  ```
- Check time range (top right corner)
- Ensure index pattern includes cloud logs

### Visualizations don't load

- Refresh the index pattern:
  **Management** → **Index Patterns** → **malcolm-*** → **Refresh field list**
- Verify field mappings exist for cloud.* and aws.* fields

### Import fails

- Check OpenSearch Dashboards version compatibility
- Ensure you have admin permissions
- Try importing individual visualizations first

## Dashboard Features

### VPC Flow Dashboard

- **Traffic Volume**: Line chart showing bytes transferred over time
- **Accept/Reject**: Pie chart of connection outcomes
- **Top Talkers**: Tables of most active source/destination IPs
- **Protocols**: Bar chart of network protocols used
- **Geo Map**: World map showing traffic destinations

### CloudTrail Dashboard

- **API Timeline**: Line chart of API calls over time
- **Success/Failure**: Pie chart of API call outcomes
- **Top Users**: Table of most active IAM users
- **Top Actions**: Table of most common API actions
- **Security Events**: Breakdown of security-tagged events
- **Geo Map**: World map showing API call sources

## Next Steps

- Create custom visualizations for specific use cases
- Set up alerts based on security events
- Export dashboards for sharing with team
- Schedule reports for regular review

## Support

For issues with dashboards:
- Check Malcolm documentation
- Review OpenSearch Dashboards logs
- Ask in Malcolm community discussions
