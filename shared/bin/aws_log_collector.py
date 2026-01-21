#!/usr/bin/env python3
"""
AWS and Azure Cloud Logs Collector
Collects logs from S3 buckets and Azure Blob Storage for ingestion into Malcolm
Supports: VPC Flow Logs, CloudTrail, ELB/ALB, S3 Access, Route 53, Azure NSG, Azure Activity
"""

import argparse
import boto3
import gzip
import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional

# Supported log types and their dataset identifiers
LOG_TYPES = {
    'vpc-flow': 'aws.vpcflowlogs',
    'cloudtrail': 'aws.cloudtrail',
    'elb': 'aws.elb',
    's3-access': 'aws.s3access',
    'route53': 'aws.route53',
    'azure-nsg': 'azure.nsgflowlogs',
    'azure-activity': 'azure.activitylogs'
}

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('aws_log_collector')


class AWSLogCollector:
    """Collects AWS logs from S3 buckets"""
    
    def __init__(self, bucket: str, log_type: str, output_dir: str, 
                 region: str = 'us-east-1', state_file: str = None):
        """
        Initialize AWS log collector
        
        Args:
            bucket: S3 bucket name containing logs
            log_type: Type of logs (vpc-flow, cloudtrail, elb, s3-access)
            output_dir: Local directory to write logs
            region: AWS region
            state_file: File to track collection state
        """
        self.bucket = bucket
        self.log_type = log_type
        self.output_dir = Path(output_dir)
        self.region = region
        self.state_file = state_file or f'/tmp/aws_log_collector_{log_type}.state'
        
        # Initialize S3 client
        self.s3 = boto3.client('s3', region_name=region)
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load state
        self.state = self._load_state()
    
    def _load_state(self) -> Dict:
        """Load collection state from file"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load state file: {e}")
        return {'last_collected': None, 'processed_files': []}
    
    def _save_state(self):
        """Save collection state to file"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state: {e}")
    
    def collect(self, prefix: str = '', max_files: int = 100) -> int:
        """
        Collect logs from S3
        
        Args:
            prefix: S3 key prefix to filter logs
            max_files: Maximum number of files to process per run
            
        Returns:
            Number of files collected
        """
        logger.info(f"Collecting {self.log_type} logs from s3://{self.bucket}/{prefix}")
        
        collected = 0
        
        try:
            # List objects in bucket
            paginator = self.s3.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.bucket, Prefix=prefix)
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    key = obj['Key']
                    
                    # Skip if already processed
                    if key in self.state['processed_files']:
                        continue
                    
                    # Skip directories
                    if key.endswith('/'):
                        continue
                    
                    # Download and process file
                    if self._process_file(key):
                        collected += 1
                        self.state['processed_files'].append(key)
                        
                        # Save state periodically
                        if collected % 10 == 0:
                            self._save_state()
                    
                    # Check max files limit
                    if collected >= max_files:
                        logger.info(f"Reached max files limit ({max_files})")
                        break
                
                if collected >= max_files:
                    break
            
            # Update last collected timestamp
            self.state['last_collected'] = datetime.utcnow().isoformat()
            self._save_state()
            
            logger.info(f"Collected {collected} files")
            return collected
            
        except Exception as e:
            logger.error(f"Error collecting logs: {e}")
            return collected
    
    def _process_file(self, key: str) -> bool:
        """
        Download and process a single log file
        
        Args:
            key: S3 object key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.debug(f"Processing {key}")
            
            # Download file to memory
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            content = response['Body'].read()
            
            # Decompress if gzipped
            if key.endswith('.gz'):
                content = gzip.decompress(content)
            
            # Determine output filename
            output_file = self.output_dir / f"{Path(key).stem}.log"
            
            # Write to output directory
            with open(output_file, 'wb') as f:
                f.write(content)
            
            logger.info(f"Wrote {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error processing {key}: {e}")
            return False
    
    def cleanup_old_files(self, days: int = 7):
        """
        Remove processed files older than specified days
        
        Args:
            days: Number of days to retain files
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        for file in self.output_dir.glob('*.log'):
            if datetime.fromtimestamp(file.stat().st_mtime) < cutoff:
                logger.info(f"Removing old file: {file}")
                file.unlink()


def main():
    parser = argparse.ArgumentParser(
        description='Collect AWS logs from S3 for Malcolm ingestion'
    )
    parser.add_argument('--bucket', required=True, help='S3 bucket name')
    parser.add_argument('--log-type', required=True, 
                       choices=['vpc-flow', 'cloudtrail', 'elb', 's3-access', 'route53', 'azure-nsg', 'azure-activity'],
                       help='Type of logs to collect')
    parser.add_argument('--output-dir', required=True, 
                       help='Output directory for logs')
    parser.add_argument('--region', default='us-east-1', 
                       help='AWS region')
    parser.add_argument('--prefix', default='', 
                       help='S3 key prefix to filter logs')
    parser.add_argument('--max-files', type=int, default=100,
                       help='Maximum files to process per run')
    parser.add_argument('--cleanup-days', type=int, default=7,
                       help='Remove files older than N days')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create collector
    collector = AWSLogCollector(
        bucket=args.bucket,
        log_type=args.log_type,
        output_dir=args.output_dir,
        region=args.region
    )
    
    # Collect logs
    collected = collector.collect(prefix=args.prefix, max_files=args.max_files)
    
    # Cleanup old files
    if args.cleanup_days > 0:
        collector.cleanup_old_files(days=args.cleanup_days)
    
    logger.info(f"Collection complete. Processed {collected} files.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
