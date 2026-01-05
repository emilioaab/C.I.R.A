"""
C.I.R.A Log Collection
Collects logs from CloudTrail, CloudWatch, VPC Flow Logs
Normalizes them to LogRecord format
"""

import boto3
import json
from datetime import datetime
from typing import List, Dict, Optional
import logging

from backend.connectors.aws.log_schema import LogRecord, LogSource, LogAction, LogStatus, LogSeverity, LogBatch
from backend.connectors.aws.log_config import LogConfig

# ============================================================================
# CUSTOM JSON ENCODER - Handle datetime objects
# ============================================================================

class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles datetime objects"""
    
    def default(self, obj):
        """Convert datetime objects to ISO format"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        
        try:
            return super().default(obj)
        except TypeError:
            # For other non-serializable objects, convert to string
            return str(obj)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# CLOUDTRAIL COLLECTOR
# ============================================================================

class CloudTrailCollector:
    """Collect events from AWS CloudTrail"""
    
    def __init__(self, region: str = None):
        self.region = region or LogConfig.get_primary_region()
        self.client = boto3.client('cloudtrail', region_name=self.region)
        self.account = self._get_account_id()
    
    def _get_account_id(self) -> str:
        """Get AWS Account ID"""
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            return "unknown"
    
    def collect_events(self) -> List[LogRecord]:
        """Collect CloudTrail events and convert to LogRecord"""
        logger.info("🔵 Collecting CloudTrail events...")
        
        records = []
        start_time = LogConfig.get_start_time()
        end_time = LogConfig.get_end_time()
        page_size = LogConfig.get_page_size()
        max_pages = LogConfig.get_max_pages()
        
        try:
            # Use paginator for CloudTrail
            paginator = self.client.get_paginator('lookup_events')
            
            pages = 0
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=page_size,
                PaginationConfig={'PageSize': page_size}
            ):
                pages += 1
                if pages > max_pages:
                    logger.warning(f"Reached max pages ({max_pages}), stopping")
                    break
                
                for event in page.get('Events', []):
                    log_record = self._normalize_event(event)
                    if log_record and LogConfig.should_include_event(log_record.service, log_record.principal):
                        records.append(log_record)
            
            logger.info(f"Collected {len(records)} CloudTrail events")
            return records
        
        except Exception as e:
            logger.error(f"Error collecting CloudTrail events: {e}")
            return records
    
    def _normalize_event(self, event: Dict) -> Optional[LogRecord]:
        """
        Convert CloudTrail event to LogRecord
        
        CloudTrail event structure:
        {
            'EventId': 'xxx',
            'EventTime': datetime,
            'EventSource': 'iam.amazonaws.com',
            'EventName': 'CreateUser',
            'Username': 'arn:aws:iam::...',
            'Resources': [{'ARN': '...', 'ResourceType': '...', 'ResourceName': '...'}],
            'CloudTrailEvent': '{...json...}'
        }
        """
        try:
            event_time = event.get('EventTime', datetime.utcnow()).isoformat()
            event_name = event.get('EventName', 'Unknown')
            event_source = event.get('EventSource', 'unknown')
            username = event.get('Username', 'unknown')
            
            # Parse raw event
            try:
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
            except:
                cloud_trail_event = {}
            
            # Extract resource info
            resources = event.get('Resources', [])
            resource = resources[0] if resources else {}
            resource_id = resource.get('ResourceName', resource.get('ARN', 'unknown'))
            resource_type = resource.get('ResourceType', 'unknown')
            
            # Get request parameters for additional context
            request_parameters = cloud_trail_event.get('requestParameters', {})
            response_elements = cloud_trail_event.get('responseElements', {})
            error_code = cloud_trail_event.get('errorCode')
            error_message = cloud_trail_event.get('errorMessage')
            
            # Determine status
            status = LogStatus.FAILURE if error_code else LogStatus.SUCCESS
            
            # Get source IP
            source_ip = cloud_trail_event.get('sourceIPAddress', '')
            
            # Normalize service name
            service = LogConfig.get_service_name(event_source)
            
            # Normalize action
            action_str = LogConfig.get_action(event_name)
            try:
                action = LogAction[action_str.upper()]
            except KeyError:
                action = LogAction.OTHER
            
            # Determine severity
            if error_code:
                severity_str = LogConfig.get_severity_for_action(error_code)
            else:
                severity_str = LogConfig.get_severity_for_action(event_name)
            
            try:
                severity = LogSeverity[severity_str.upper()]
            except KeyError:
                severity = LogSeverity.INFO
            
            # Build message
            message = f"{event_name}"
            if error_code:
                message += f" (Error: {error_code})"
            
            # Create LogRecord
            return LogRecord(
                timestamp=event_time,
                source=LogSource.CLOUDTRAIL,
                account=self.account,
                region=self.region,
                service=service,
                action=action,
                status=status,
                severity=severity,
                resource_id=resource_id,
                resource_type=resource_type,
                principal=username,
                principal_type='iam-user',
                src_ip=source_ip,
                message=message,
                error_code=error_code,
                raw=event
            )
        
        except Exception as e:
            logger.error(f"Error normalizing CloudTrail event: {e}")
            return None

# ============================================================================
# VPCFLOW COLLECTOR (Placeholder for MVP)
# ============================================================================

class VPCFlowCollector:
    """Collect VPC Flow Logs (placeholder for MVP)"""
    
    def __init__(self, region: str = None):
        self.region = region or LogConfig.get_primary_region()
        self.account = self._get_account_id()
    
    def _get_account_id(self) -> str:
        """Get AWS Account ID"""
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            return "unknown"
    
    def collect_logs(self) -> List[LogRecord]:
        """
        Collect VPC Flow Logs from CloudWatch Logs
        
        MVP: Read from CloudWatch Logs group
        Future: Read from S3 bucket where Flow Logs are stored
        """
        logger.info("Collecting VPC Flow Logs (MVP - CloudWatch)...")
        
        records = []
        
        try:
            logs_client = boto3.client('logs', region_name=self.region)
            
            # Default VPC Flow Logs group name
            log_group = '/aws/vpc/flowlogs'
            
            try:
                # Get recent log streams
                streams = logs_client.describe_log_streams(
                    logGroupName=log_group,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=10
                )
                
                start_time = int(LogConfig.get_start_time().timestamp() * 1000)
                end_time = int(LogConfig.get_end_time().timestamp() * 1000)
                
                for stream in streams.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    
                    try:
                        # Get events from stream
                        events = logs_client.filter_log_events(
                            logGroupName=log_group,
                            logStreamNamePrefix=stream_name,
                            startTime=start_time,
                            endTime=end_time,
                            limit=LogConfig.get_page_size()
                        )
                        
                        for event in events.get('events', []):
                            log_record = self._normalize_flow_log(event)
                            if log_record:
                                records.append(log_record)
                    
                    except Exception as e:
                        logger.debug(f"Error reading stream {stream_name}: {e}")
                        continue
            
            except Exception as e:
                logger.warning(f"VPC Flow Logs group not found ({log_group}): {e}")
            
            logger.info(f"Collected {len(records)} VPC Flow Log events")
            return records
        
        except Exception as e:
            logger.error(f"Error collecting VPC Flow Logs: {e}")
            return records
    
    def _normalize_flow_log(self, event: Dict) -> Optional[LogRecord]:
        """
        Convert VPC Flow Log to LogRecord
        
        VPC Flow Log format (space-delimited):
        version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes 
        windowstart windowend action tcpflags log-status
        
        Example:
        2 828414850095 eni-1234567 10.0.1.100 10.0.2.50 443 12345 6 100 50000 1234567890 1234567900 ACCEPT OK
        """
        try:
            timestamp = datetime.fromtimestamp(event['timestamp'] / 1000).isoformat()
            message = event.get('message', '')
            
            # Parse VPC Flow Logs format
            parts = message.split()
            
            if len(parts) < 14:
                return None
            
            # Extract fields
            account = parts[1]
            interface_id = parts[2]
            src_ip = parts[3]
            dst_ip = parts[4]
            src_port = parts[5]
            dst_port = parts[6]
            protocol = parts[7]
            action = parts[12]  # ACCEPT or REJECT
            
            # Determine status
            status = LogStatus.SUCCESS if action == 'ACCEPT' else LogStatus.FAILURE
            
            # Determine severity
            severity = LogSeverity.LOW
            
            # Normalize action
            try:
                action_enum = LogAction[action.upper()]
            except KeyError:
                action_enum = LogAction.NETWORK_FLOW
            
            return LogRecord(
                timestamp=timestamp,
                source=LogSource.VPC_FLOW,
                account=account,
                region=self.region,
                service='vpc',
                action=action_enum,
                status=status,
                severity=severity,
                resource_id=interface_id,
                resource_type='network-interface',
                principal=interface_id,
                principal_type='eni',
                src_ip=src_ip,
                dst_ip=dst_ip,
                message=f"VPC Flow: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({action})",
                raw={'flow_log': message}
            )
        
        except Exception as e:
            logger.debug(f"Error normalizing VPC Flow Log: {e}")
            return None

# ============================================================================
# MAIN LOG COLLECTOR ORCHESTRATOR
# ============================================================================

class LogCollector:
    """Main orchestrator for collecting logs from all sources"""
    
    def __init__(self):
        self.config = LogConfig()
        self.all_records = []
    
    def collect_all(self) -> List[LogRecord]:
        """
        Collect logs from all enabled sources
        Returns list of normalized LogRecord objects
        """
        logger.info("\n" + "="*80)
        logger.info("🔷 STARTING LOG COLLECTION")
        logger.info("="*80)
        
        self.all_records = []
        enabled_sources = LogConfig.get_enabled_sources()
        
        # Collect from CloudTrail
        if 'cloudtrail' in enabled_sources:
            try:
                collector = CloudTrailCollector()
                records = collector.collect_events()
                self.all_records.extend(records)
            except Exception as e:
                logger.error(f"CloudTrail collection failed: {e}")
        
        # Collect from VPC Flow Logs
        if 'vpc_flow' in enabled_sources:
            try:
                collector = VPCFlowCollector()
                records = collector.collect_logs()
                self.all_records.extend(records)
            except Exception as e:
                logger.error(f"VPC Flow Logs collection failed: {e}")
        
        # CloudWatch (placeholder)
        if 'cloudwatch' in enabled_sources:
            logger.info("CloudWatch collection (not implemented in MVP)")
        
        logger.info(f"\nTOTAL LOGS COLLECTED: {len(self.all_records)}")
        logger.info("="*80 + "\n")
        
        return self.all_records
    
    def save_to_file(self, records: List[LogRecord] = None) -> str:
        """
        Save collected logs to JSON file
        Returns filename
        """
        if records is None:
            records = self.all_records
        
        if not records:
            logger.warning("No records to save")
            return None
        
        # Create batch
        batch = LogBatch(
            source=LogSource.CLOUDTRAIL,  # Mixed, but we'll use this
            records=records
        )
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"logs_{timestamp}.json"
        
        # Save to file with DateTimeEncoder
        try:
            with open(filename, 'w') as f:
                json.dump(batch.to_dict(), f, indent=2, cls=DateTimeEncoder)
            
            logger.info(f"💾 Logs saved to: {filename}")
            return filename
        
        except Exception as e:
            logger.error(f"Error saving logs: {e}")
            return None
    
    def get_summary(self) -> Dict:
        """Get summary statistics of collected logs"""
        if not self.all_records:
            return {
                'total': 0,
                'by_source': {},
                'by_service': {},
                'by_severity': {}
            }
        
        summary = {
            'total': len(self.all_records),
            'by_source': {},
            'by_service': {},
            'by_severity': {},
            'by_status': {}
        }
        
        # Count by source
        for record in self.all_records:
            source = record.source.value
            summary['by_source'][source] = summary['by_source'].get(source, 0) + 1
            
            service = record.service
            summary['by_service'][service] = summary['by_service'].get(service, 0) + 1
            
            severity = record.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            status = record.status.value
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
        
        return summary

# ============================================================================
# TESTING
# ============================================================================

if __name__ == '__main__':
    logger.info("Testing LogCollector...")
    
    collector = LogCollector()
    records = collector.collect_all()
    
    # Save to file
    filename = collector.save_to_file()
    
    # Print summary
    summary = collector.get_summary()
    print("\nSummary:")
    print(f"  Total: {summary['total']}")
    print(f"  By source: {summary['by_source']}")
    print(f"  By service: {summary['by_service']}")
    print(f"  By severity: {summary['by_severity']}")