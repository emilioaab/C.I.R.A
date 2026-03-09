"""
C.I.R.A Log Collection
Collects logs from CloudTrail, CloudWatch, VPC Flow Logs, GuardDuty
Normalizes them to LogRecord format
Supports multi-environment (prod/test) within a single AWS account
"""

import boto3
import json
import time
from datetime import datetime
from typing import List, Dict, Optional
import logging

from backend.connectors.aws.log_schema import LogRecord, LogSource, LogAction, LogStatus, LogSeverity, LogBatch
from backend.connectors.aws.log_config import LogConfig, load_environment

# ============================================================================
# CUSTOM JSON ENCODER - Handle datetime objects
# ============================================================================

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# RETRY HELPER
# ============================================================================

def _with_retry(fn, retries: int = 3, delay: float = 1.0):
    """Call fn with simple retry on exception (exponential backoff)"""
    for attempt in range(retries):
        try:
            return fn()
        except Exception as e:
            if attempt == retries - 1:
                raise
            wait = delay * (2 ** attempt)
            logger.warning(f"Retry {attempt + 1}/{retries} after error: {e} (waiting {wait:.1f}s)")
            time.sleep(wait)


# ============================================================================
# CLOUDTRAIL COLLECTOR
# ============================================================================

class CloudTrailCollector:
    """Collect events from AWS CloudTrail"""

    def __init__(self, region: str = None):
        self.region = region or LogConfig.get_primary_region()
        self.environment = LogConfig.get_environment()
        self.client = boto3.client('cloudtrail', region_name=self.region)
        self.account = self._get_account_id()

    def _get_account_id(self) -> str:
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            return "unknown"

    def collect_events(self) -> List[LogRecord]:
        """Collect CloudTrail events and convert to LogRecord"""
        logger.info(f"[{self.environment.upper()}] Collecting CloudTrail events...")

        records = []
        start_time = LogConfig.get_start_time()
        end_time = LogConfig.get_end_time()
        page_size = LogConfig.get_page_size()
        max_pages = LogConfig.get_max_pages()

        try:
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

            logger.info(f"[{self.environment.upper()}] CloudTrail: {len(records)} events collected")
            return records

        except Exception as e:
            logger.error(f"Error collecting CloudTrail events: {e}")
            return records

    def _normalize_event(self, event: Dict) -> Optional[LogRecord]:
        try:
            event_time = event.get('EventTime', datetime.utcnow())
            if isinstance(event_time, datetime):
                event_time = event_time.isoformat()

            event_name = event.get('EventName', 'Unknown')
            event_source = event.get('EventSource', 'unknown')
            username = event.get('Username', 'unknown')

            try:
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
            except Exception:
                cloud_trail_event = {}

            resources = event.get('Resources', [])
            resource = resources[0] if resources else {}
            resource_id = resource.get('ResourceName', resource.get('ARN', 'unknown'))
            resource_type = resource.get('ResourceType', 'unknown')

            error_code = cloud_trail_event.get('errorCode')
            source_ip = cloud_trail_event.get('sourceIPAddress', '')

            status = LogStatus.FAILURE if error_code else LogStatus.SUCCESS
            service = LogConfig.get_service_name(event_source)

            action_str = LogConfig.get_action(event_name)
            try:
                action = LogAction[action_str.upper()]
            except KeyError:
                action = LogAction.OTHER

            severity_str = LogConfig.get_severity_for_action(error_code if error_code else event_name)
            try:
                severity = LogSeverity[severity_str.upper()]
            except KeyError:
                severity = LogSeverity.INFO

            message = event_name
            if error_code:
                message += f" (Error: {error_code})"

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
# VPC FLOW LOGS COLLECTOR
# ============================================================================

class VPCFlowCollector:
    """Collect VPC Flow Logs from CloudWatch Logs"""

    def __init__(self, region: str = None):
        self.region = region or LogConfig.get_primary_region()
        self.environment = LogConfig.get_environment()
        self.account = self._get_account_id()
        self.logs_client = boto3.client('logs', region_name=self.region)

    def _get_account_id(self) -> str:
        try:
            sts = boto3.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            logger.error(f"Error getting account ID: {e}")
            return "unknown"

    def _discover_flow_log_groups(self) -> List[str]:
        """
        Discover VPC Flow Log CloudWatch groups dynamically.
        1. Tries the configured group name first (from env file).
        2. Falls back to scanning all log groups that look like flow logs.
        """
        configured = LogConfig.get_vpc_flow_log_group()

        try:
            response = self.logs_client.describe_log_groups(
                logGroupNamePrefix=configured, limit=1
            )
            groups = response.get('logGroups', [])
            if groups and groups[0]['logGroupName'] == configured:
                logger.info(f"VPC Flow Log group found: {configured}")
                return [configured]
        except Exception:
            pass

        # Fallback: scan all log groups for flow log patterns
        logger.info("Configured VPC Flow Log group not found, scanning all log groups...")
        found = []
        try:
            paginator = self.logs_client.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for group in page.get('logGroups', []):
                    name = group['logGroupName']
                    if any(kw in name.lower() for kw in ['flowlog', 'flow-log', 'vpcflow', 'vpc/flow']):
                        found.append(name)
        except Exception as e:
            logger.warning(f"Could not scan log groups: {e}")

        if found:
            logger.info(f"Found {len(found)} VPC Flow Log group(s): {found}")
        else:
            logger.warning(
                "No VPC Flow Log groups found. "
                "Enable VPC Flow Logs → CloudWatch to collect network traffic data."
            )

        return found

    def collect_logs(self) -> List[LogRecord]:
        """Collect VPC Flow Logs from discovered CloudWatch Log Groups"""
        logger.info(f"[{self.environment.upper()}] Collecting VPC Flow Logs...")

        records = []
        log_groups = _with_retry(self._discover_flow_log_groups)

        if not log_groups:
            return records

        start_time = int(LogConfig.get_start_time().timestamp() * 1000)
        end_time = int(LogConfig.get_end_time().timestamp() * 1000)
        page_size = LogConfig.get_page_size()

        for log_group in log_groups:
            try:
                streams = _with_retry(lambda: self.logs_client.describe_log_streams(
                    logGroupName=log_group,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=10
                ))

                for stream in streams.get('logStreams', []):
                    stream_name = stream['logStreamName']
                    try:
                        events = _with_retry(lambda: self.logs_client.filter_log_events(
                            logGroupName=log_group,
                            logStreamNamePrefix=stream_name,
                            startTime=start_time,
                            endTime=end_time,
                            limit=page_size
                        ))

                        for event in events.get('events', []):
                            record = self._normalize_flow_log(event)
                            if record:
                                records.append(record)

                    except Exception as e:
                        logger.debug(f"Error reading stream {stream_name}: {e}")

            except Exception as e:
                logger.warning(f"Error reading log group {log_group}: {e}")

        logger.info(f"[{self.environment.upper()}] VPC Flow Logs: {len(records)} events collected")
        return records

    def _normalize_flow_log(self, event: Dict) -> Optional[LogRecord]:
        """
        Convert VPC Flow Log line to LogRecord.
        Format: version account-id interface-id srcaddr dstaddr srcport dstport
                protocol packets bytes windowstart windowend action tcpflags log-status
        """
        try:
            timestamp = datetime.fromtimestamp(event['timestamp'] / 1000).isoformat()
            message = event.get('message', '').strip()

            parts = message.split()
            if len(parts) < 14:
                return None

            account = parts[1]
            interface_id = parts[2]
            src_ip = parts[3]
            dst_ip = parts[4]
            src_port = parts[5]
            dst_port = parts[6]
            action_str = parts[12]   # ACCEPT or REJECT
            log_status = parts[13]   # OK, NODATA, SKIPDATA

            if log_status in ('SKIPDATA', 'NODATA'):
                return None

            status = LogStatus.SUCCESS if action_str == 'ACCEPT' else LogStatus.FAILURE
            action_enum = LogAction.ACCEPTED if action_str == 'ACCEPT' else LogAction.REJECTED
            severity = LogSeverity.INFO if action_str == 'ACCEPT' else LogSeverity.MEDIUM

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
                message=f"VPC Flow: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({action_str})",
                raw={'flow_log': message}
            )

        except Exception as e:
            logger.debug(f"Error normalizing VPC Flow Log: {e}")
            return None


# ============================================================================
# GUARDDUTY COLLECTOR
# ============================================================================

class GuardDutyCollector:
    """Collect GuardDuty findings as high-severity log events"""

    def __init__(self, region: str = None):
        self.region = region or LogConfig.get_primary_region()
        self.environment = LogConfig.get_environment()
        self.client = boto3.client('guardduty', region_name=self.region)
        self.account = self._get_account_id()

    def _get_account_id(self) -> str:
        try:
            return boto3.client('sts').get_caller_identity()['Account']
        except Exception:
            return "unknown"

    def _get_detector_id(self) -> Optional[str]:
        try:
            detectors = _with_retry(lambda: self.client.list_detectors())
            ids = detectors.get('DetectorIds', [])
            return ids[0] if ids else None
        except Exception as e:
            logger.warning(f"GuardDuty not available: {e}")
            return None

    def collect_findings(self) -> List[LogRecord]:
        """Collect GuardDuty findings updated in the lookback window"""
        logger.info(f"[{self.environment.upper()}] Collecting GuardDuty findings...")

        records = []
        detector_id = self._get_detector_id()

        if not detector_id:
            logger.warning("GuardDuty detector not found. Enable GuardDuty in your AWS account.")
            return records

        try:
            start_ms = int(LogConfig.get_start_time().timestamp() * 1000)
            finding_ids = []

            paginator = self.client.get_paginator('list_findings')
            for page in paginator.paginate(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'updatedAt': {'GreaterThanOrEqual': start_ms}
                    }
                }
            ):
                finding_ids.extend(page.get('FindingIds', []))

            if not finding_ids:
                logger.info("No new GuardDuty findings in time window")
                return records

            # Fetch in batches of 50 (API limit)
            for i in range(0, len(finding_ids), 50):
                batch_ids = finding_ids[i:i + 50]
                response = _with_retry(lambda: self.client.get_findings(
                    DetectorId=detector_id,
                    FindingIds=batch_ids
                ))
                for finding in response.get('Findings', []):
                    record = self._normalize_finding(finding)
                    if record:
                        records.append(record)

        except Exception as e:
            logger.error(f"Error collecting GuardDuty findings: {e}")

        logger.info(f"[{self.environment.upper()}] GuardDuty: {len(records)} findings collected")
        return records

    def _normalize_finding(self, finding: Dict) -> Optional[LogRecord]:
        try:
            gd_severity = finding.get('Severity', 0)
            if gd_severity >= 7:
                severity = LogSeverity.CRITICAL
            elif gd_severity >= 4:
                severity = LogSeverity.HIGH
            elif gd_severity >= 2:
                severity = LogSeverity.MEDIUM
            else:
                severity = LogSeverity.LOW

            service_info = finding.get('Service', {})
            action_info = service_info.get('Action', {})
            action_type = action_info.get('ActionType', 'other').lower()

            action_map = {
                'aws_api_call': LogAction.OTHER,
                'dns_request': LogAction.NETWORK_FLOW,
                'network_connection': LogAction.NETWORK_FLOW,
                'port_probe': LogAction.NETWORK_FLOW,
            }
            action = action_map.get(action_type, LogAction.OTHER)

            resource = finding.get('Resource', {})
            resource_type = resource.get('ResourceType', 'unknown').lower()

            instance_id = resource.get('InstanceDetails', {}).get('InstanceId')
            s3_details = resource.get('S3BucketDetails', [])
            resource_id = instance_id or (s3_details[0].get('Name') if s3_details else 'unknown')

            src_ip = (
                action_info.get('NetworkConnectionAction', {})
                    .get('RemoteIpDetails', {}).get('IpAddressV4') or
                action_info.get('PortProbeAction', {})
                    .get('RemoteIpDetails', {}).get('IpAddressV4')
            )

            return LogRecord(
                timestamp=finding.get('UpdatedAt', datetime.utcnow().isoformat()),
                source=LogSource.CLOUDTRAIL,
                account=finding.get('AccountId', self.account),
                region=finding.get('Region', self.region),
                service=resource_type,
                action=action,
                status=LogStatus.FAILURE,
                severity=severity,
                resource_id=resource_id or 'unknown',
                resource_type=resource_type,
                principal=finding.get('AccountId', self.account),
                principal_type='unknown',
                src_ip=src_ip,
                message=f"[GuardDuty] {finding.get('Title', 'Unknown finding')}",
                raw=finding
            )

        except Exception as e:
            logger.error(f"Error normalizing GuardDuty finding: {e}")
            return None


# ============================================================================
# MAIN LOG COLLECTOR ORCHESTRATOR
# ============================================================================

class LogCollector:
    """
    Orchestrator: collects logs from all enabled sources for a given environment.

    Usage:
        # Use active environment (default: prod)
        collector = LogCollector()

        # Or explicitly select an environment
        collector = LogCollector(env='test')

        records = collector.collect_all()
        collector.save_to_file()
        print(collector.get_summary())
    """

    def __init__(self, env: str = None):
        if env:
            load_environment(env)
        self.environment = LogConfig.get_environment()
        self.region = LogConfig.get_primary_region()
        self.all_records: List[LogRecord] = []

    def collect_all(self) -> List[LogRecord]:
        """Collect logs from all enabled sources for the current environment"""
        logger.info("\n" + "=" * 80)
        logger.info(
            f"CIRA LOG COLLECTION  |  Environment: {self.environment.upper()}  |  Region: {self.region}"
        )
        logger.info("=" * 80)

        self.all_records = []
        enabled_sources = LogConfig.get_enabled_sources()

        if 'cloudtrail' in enabled_sources:
            try:
                records = CloudTrailCollector(region=self.region).collect_events()
                self.all_records.extend(records)
            except Exception as e:
                logger.error(f"CloudTrail collection failed: {e}")

        if 'vpc_flow' in enabled_sources:
            try:
                records = VPCFlowCollector(region=self.region).collect_logs()
                self.all_records.extend(records)
            except Exception as e:
                logger.error(f"VPC Flow Logs collection failed: {e}")

        if 'guardduty' in enabled_sources and LogConfig.is_guardduty_enabled():
            try:
                records = GuardDutyCollector(region=self.region).collect_findings()
                self.all_records.extend(records)
            except Exception as e:
                logger.error(f"GuardDuty collection failed: {e}")

        logger.info(
            f"\nTOTAL: {len(self.all_records)} log records collected from {self.environment.upper()}"
        )
        logger.info("=" * 80 + "\n")
        return self.all_records

    def save_to_file(self, records: List[LogRecord] = None) -> Optional[str]:
        """Save collected logs to JSON file. Returns filename."""
        if records is None:
            records = self.all_records

        if not records:
            logger.warning("No records to save")
            return None

        # Use the dominant source for the batch label
        source_counts: Dict[LogSource, int] = {}
        for r in records:
            source_counts[r.source] = source_counts.get(r.source, 0) + 1
        dominant_source = max(source_counts, key=source_counts.get)

        batch = LogBatch(source=dominant_source, records=records)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"logs_{self.environment}_{timestamp}.json"

        try:
            with open(filename, 'w') as f:
                json.dump(batch.to_dict(), f, indent=2, cls=DateTimeEncoder)
            logger.info(f"Logs saved to: {filename}")
            return filename
        except Exception as e:
            logger.error(f"Error saving logs: {e}")
            return None

    def get_summary(self) -> Dict:
        """Get summary statistics of collected logs"""
        if not self.all_records:
            return {
                'environment': self.environment,
                'total': 0,
                'by_source': {},
                'by_service': {},
                'by_severity': {},
                'by_status': {}
            }

        summary: Dict = {
            'environment': self.environment,
            'total': len(self.all_records),
            'by_source': {},
            'by_service': {},
            'by_severity': {},
            'by_status': {}
        }

        for record in self.all_records:
            source = record.source.value
            summary['by_source'][source] = summary['by_source'].get(source, 0) + 1
            summary['by_service'][record.service] = summary['by_service'].get(record.service, 0) + 1
            sev = record.severity.value
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1
            st = record.status.value
            summary['by_status'][st] = summary['by_status'].get(st, 0) + 1

        return summary


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    import sys
    env = sys.argv[1] if len(sys.argv) > 1 else 'prod'
    logger.info(f"Running log collection for environment: {env}")

    collector = LogCollector(env=env)
    records = collector.collect_all()
    filename = collector.save_to_file()
    summary = collector.get_summary()

    print(f"\nEnvironment : {summary['environment']}")
    print(f"Total       : {summary['total']}")
    print(f"By source   : {summary['by_source']}")
    print(f"By service  : {summary['by_service']}")
    print(f"By severity : {summary['by_severity']}")
    if filename:
        print(f"Saved to    : {filename}")
