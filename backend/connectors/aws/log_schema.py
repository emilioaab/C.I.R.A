"""
C.I.R.A Log Schema
Normalized log record structure for all sources (CloudTrail, CloudWatch, VPC Flow Logs)
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
from datetime import datetime
from enum import Enum

# ============================================================================
# ENUMS - Log Classification
# ============================================================================

class LogSource(str, Enum):
    """Where the log came from"""
    CLOUDTRAIL = "cloudtrail"
    CLOUDWATCH = "cloudwatch"
    VPC_FLOW = "vpc_flow"
    S3_ACCESS = "s3_access"

class LogAction(str, Enum):
    """What action was taken (normalized across sources)"""
    # Auth/Access
    LOGIN = "login"
    LOGOUT = "logout"
    AUTH_FAIL = "auth_fail"
    ACCESS_DENIED = "access_denied"
    
    # Resource Changes
    CREATE = "create"
    DELETE = "delete"
    MODIFY = "modify"
    ATTACH = "attach"
    DETACH = "detach"
    
    # Security
    SG_MODIFY = "sg_modify"
    POLICY_CHANGE = "policy_change"
    PERMISSION_CHANGE = "permission_change"
    
    # Network
    NETWORK_FLOW = "network_flow"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    
    # Default
    OTHER = "other"

class LogStatus(str, Enum):
    """Success/Failure status"""
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

class LogSeverity(str, Enum):
    """Risk level of the action"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# ============================================================================
# LOG RECORD - Main normalized structure
# ============================================================================

@dataclass
class LogRecord:
    """
    Normalized log record - single schema for all sources
    
    Example 1 (CloudTrail):
        LogRecord(
            timestamp='2026-01-04T10:30:00Z',
            source='cloudtrail',
            account='828414850095',
            region='us-east-1',
            service='iam',
            action='create',
            resource_id='user-john',
            resource_type='iam-user',
            principal='arn:aws:iam::828414850095:user/admin',
            principal_type='iam-user',
            status='success',
            severity='medium',
            src_ip='203.0.113.42',
            dst_ip='iam.amazonaws.com',
            message='CreateUser request',
            raw={'eventName': 'CreateUser', ...}  # Original event
        )
    
    Example 2 (VPC Flow Logs):
        LogRecord(
            timestamp='2026-01-04T10:30:15Z',
            source='vpc_flow',
            account='828414850095',
            region='us-east-1',
            service='vpc',
            action='accepted',
            resource_id='eni-12345678',
            resource_type='network-interface',
            principal='eni-12345678',
            principal_type='eni',
            status='success',
            severity='info',
            src_ip='10.0.1.100',
            dst_ip='10.0.2.50',
            message='TCP flow accepted',
            raw={'srcaddr': '10.0.1.100', ...}
        )
    """
    
    # ========================================================================
    # REQUIRED FIELDS
    # ========================================================================
    
    timestamp: str
    """ISO 8601 timestamp of the event (e.g., '2026-01-04T10:30:00Z')"""
    
    source: LogSource
    """Where log came from: cloudtrail, cloudwatch, vpc_flow, s3_access"""
    
    account: str
    """AWS Account ID (e.g., '828414850095')"""
    
    region: str
    """AWS Region (e.g., 'us-east-1')"""
    
    service: str
    """AWS Service (e.g., 'iam', 'ec2', 's3', 'cloudtrail')"""
    
    action: LogAction
    """Normalized action: create, delete, modify, login, auth_fail, etc."""
    
    status: LogStatus
    """Success or Failure"""
    
    severity: LogSeverity
    """Risk level: info, low, medium, high, critical"""
    
    # ========================================================================
    # RESOURCE & PRINCIPAL
    # ========================================================================
    
    resource_id: str
    """What resource was accessed (e.g., 'i-1234567890abcdef0', 'user-john', 'sg-12345')"""
    
    resource_type: str
    """Type of resource (e.g., 'ec2-instance', 'iam-user', 'security-group')"""
    
    principal: str
    """Who did the action (ARN or IP) (e.g., 'arn:aws:iam::...', '203.0.113.42')"""
    
    principal_type: str
    """Type of principal (iam-user, role, service, ip, etc.)"""
    
    # ========================================================================
    # NETWORK
    # ========================================================================
    
    src_ip: Optional[str] = None
    """Source IP address (if network-related)"""
    
    dst_ip: Optional[str] = None
    """Destination IP address (if network-related)"""
    
    # ========================================================================
    # METADATA
    # ========================================================================
    
    message: str = ""
    """Human-readable summary of the event"""
    
    raw: Dict[str, Any] = None
    """Original event data from source (for reference/debugging)"""
    
    # ========================================================================
    # EXTRA CONTEXT (optional)
    # ========================================================================
    
    user_agent: Optional[str] = None
    """HTTP User-Agent if available"""
    
    error_code: Optional[str] = None
    """Error code if operation failed"""
    
    response_code: Optional[int] = None
    """HTTP response code (for API calls)"""
    
    # ========================================================================
    # INTERNAL METADATA
    # ========================================================================
    
    ingested_at: str = None
    """When we ingested this log (set by collector)"""
    
    log_id: str = ""
    """Unique log ID for deduplication"""
    
    def __post_init__(self):
        """Set defaults after initialization"""
        if self.raw is None:
            self.raw = {}
        if self.ingested_at is None:
            self.ingested_at = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        # Convert enums to strings
        data['source'] = self.source.value
        data['action'] = self.action.value
        data['status'] = self.status.value
        data['severity'] = self.severity.value
        return data

# ============================================================================
# BATCH CONTAINER - Multiple logs
# ============================================================================

@dataclass
class LogBatch:
    """
    Container for a batch of log records
    Used when writing to file or DB
    """
    
    source: LogSource
    """Source all logs came from"""
    
    records: list
    """List of LogRecord objects"""
    
    timestamp: str = None
    """When batch was created"""
    
    count: int = 0
    """Number of records"""
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        self.count = len(self.records)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'source': self.source.value,
            'timestamp': self.timestamp,
            'count': self.count,
            'records': [r.to_dict() if hasattr(r, 'to_dict') else r for r in self.records]
        }

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def create_log_record(
    timestamp: str,
    source: LogSource,
    account: str,
    region: str,
    service: str,
    action: LogAction,
    status: LogStatus,
    severity: LogSeverity,
    resource_id: str,
    resource_type: str,
    principal: str,
    principal_type: str,
    message: str = "",
    src_ip: str = None,
    dst_ip: str = None,
    raw: Dict = None,
    **kwargs
) -> LogRecord:
    """Factory function to create a LogRecord with validation"""
    
    return LogRecord(
        timestamp=timestamp,
        source=source,
        account=account,
        region=region,
        service=service,
        action=action,
        status=status,
        severity=severity,
        resource_id=resource_id,
        resource_type=resource_type,
        principal=principal,
        principal_type=principal_type,
        message=message,
        src_ip=src_ip,
        dst_ip=dst_ip,
        raw=raw or {},
        **kwargs
    )