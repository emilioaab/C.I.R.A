"""
C.I.R.A Log Configuration
Centralized config for log collection sources, lookback windows, severity mappings
"""

import os
from datetime import datetime, timedelta
from typing import List, Dict
from dotenv import load_dotenv

load_dotenv()

# ============================================================================
# LOG COLLECTION SETTINGS
# ============================================================================

class LogConfig:
    """Centralized log configuration"""
    
    # ========================================================================
    # ENABLED SOURCES - Which log sources to collect from (MVP)
    # ========================================================================
    
    @classmethod
    def get_enabled_sources(cls) -> List[str]:
        """
        Which log sources to enable
        
        ENV: LOG_SOURCES=cloudtrail,vpc_flow,cloudwatch
        Default: cloudtrail,vpc_flow (no S3 polling by default)
        """
        sources_str = os.getenv('LOG_SOURCES', 'cloudtrail,vpc_flow')
        return [s.strip() for s in sources_str.split(',') if s.strip()]
    
    @classmethod
    def is_source_enabled(cls, source: str) -> bool:
        """Check if a specific source is enabled"""
        return source.lower() in cls.get_enabled_sources()
    
    # ========================================================================
    # TIME WINDOWS - Lookback period for collecting logs
    # ========================================================================
    
    @classmethod
    def get_lookback_minutes(cls) -> int:
        """
        How many minutes back to look for logs
        
        ENV: LOG_LOOKBACK_MIN=60
        Default: 60 minutes (1 hour)
        
        For CloudTrail: lookback_minutes_ago to now
        For CloudWatch: start_time = now - lookback_minutes
        For VPC Flow: lookback from S3 last run
        """
        try:
            return int(os.getenv('LOG_LOOKBACK_MIN', '60'))
        except ValueError:
            return 60
    
    @classmethod
    def get_start_time(cls) -> datetime:
        """Get start time for lookback window"""
        lookback = cls.get_lookback_minutes()
        return datetime.utcnow() - timedelta(minutes=lookback)
    
    @classmethod
    def get_end_time(cls) -> datetime:
        """Get end time (now)"""
        return datetime.utcnow()
    
    # ========================================================================
    # REGIONS - Which AWS regions to scan
    # ========================================================================
    
    @classmethod
    def get_regions(cls) -> List[str]:
        """
        Which AWS regions to collect logs from
        
        ENV: LOG_REGIONS=us-east-1,us-west-2,eu-west-1
        Default: us-east-1 (primary region)
        
        Note: CloudTrail is global but we specify region for API calls
        """
        regions_str = os.getenv('LOG_REGIONS', 'us-east-1')
        return [r.strip() for r in regions_str.split(',') if r.strip()]
    
    @classmethod
    def get_primary_region(cls) -> str:
        """Get primary/default region"""
        regions = cls.get_regions()
        return regions[0] if regions else 'us-east-1'
    
    # ========================================================================
    # PAGINATION - Handling large result sets
    # ========================================================================
    
    @classmethod
    def get_page_size(cls) -> int:
        """
        Number of records per page when paginating API results
        
        ENV: LOG_PAGE_SIZE=100
        Default: 100 (CloudTrail default)
        """
        try:
            return int(os.getenv('LOG_PAGE_SIZE', '100'))
        except ValueError:
            return 100
    
    @classmethod
    def get_max_pages(cls) -> int:
        """
        Maximum number of pages to fetch per source (to avoid huge backfills)
        
        ENV: LOG_MAX_PAGES=10
        Default: 10 (10 * 100 = 1000 logs max)
        """
        try:
            return int(os.getenv('LOG_MAX_PAGES', '10'))
        except ValueError:
            return 10
    
    # ========================================================================
    # FILTERING - What events to include/exclude
    # ========================================================================
    
    @classmethod
    def get_exclude_services(cls) -> List[str]:
        """
        Services to exclude (too noisy)
        
        ENV: LOG_EXCLUDE_SERVICES=cloudwatch,route53
        Default: cloudwatch (too chatty)
        """
        exclude_str = os.getenv('LOG_EXCLUDE_SERVICES', 'cloudwatch')
        return [s.strip() for s in exclude_str.split(',') if s.strip()]
    
    @classmethod
    def get_exclude_principals(cls) -> List[str]:
        """
        Principals to exclude (e.g., monitoring tools)
        
        ENV: LOG_EXCLUDE_PRINCIPALS=arn:aws:iam::...
        Default: empty (none excluded)
        """
        exclude_str = os.getenv('LOG_EXCLUDE_PRINCIPALS', '')
        return [p.strip() for p in exclude_str.split(',') if p.strip()]
    
    @classmethod
    def should_include_event(cls, service: str, principal: str) -> bool:
        """Check if event should be included"""
        if service in cls.get_exclude_services():
            return False
        if principal in cls.get_exclude_principals():
            return False
        return True
    
    # ========================================================================
    # SEVERITY MAPPING - Event names → severity levels
    # ========================================================================
    
    @classmethod
    def get_severity_rules(cls) -> Dict[str, str]:
        """
        Rules to infer severity from event names/types
        Maps event patterns to severity levels
        
        Format: "event_pattern" → "severity"
        """
        return {
            # CRITICAL
            r'ConsoleLogin|RootConsoleLogin': 'critical',
            r'UnauthorizedOperation|AccessDenied': 'critical',
            r'DeleteTrail|StopLogging|DeleteDatabase': 'critical',
            r'CreateAccessKey|AttachUserPolicy.*Admin': 'critical',
            r'ModifyDBInstance.*PubliclyAccessible.*true': 'critical',
            
            # HIGH
            r'CreateUser|CreateRole|CreateSecurityGroup': 'high',
            r'AttachUserPolicy|PutUserPolicy': 'high',
            r'ModifySecurityGroupIngress.*0\.0\.0\.0/0': 'high',
            r'CreateBucket|PutBucketPolicy': 'high',
            r'ModifyDBInstance|DeleteDBInstance': 'high',
            r'AssumeRole|GetSessionToken': 'high',
            
            # MEDIUM
            r'ModifyUser|ModifyRole|UpdateAssumeRolePolicy': 'medium',
            r'TagResource|UntagResource': 'medium',
            r'GetObject|PutObject|DeleteObject': 'medium',
            r'StartInstances|StopInstances|TerminateInstances': 'medium',
            r'RebootDBInstance': 'medium',
            r'CreateNetworkInterface': 'medium',
            
            # LOW
            r'DescribeInstances|ListBuckets|ListUsers': 'low',
            r'GetUser|GetRole': 'low',
            r'ListSecurityGroups|DescribeSecurityGroups': 'low',
            r'HeadObject|HeadBucket': 'low',
        }
    
    @classmethod
    def get_severity_for_action(cls, action_name: str) -> str:
        """
        Infer severity from action/event name
        Returns: 'critical', 'high', 'medium', 'low', 'info'
        """
        import re
        
        rules = cls.get_severity_rules()
        
        # Check each pattern
        for pattern, severity in rules.items():
            if re.search(pattern, action_name, re.IGNORECASE):
                return severity
        
        # Default: info
        return 'info'
    
    # ========================================================================
    # SERVICE MAPPING - Normalize service names
    # ========================================================================
    
    @classmethod
    def get_service_mapping(cls) -> Dict[str, str]:
        """
        Map event source to service name
        
        CloudTrail eventSource → normalized service
        """
        return {
            # Identity & Access
            'iam.amazonaws.com': 'iam',
            'sts.amazonaws.com': 'sts',
            'cognito-identity.amazonaws.com': 'cognito',
            
            # Compute
            'ec2.amazonaws.com': 'ec2',
            'elasticloadbalancing.amazonaws.com': 'elb',
            'autoscaling.amazonaws.com': 'autoscaling',
            'lambda.amazonaws.com': 'lambda',
            'ecs.amazonaws.com': 'ecs',
            
            # Storage
            's3.amazonaws.com': 's3',
            'ebs.amazonaws.com': 'ebs',
            'efs.amazonaws.com': 'efs',
            
            # Database
            'rds.amazonaws.com': 'rds',
            'dynamodb.amazonaws.com': 'dynamodb',
            'elasticache.amazonaws.com': 'elasticache',
            
            # Network
            'ec2.amazonaws.com': 'vpc',  # VPC is part of EC2
            'route53.amazonaws.com': 'route53',
            'cloudfront.amazonaws.com': 'cloudfront',
            
            # Management
            'cloudtrail.amazonaws.com': 'cloudtrail',
            'cloudwatch.amazonaws.com': 'cloudwatch',
            'logs.amazonaws.com': 'logs',
            'config.amazonaws.com': 'config',
            
            # Security
            'kms.amazonaws.com': 'kms',
            'acm.amazonaws.com': 'acm',
            'secretsmanager.amazonaws.com': 'secretsmanager',
        }
    
    @classmethod
    def get_service_name(cls, event_source: str) -> str:
        """Normalize event source to service name"""
        mapping = cls.get_service_mapping()
        return mapping.get(event_source, event_source.split('.')[0] if '.' in event_source else 'unknown')
    
    # ========================================================================
    # ACTION MAPPING - Normalize action names
    # ========================================================================
    
    @classmethod
    def get_action_mapping(cls) -> Dict[str, str]:
        """
        Map CloudTrail eventName to normalized LogAction
        """
        return {
            # Login/Auth
            'ConsoleLogin': 'login',
            'RootConsoleLogin': 'login',
            'CreateLoginProfile': 'login',
            'DeleteLoginProfile': 'logout',
            'GetSessionToken': 'login',
            'AssumeRole': 'login',
            
            # Failures
            'UnauthorizedOperation': 'access_denied',
            'AccessDenied': 'access_denied',
            'AuthFailure': 'auth_fail',
            
            # Create
            'CreateUser': 'create',
            'CreateRole': 'create',
            'CreateInstance': 'create',
            'CreateBucket': 'create',
            'CreateSecurityGroup': 'create',
            'CreateDatabase': 'create',
            
            # Delete
            'DeleteUser': 'delete',
            'DeleteRole': 'delete',
            'TerminateInstances': 'delete',
            'DeleteBucket': 'delete',
            'DeleteSecurityGroup': 'delete',
            'DeleteDatabase': 'delete',
            
            # Modify
            'UpdateUser': 'modify',
            'UpdateRole': 'modify',
            'ModifySecurityGroupIngress': 'sg_modify',
            'ModifySecurityGroupEgress': 'sg_modify',
            'ModifyDBInstance': 'modify',
            'PutBucketPolicy': 'policy_change',
            'AttachUserPolicy': 'policy_change',
            'DetachUserPolicy': 'policy_change',
            
            # Attach/Detach
            'AttachUserPolicy': 'attach',
            'AttachRolePolicy': 'attach',
            'DetachUserPolicy': 'detach',
            'DetachRolePolicy': 'detach',
        }
    
    @classmethod
    def get_action(cls, event_name: str) -> str:
        """Normalize event name to LogAction"""
        mapping = cls.get_action_mapping()
        return mapping.get(event_name, 'other')
    
    # ========================================================================
    # DEBUG/LOGGING
    # ========================================================================
    
    @classmethod
    def get_debug_mode(cls) -> bool:
        """Enable debug logging"""
        return os.getenv('LOG_DEBUG', 'false').lower() == 'true'
    
    @classmethod
    def print_config(cls):
        """Print current configuration for debugging"""
        print("\n" + "="*80)
        print("LOG CONFIGURATION")
        print("="*80)
        print(f"\nSOURCES (enabled):")
        for source in cls.get_enabled_sources():
            print(f"   • {source}")
        
        print(f"\nTIME WINDOW:")
        print(f"   Lookback: {cls.get_lookback_minutes()} minutes")
        print(f"   Start: {cls.get_start_time().isoformat()}")
        print(f"   End: {cls.get_end_time().isoformat()}")
        
        print(f"\nREGIONS:")
        for region in cls.get_regions():
            print(f"   • {region}")
        
        print(f"\nPAGINATION:")
        print(f"   Page size: {cls.get_page_size()}")
        print(f"   Max pages: {cls.get_max_pages()}")
        
        print(f"\nEXCLUDED SERVICES:")
        for service in cls.get_exclude_services():
            print(f"   • {service}")
        
        print(f"\nDEBUG: {cls.get_debug_mode()}")
        print("="*80 + "\n")

