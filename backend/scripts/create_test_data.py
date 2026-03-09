"""
Create Test Data for C.I.R.A
Populates DB with realistic sample data for testing the dashboard
"""

import os
import sys
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.api.models import Base, Assessment, Finding, Resource, LogEvent, ComplianceStatus

def get_db_url():
    return (
        f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}"
        f"@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
    )

print("=" * 60)
print("C.I.R.A - Create Test Data")
print("=" * 60)

try:
    engine = create_engine(get_db_url())
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    print("OK: Connected to database and reset tables")

    # ----------------------------------------------------------------
    # ASSESSMENT
    # ----------------------------------------------------------------
    assessment_id = f"test-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    assessment = Assessment(
        id=assessment_id,
        environment='test',
        account_id='828414850095',
        region='us-east-1',
        timestamp=datetime.utcnow(),
        total_checks=42,
        passed=8,
        failed=34,
        pass_rate='19.0%',
        critical_count=4,
        high_count=14,
        medium_count=16,
        low_count=0,
    )
    session.add(assessment)
    session.flush()
    print(f"OK: Assessment {assessment_id}")

    # ----------------------------------------------------------------
    # FINDINGS
    # ----------------------------------------------------------------
    findings_data = [
        ('AWS_IAM_001', 'Root account MFA enabled',       'iam', 'CRITICAL', 'FAIL',  'root-account',    'iam-root',       'Root account does not have MFA enabled',              'Enable MFA on root account via AWS Console',        ['CIS', 'GDPR', 'HIPAA'], 95),
        ('AWS_IAM_002', 'IAM user MFA enabled',           'iam', 'HIGH',     'FAIL',  'user-alice',      'iam-user',       'IAM user alice does not have MFA enabled',            'Enable MFA for user alice',                         ['CIS', 'HIPAA'],         80),
        ('AWS_IAM_003', 'Overly permissive IAM policy',   'iam', 'HIGH',     'FAIL',  'AdminPolicy',     'iam-policy',     'Policy AdminPolicy has wildcard (*) permissions',     'Apply least privilege - remove wildcard permissions',['CIS', 'GDPR'],          85),
        ('AWS_IAM_004', 'Access key rotation',            'iam', 'MEDIUM',   'FAIL',  'user-bob/AKIA123','iam-access-key', 'Access key for user-bob is 120 days old',             'Rotate access key for user-bob',                    ['CIS'],                  60),
        ('AWS_EC2_001', 'Unrestricted SSH access',        'ec2', 'CRITICAL', 'FAIL',  'sg-0a1b2c3d',    'security-group', 'Security group allows SSH from 0.0.0.0/0',            'Restrict SSH to specific IP ranges',                ['CIS', 'PCI-DSS'],       92),
        ('AWS_VPC_002', 'VPC Flow Logs enabled',          'vpc', 'MEDIUM',   'FAIL',  'vpc-12345678',    'vpc',            'VPC does not have Flow Logs enabled',                 'Enable VPC Flow Logs for network monitoring',        ['CIS', 'GDPR'],          65),
        ('AWS_S3_001',  'S3 bucket public access blocked','s3',  'CRITICAL', 'FAIL',  'my-data-bucket',  's3-bucket',      'S3 bucket my-data-bucket allows public access',       'Enable all S3 public access blocks',                ['CIS', 'GDPR', 'HIPAA'], 95),
        ('AWS_RDS_001', 'RDS database encryption',        'rds', 'HIGH',     'FAIL',  'prod-db-01',      'rds-instance',   'RDS instance prod-db-01 is not encrypted',            'Enable encryption at rest for RDS instance',        ['CIS', 'GDPR', 'HIPAA'], 80),
        ('AWS_CT_001',  'CloudTrail enabled',             'cloudtrail','INFO','PASS',  'cira-cloudtrail','cloudtrail',     'CloudTrail is logging',                               'N/A',                                               ['CIS'],                  0),
        ('AWS_LOG_001', 'CloudWatch logs configured',     'logs','MEDIUM',   'FAIL',  'account',         'log-group',      'No CloudWatch log groups configured',                 'Create CloudWatch log groups',                      ['CIS', 'GDPR'],          70),
    ]

    for check_id, check_title, service, severity, status, resource_id, resource_type, desc, remediation, frameworks, threat_score in findings_data:
        session.add(Finding(
            id=str(uuid.uuid4()),
            assessment_id=assessment_id,
            check_id=check_id,
            check_title=check_title,
            service=service,
            severity=severity,
            status=status,
            resource_id=resource_id,
            resource_type=resource_type,
            region='us-east-1',
            description=desc,
            remediation=remediation,
            frameworks=frameworks,
            threat_score=threat_score,
            timestamp=datetime.utcnow(),
        ))
    print(f"OK: {len(findings_data)} findings")

    # ----------------------------------------------------------------
    # RESOURCES
    # ----------------------------------------------------------------
    resources_data = [
        ('i-0abc123def456',  'ec2_instances',    'running', {'instance_type': 't3.micro',  'public_ip': '54.1.2.3'}),
        ('i-0def456abc789',  'ec2_instances',    'stopped', {'instance_type': 't3.small',  'public_ip': None}),
        ('my-data-bucket',   's3_buckets',       'active',  {'versioning': 'Disabled', 'encryption': 'None'}),
        ('cira-logs-bucket', 's3_buckets',       'active',  {'versioning': 'Enabled',  'encryption': 'AES256'}),
        ('prod-db-01',       'rds_databases',    'available',{'engine': 'mysql', 'version': '8.0', 'encrypted': False}),
        ('AdminRole',        'iam_roles',        'active',  {'arn': 'arn:aws:iam::828414850095:role/AdminRole'}),
        ('ReadOnlyRole',     'iam_roles',        'active',  {'arn': 'arn:aws:iam::828414850095:role/ReadOnlyRole'}),
        ('prod-alb-01',      'elb_load_balancers','active', {'scheme': 'internet-facing', 'state': 'active'}),
    ]

    for rid, rtype, state, metadata in resources_data:
        session.add(Resource(
            id=str(uuid.uuid4()),
            resource_id=rid,
            resource_type=rtype,
            account='828414850095',
            region='us-east-1',
            name=rid,
            state=state,
            resource_metadata=metadata,
        ))
    print(f"OK: {len(resources_data)} resources")

    # ----------------------------------------------------------------
    # LOG EVENTS
    # ----------------------------------------------------------------
    log_entries = [
        (datetime.utcnow() - timedelta(minutes=5),  'cloudtrail', 'iam', 'create',       'arn:aws:iam::828414850095:user/admin', 'success', 'medium',   'CreateUser - new-employee'),
        (datetime.utcnow() - timedelta(minutes=12), 'cloudtrail', 'ec2', 'modify',       'arn:aws:iam::828414850095:user/admin', 'success', 'high',     'ModifySecurityGroupIngress - sg-0a1b2c3d'),
        (datetime.utcnow() - timedelta(minutes=20), 'cloudtrail', 's3',  'policy_change','arn:aws:iam::828414850095:user/devops','success', 'high',     'PutBucketPolicy - my-data-bucket'),
        (datetime.utcnow() - timedelta(minutes=35), 'cloudtrail', 'iam', 'login',        'root',                                'success', 'critical', 'RootConsoleLogin'),
        (datetime.utcnow() - timedelta(minutes=45), 'cloudtrail', 'iam', 'access_denied','arn:aws:iam::828414850095:user/intern','failure', 'critical', 'UnauthorizedOperation - GetSecretValue'),
        (datetime.utcnow() - timedelta(minutes=58), 'cloudtrail', 'rds', 'modify',       'arn:aws:iam::828414850095:user/admin', 'success', 'high',     'ModifyDBInstance - prod-db-01'),
        (datetime.utcnow() - timedelta(hours=1),    'cloudtrail', 'ec2', 'create',       'arn:aws:iam::828414850095:user/admin', 'success', 'medium',   'RunInstances - i-0abc123def456'),
        (datetime.utcnow() - timedelta(hours=2),    'cloudtrail', 'iam', 'attach',       'arn:aws:iam::828414850095:user/admin', 'success', 'high',     'AttachUserPolicy - AdministratorAccess'),
    ]

    for ts, source, service, action, principal, status, severity, message in log_entries:
        session.add(LogEvent(
            id=str(uuid.uuid4()),
            timestamp=ts,
            source=source,
            account='828414850095',
            region='us-east-1',
            service=service,
            action=action,
            principal=principal,
            principal_type='iam-user',
            status=status,
            severity=severity,
            resource_id='unknown',
            resource_type='unknown',
            message=message,
            event_details={'raw': message},
        ))
    print(f"OK: {len(log_entries)} log events")

    # ----------------------------------------------------------------
    # COMPLIANCE
    # ----------------------------------------------------------------
    compliance_data = [
        ('CIS',     42, 8,  34, 19.0),
        ('GDPR',    25, 7,  18, 28.0),
        ('HIPAA',   30, 5,  25, 16.7),
        ('PCI-DSS', 20, 4,  16, 20.0),
    ]

    for fw, total, passed, failed, pct in compliance_data:
        session.add(ComplianceStatus(
            id=str(uuid.uuid4()),
            assessment_id=assessment_id,
            framework=fw,
            total_controls=total,
            passed=passed,
            failed=failed,
            compliance_percentage=pct,
        ))
    print(f"OK: {len(compliance_data)} compliance frameworks")

    session.commit()
    print("\nOK: All test data saved to DB!")
    print("\nNext steps:")
    print("  1. python api.py")
    print("  2. Open http://localhost:5000")

except Exception as e:
    print(f"\nFAIL: {e}")
    if 'session' in locals():
        session.rollback()
finally:
    if 'session' in locals():
        session.close()
