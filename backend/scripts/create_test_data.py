"""
Create Test Data for C.I.R.A
Populates database with sample data for testing
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.api.models import Base, Assessment, Finding, Resource, LogEvent, ComplianceStatus
from datetime import datetime, timedelta
import uuid
import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("Create Test Data")
print("=" * 60)

def get_db_url():
    """Get database URL from environment variables"""
    return f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"

try:
    print("\nConnecting to PostgreSQL...")
    engine = create_engine(get_db_url())
    Session = sessionmaker(bind=engine)
    session = Session()
    print("OK: Connected to database")
    
    print("\nCreating test assessment...")
    assessment = Assessment(
        id=f"test-assessment-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        timestamp=datetime.utcnow(),
        environment='testing',
        region='us-east-1',
        total_checks=42,
        passed=8,
        failed=34,
        pass_rate='19.0%',
        critical_count=4,
        high_count=14,
        medium_count=16,
        low_count=0
    )
    session.add(assessment)
    session.flush()
    print(f"OK: Created assessment {assessment.id}")
    
    print("\nCreating test resources...")
    resources = [
        Resource(
            id='test-ec2-001',
            assessment_id=assessment.id,
            resource_id='i-test-001',
            resource_type='ec2',
            account='123456789012',
            region='us-east-1',
            name='Test-Web-Server',
            state='running',
            metadata={
                'instance_type': 't2.micro',
                'public_ip': '10.0.1.100',
                'private_ip': '10.0.1.100'
            }
        ),
        Resource(
            id='test-s3-001',
            assessment_id=assessment.id,
            resource_id='test-bucket-001',
            resource_type='s3',
            account='123456789012',
            region='us-east-1',
            name='Test-Bucket',
            state='active',
            metadata={
                'bucket_name': 'test-bucket-001',
                'versioning': 'Enabled',
                'encryption': 'AES256'
            }
        ),
        Resource(
            id='test-rds-001',
            assessment_id=assessment.id,
            resource_id='test-db-instance',
            resource_type='rds',
            account='123456789012',
            region='us-east-1',
            name='Test-Database',
            state='available',
            metadata={
                'engine': 'mysql',
                'version': '5.7.33',
                'encryption': 'enabled'
            }
        )
    ]
    for resource in resources:
        session.add(resource)
    session.flush()
    print(f"OK: Created {len(resources)} test resources")
    
    print("\nCreating test findings...")
    findings = [
        Finding(
            id='finding-001',
            check_id='AWS_IAM_001',
            check_title='Root account MFA enabled',
            assessment_id=assessment.id,
            service='iam',
            severity='CRITICAL',
            status='FAIL',
            resource_id='root',
            resource_type='iam-user',
            region='global',
            description='Root account does not have MFA enabled',
            remediation='Enable MFA for root account',
            frameworks=['CIS', 'PCI-DSS'],
            threat_score=100
        ),
        Finding(
            id='finding-002',
            check_id='AWS_EC2_001',
            check_title='Unrestricted SSH access',
            assessment_id=assessment.id,
            service='ec2',
            severity='HIGH',
            status='FAIL',
            resource_id='i-test-001',
            resource_type='security-group',
            region='us-east-1',
            description='Security group allows SSH (port 22) from 0.0.0.0/0',
            remediation='Restrict SSH access to specific IPs',
            frameworks=['CIS', 'PCI-DSS'],
            threat_score=90
        ),
        Finding(
            id='finding-003',
            check_id='AWS_S3_001',
            check_title='S3 bucket public access',
            assessment_id=assessment.id,
            service='s3',
            severity='CRITICAL',
            status='FAIL',
            resource_id='test-bucket-001',
            resource_type='s3-bucket',
            region='us-east-1',
            description='S3 bucket is publicly accessible',
            remediation='Block public access to S3 bucket',
            frameworks=['CIS', 'GDPR'],
            threat_score=95
        ),
        Finding(
            id='finding-004',
            check_id='AWS_RDS_001',
            check_title='RDS encryption at rest',
            assessment_id=assessment.id,
            service='rds',
            severity='HIGH',
            status='PASS',
            resource_id='test-db-instance',
            resource_type='rds-instance',
            region='us-east-1',
            description='RDS instance has encryption at rest enabled',
            remediation='N/A - Check passed',
            frameworks=['PCI-DSS', 'HIPAA'],
            threat_score=0
        )
    ]
    for finding in findings:
        session.add(finding)
    session.flush()
    print(f"OK: Created {len(findings)} test findings")
    
    print("\nCreating test log events...")
    log_events = [
        LogEvent(
            id=f'log-{uuid.uuid4()}',
            timestamp=datetime.utcnow() - timedelta(minutes=10),
            source='cloudtrail',
            account='123456789012',
            region='us-east-1',
            service='iam',
            action='CreateUser',
            status='success',
            severity='medium',
            resource_id='test-user',
            resource_type='iam-user',
            principal='arn:aws:iam::123456789012:user/admin',
            principal_type='iam-user',
            message='CreateUser request for test-user',
            raw_data={'EventName': 'CreateUser', 'Username': 'test-user'}
        ),
        LogEvent(
            id=f'log-{uuid.uuid4()}',
            timestamp=datetime.utcnow() - timedelta(minutes=5),
            source='cloudtrail',
            account='123456789012',
            region='us-east-1',
            service='ec2',
            action='RunInstances',
            status='success',
            severity='low',
            resource_id='i-test-002',
            resource_type='ec2-instance',
            principal='arn:aws:iam::123456789012:user/admin',
            principal_type='iam-user',
            message='RunInstances request for i-test-002',
            raw_data={'EventName': 'RunInstances', 'InstanceId': 'i-test-002'}
        ),
        LogEvent(
            id=f'log-{uuid.uuid4()}',
            timestamp=datetime.utcnow(),
            source='cloudtrail',
            account='123456789012',
            region='us-east-1',
            service='iam',
            action='GetUser',
            status='success',
            severity='info',
            resource_id='test-user',
            resource_type='iam-user',
            principal='arn:aws:iam::123456789012:user/admin',
            principal_type='iam-user',
            message='GetUser request for test-user',
            raw_data={'EventName': 'GetUser', 'UserName': 'test-user'}
        )
    ]
    for log_event in log_events:
        session.add(log_event)
    session.flush()
    print(f"OK: Created {len(log_events)} test log events")
    
    print("\nCreating compliance status...")
    compliance_statuses = [
        ComplianceStatus(
            id='compliance-cis-001',
            assessment_id=assessment.id,
            framework='CIS',
            total_controls=42,
            passed=8,
            failed=34,
            compliance_percentage=19.0
        ),
        ComplianceStatus(
            id='compliance-pci-001',
            assessment_id=assessment.id,
            framework='PCI-DSS',
            total_controls=30,
            passed=5,
            failed=25,
            compliance_percentage=16.7
        ),
        ComplianceStatus(
            id='compliance-gdpr-001',
            assessment_id=assessment.id,
            framework='GDPR',
            total_controls=25,
            passed=7,
            failed=18,
            compliance_percentage=28.0
        )
    ]
    for status in compliance_statuses:
        session.add(status)
    session.flush()
    print(f"OK: Created {len(compliance_statuses)} compliance statuses")
    
    session.commit()
    print("\nOK: Test data created successfully!")
    print("\nSummary:")
    print(f"   - Assessments: 1")
    print(f"   - Resources: {len(resources)}")
    print(f"   - Findings: {len(findings)}")
    print(f"   - Log Events: {len(log_events)}")
    print(f"   - Compliance Statuses: {len(compliance_statuses)}")
    
    print("\nNext steps:")
    print("   1. Run: python api.py")
    print("   2. Visit: http://localhost:5000")
    print("   3. Check database with check_data.py")
    
except Exception as e:
    print(f"\nFAIL: {e}")
    print("\nTroubleshooting:")
    print("   - Check PostgreSQL is running")
    print("   - Run init_database.py first")
    print("   - Verify .env has correct DB credentials")
    if 'session' in locals():
        session.rollback()
finally:
    if 'session' in locals():
        session.close()