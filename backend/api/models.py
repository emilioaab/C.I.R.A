from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()


class Assessment(Base):
    __tablename__ = 'assessments'

    id = Column(String, primary_key=True)
    environment = Column(String)           # prod / test
    account_id = Column(String)
    region = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_checks = Column(Integer, default=0)
    passed = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    pass_rate = Column(String)             # e.g. "80.0%"
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)


class Finding(Base):
    __tablename__ = 'findings'

    id = Column(String, primary_key=True)
    assessment_id = Column(String)
    check_id = Column(String)
    check_title = Column(String)
    service = Column(String)
    severity = Column(String)              # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String)               # PASS, FAIL
    resource_id = Column(String)
    resource_type = Column(String)
    region = Column(String)
    description = Column(Text)
    remediation = Column(Text)
    frameworks = Column(JSON)             # ["CIS", "GDPR", ...]
    threat_score = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)


class Resource(Base):
    __tablename__ = 'resources'

    id = Column(String, primary_key=True)
    resource_id = Column(String, unique=True)
    resource_type = Column(String)        # ec2, s3, rds, iam, elb
    account = Column(String)
    region = Column(String)
    name = Column(String)
    state = Column(String)
    resource_metadata = Column(JSON)
    discovered_at = Column(DateTime, default=datetime.utcnow)


class LogEvent(Base):
    __tablename__ = 'log_events'

    id = Column(String, primary_key=True)
    timestamp = Column(DateTime)
    source = Column(String)               # cloudtrail, vpc_flow
    account = Column(String)
    region = Column(String)
    service = Column(String)              # ec2, iam, s3 ...
    action = Column(String)              # CreateUser, RunInstances ...
    principal = Column(String)
    principal_type = Column(String)
    status = Column(String)              # success, failure
    severity = Column(String)            # info, low, medium, high, critical
    resource_id = Column(String)
    resource_type = Column(String)
    message = Column(Text)
    event_details = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)


class ComplianceStatus(Base):
    __tablename__ = 'compliance_status'

    id = Column(String, primary_key=True)
    assessment_id = Column(String)
    framework = Column(String)            # CIS, GDPR, HIPAA, PCI-DSS
    total_controls = Column(Integer, default=0)
    passed = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    compliance_percentage = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow)
