from sqlalchemy import Column, String, Integer, DateTime, JSON, Enum, Boolean
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime
import enum

Base = declarative_base()

class Assessment(Base):
    __tablename__ = 'assessments'
    
    id = Column(String, primary_key=True)
    account_id = Column(String)
    region = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    total_checks = Column(Integer, default=0)
    passed = Column(Integer, default=0)
    failed = Column(Integer, default=0)
    findings = Column(JSON)

class Finding(Base):
    __tablename__ = 'findings'
    
    id = Column(String, primary_key=True)
    assessment_id = Column(String)
    check_id = Column(String)
    title = Column(String)
    description = Column(String)
    severity = Column(String)  # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String)    # PASS, FAIL
    threat_score = Column(Integer)
    affected_resource = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Resource(Base):
    __tablename__ = 'resources'
    
    id = Column(String, primary_key=True)
    resource_id = Column(String, unique=True)
    resource_type = Column(String)  # ec2, s3, rds, iam, elb
    account = Column(String)
    region = Column(String)
    name = Column(String)
    state = Column(String)
    resource_metadata = Column(JSON)  # Changed from 'metadata'
    discovered_at = Column(DateTime, default=datetime.utcnow)

class LogEvent(Base):
    __tablename__ = 'log_events'
    
    id = Column(String, primary_key=True)
    timestamp = Column(DateTime)
    source = Column(String)      # cloudtrail, vpc_flow, etc
    service = Column(String)     # ec2, iam, s3, etc
    action = Column(String)      # CreateUser, RunInstances, etc
    principal = Column(String)   # user or role
    status = Column(String)      # success, failure
    severity = Column(String)    # info, warning, error
    event_details = Column(JSON)  # Changed from 'details'
    created_at = Column(DateTime, default=datetime.utcnow)

class ComplianceStatus(Base):
    __tablename__ = 'compliance_status'
    
    id = Column(String, primary_key=True)
    framework = Column(String)   # CIS, GDPR, HIPAA, PCI-DSS
    total_checks = Column(Integer)
    passed = Column(Integer)
    failed = Column(Integer)
    percentage = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)