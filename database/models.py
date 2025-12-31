from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os
from dotenv import load_dotenv

# טעינת משתני סביבה
load_dotenv()

# יצירת Base class
Base = declarative_base()

# מודל לשרתי ענן (EC2)
class CloudInstance(Base):
    __tablename__ = 'cloud_instances'
    
    id = Column(Integer, primary_key=True)
    instance_id = Column(String(100), unique=True, nullable=False)
    provider = Column(String(20), default='AWS')
    name = Column(String(200))
    state = Column(String(50))
    instance_type = Column(String(50))
    public_ip = Column(String(50))
    private_ip = Column(String(50))
    region = Column(String(50))
    last_seen = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

# מודל להתראות אבטחה
class SecurityAlert(Base):
    __tablename__ = 'security_alerts'
    
    id = Column(Integer, primary_key=True)
    alert_type = Column(String(50))  # anomaly, misconfiguration
    severity = Column(String(20))    # low, medium, high, critical
    instance_id = Column(String(100))
    title = Column(String(200))
    description = Column(Text)
    status = Column(String(20), default='open')  # open, investigating, resolved
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime)

# מודל למטריקות ניטור
class MonitoringMetric(Base):
    __tablename__ = 'monitoring_metrics'
    
    id = Column(Integer, primary_key=True)
    instance_id = Column(String(100))
    metric_type = Column(String(50))  # cpu, memory, network
    value = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)

# פונקציה ליצירת החיבור
def get_db_url():
    return f"postgresql://{os.getenv('DB_USER')}:{os.getenv('DB_PASSWORD')}@{os.getenv('DB_HOST')}:{os.getenv('DB_PORT')}/{os.getenv('DB_NAME')}"
