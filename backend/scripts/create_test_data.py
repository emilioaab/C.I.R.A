from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, CloudInstance, SecurityAlert, get_db_url
from datetime import datetime, timedelta
import random

print("=" * 50)
print("🧪 יצירת נתונים לדוגמה")
print("=" * 50)

# יצירת חיבור
engine = create_engine(get_db_url())
Session = sessionmaker(bind=engine)
session = Session()

# יצירת שרתים לדוגמה
instances = [
    {
        'instance_id': 'i-demo-001',
        'name': 'Web-Server-1',
        'state': 'running',
        'instance_type': 't2.micro',
        'public_ip': '54.123.45.67',
        'private_ip': '172.31.0.1',
        'region': 'us-east-1a'
    },
    {
        'instance_id': 'i-demo-002',
        'name': 'Database-Server',
        'state': 'running',
        'instance_type': 't2.small',
        'public_ip': None,
        'private_ip': '172.31.0.2',
        'region': 'us-east-1a'
    },
    {
        'instance_id': 'i-demo-003',
        'name': 'Test-Server',
        'state': 'stopped',
        'instance_type': 't2.micro',
        'public_ip': None,
        'private_ip': '172.31.0.3',
        'region': 'us-east-1b'
    }
]

# הוספת השרתים
for inst in instances:
    existing = session.query(CloudInstance).filter_by(instance_id=inst['instance_id']).first()
    if not existing:
        new_instance = CloudInstance(**inst)
        session.add(new_instance)
        print(f"➕ נוסף שרת: {inst['name']} ({inst['instance_id']})")

# יצירת התראות לדוגמה
alerts = [
    {
        'alert_type': 'misconfiguration',
        'severity': 'high',
        'instance_id': 'i-demo-001',
        'title': 'Security Group Too Open',
        'description': 'Port 22 (SSH) is open to 0.0.0.0/0'
    },
    {
        'alert_type': 'anomaly',
        'severity': 'medium',
        'instance_id': 'i-demo-002',
        'title': 'High CPU Usage',
        'description': 'CPU usage above 80% for last 10 minutes'
    }
]

for alert in alerts:
    new_alert = SecurityAlert(**alert)
    session.add(new_alert)
    print(f"⚠️  נוספה התראה: {alert['title']}")

# שמירה
session.commit()

# הצגת סיכום
total_instances = session.query(CloudInstance).count()
total_alerts = session.query(SecurityAlert).filter_by(status='open').count()

print("\n✅ הנתונים נוצרו בהצלחה!")
print(f"📊 סיכום:")
print(f"   - {total_instances} שרתים במערכת")
print(f"   - {total_alerts} התראות פתוחות")

session.close()
