from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import CloudInstance, SecurityAlert, get_db_url

engine = create_engine(get_db_url())
Session = sessionmaker(bind=engine)
session = Session()

print("\n📊 נתונים במסד:")
print("=" * 50)

# שרתים
print("\n🖥️  שרתים:")
for instance in session.query(CloudInstance).all():
    status = "🟢" if instance.state == "running" else "🔴"
    print(f"  {status} {instance.name} ({instance.instance_id}) - {instance.state}")

# התראות
print("\n⚠️  התראות פתוחות:")
for alert in session.query(SecurityAlert).filter_by(status='open').all():
    severity_icon = {"low": "🟡", "medium": "🟠", "high": "🔴", "critical": "🔴"}.get(alert.severity, "⚪")
    print(f"  {severity_icon} [{alert.severity}] {alert.title}")

session.close()
