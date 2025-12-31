from database.models import Base, get_db_url
from sqlalchemy import create_engine

print("=" * 50)
print("🗄️  יצירת טבלאות במסד הנתונים")
print("=" * 50)

# יצירת חיבור
engine = create_engine(get_db_url())

# יצירת כל הטבלאות
Base.metadata.create_all(engine)

print("✅ הטבלאות נוצרו בהצלחה!")
print("\n📋 טבלאות שנוצרו:")
print("   - cloud_instances")
print("   - security_alerts") 
print("   - monitoring_metrics")
