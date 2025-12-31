import boto3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, CloudInstance, get_db_url
from datetime import datetime
import os
from dotenv import load_dotenv

# טעינת משתני סביבה
load_dotenv()

print("=" * 50)
print("🔄 סנכרון נתוני AWS למסד הנתונים")
print("=" * 50)

# יצירת חיבור לDB
engine = create_engine(get_db_url())
Session = sessionmaker(bind=engine)
session = Session()

# יצירת חיבור לAWS
ec2 = boto3.client(
    'ec2',
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    region_name=os.getenv('AWS_REGION', 'us-east-1')
)

try:
    # קבלת כל השרתים מAWS
    response = ec2.describe_instances()
    
    instances_count = 0
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            
            # בדיקה אם השרת כבר קיים בDB
            existing = session.query(CloudInstance).filter_by(instance_id=instance_id).first()
            
            if existing:
                # עדכון נתונים קיימים
                existing.state = instance['State']['Name']
                existing.last_seen = datetime.utcnow()
                print(f"📝 מעדכן: {instance_id}")
            else:
                # יצירת רשומה חדשה
                name = None
                for tag in instance.get('Tags', []):
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                        break
                
                new_instance = CloudInstance(
                    instance_id=instance_id,
                    provider='AWS',
                    name=name,
                    state=instance['State']['Name'],
                    instance_type=instance.get('InstanceType'),
                    public_ip=instance.get('PublicIpAddress'),
                    private_ip=instance.get('PrivateIpAddress'),
                    region=instance.get('Placement', {}).get('AvailabilityZone')
                )
                session.add(new_instance)
                print(f"➕ מוסיף: {instance_id}")
                
            instances_count += 1
    
    # שמירת השינויים
    session.commit()
    print(f"\n✅ סנכרון הושלם! נמצאו {instances_count} שרתים")
    
    # הצגת סיכום מהDB
    total_in_db = session.query(CloudInstance).count()
    print(f"📊 סה״כ במסד הנתונים: {total_in_db} שרתים")
    
except Exception as e:
    print(f"❌ שגיאה: {e}")
    session.rollback()
finally:
    session.close()
