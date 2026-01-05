"""
AWS to Database Synchronization
Pulls AWS EC2 instances and stores in PostgreSQL
"""

import boto3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from backend.api.models import Base, Resource
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

print("=" * 60)
print("AWS to Database Synchronization")
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
    
    print("\nConnecting to AWS...")
    ec2 = boto3.client(
        'ec2',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )
    print("OK: Connected to AWS")
    
    print("\nFetching EC2 instances from AWS...")
    response = ec2.describe_instances()
    
    instances_synced = 0
    instances_updated = 0
    
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            resource_id = instance['InstanceId']
            
            existing = session.query(Resource).filter_by(resource_id=resource_id).first()
            
            name = None
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break
            
            metadata = {
                'instance_type': instance.get('InstanceType'),
                'public_ip': instance.get('PublicIpAddress'),
                'private_ip': instance.get('PrivateIpAddress'),
                'availability_zone': instance.get('Placement', {}).get('AvailabilityZone'),
                'vpc_id': instance.get('VpcId'),
                'subnet_id': instance.get('SubnetId'),
                'key_name': instance.get('KeyName'),
                'security_groups': [sg['GroupId'] for sg in instance.get('SecurityGroups', [])]
            }
            
            if existing:
                existing.state = instance['State']['Name']
                existing.metadata = metadata
                existing.discovered_at = datetime.utcnow()
                print(f"UPDATED: {resource_id}")
                instances_updated += 1
            else:
                new_resource = Resource(
                    id=f"aws-ec2-{resource_id}",
                    resource_id=resource_id,
                    resource_type='ec2',
                    account=os.getenv('AWS_ACCOUNT_ID', 'unknown'),
                    region=instance.get('Placement', {}).get('AvailabilityZone', 'unknown'),
                    name=name,
                    state=instance['State']['Name'],
                    metadata=metadata
                )
                session.add(new_resource)
                print(f"ADDED: {resource_id}")
                instances_synced += 1
    
    session.commit()
    print(f"\nOK: Synchronization complete!")
    print(f"   - Added: {instances_synced} new instances")
    print(f"   - Updated: {instances_updated} existing instances")
    
    total_resources = session.query(Resource).count()
    print(f"   - Total in database: {total_resources} resources")
    
except Exception as e:
    print(f"\nFAIL: {e}")
    print("\nTroubleshooting:")
    print("   - Check AWS credentials in .env")
    print("   - Check PostgreSQL is running")
    print("   - Run init_database.py first")
    if 'session' in locals():
        session.rollback()
finally:
    if 'session' in locals():
        session.close()