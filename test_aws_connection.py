#!/usr/bin/env python3
"""
AWS Connection Test
This script tests AWS connection and shows account resources
"""

import boto3
import os
from dotenv import load_dotenv

load_dotenv()

def test_connection():
    """Test if the connection works"""
    try:
        print("Connecting to AWS...")
        
        ec2 = boto3.client('ec2',
            region_name=os.getenv('AWS_REGION'),
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
        
        regions = ec2.describe_regions()
        print(f"OK: Connection successful! Found {len(regions['Regions'])} regions")
        
        return True
        
    except Exception as e:
        print(f"FAIL: Connection error: {e}")
        return False

def show_my_resources():
    """Show what you currently have in AWS"""
    print("\nYour AWS Status:")
    print("=" * 50)
    
    ec2 = boto3.client('ec2',
        region_name=os.getenv('AWS_REGION'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    
    instances = ec2.describe_instances()
    instance_count = 0
    
    print("\nInstances (EC2):")
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_count += 1
            name = 'No name'
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    name = tag['Value']
            
            print(f"   - {name}")
            print(f"     ID: {instance['InstanceId']}")
            print(f"     Status: {instance['State']['Name']}")
            print(f"     Type: {instance['InstanceType']}")
    
    if instance_count == 0:
        print("   No instances yet")
    
    s3 = boto3.client('s3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    
    print("\nStorage (S3 Buckets):")
    try:
        buckets = s3.list_buckets()
        if buckets['Buckets']:
            for bucket in buckets['Buckets']:
                print(f"   - {bucket['Name']}")
                print(f"     Created: {bucket['CreationDate'].strftime('%m/%d/%Y')}")
        else:
            print("   No buckets yet")
    except:
        print("   No S3 permissions")
    
    print("\nNetworks (VPCs):")
    vpcs = ec2.describe_vpcs()
    for vpc in vpcs['Vpcs']:
        vpc_name = vpc.get('VpcId', 'Unknown')
        for tag in vpc.get('Tags', []):
            if tag['Key'] == 'Name':
                vpc_name = tag['Value']
        
        print(f"   - {vpc_name}")
        print(f"     CIDR: {vpc['CidrBlock']}")
        print(f"     Default: {'Yes' if vpc.get('IsDefault') else 'No'}")

def create_first_test_instance():
    """Create first test instance"""
    print("\nWant to create your first test instance?")
    answer = input("   Type 'yes' to create: ").strip().lower()
    
    if answer != 'yes':
        print("   Cancelled.")
        return
    
    ec2 = boto3.client('ec2',
        region_name=os.getenv('AWS_REGION'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    
    try:
        print("\nCreating test instance...")
        
        images = ec2.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        
        if not images['Images']:
            print("FAIL: No suitable image found")
            return
            
        latest_ami = sorted(images['Images'], 
                           key=lambda x: x['CreationDate'], 
                           reverse=True)[0]
        
        response = ec2.run_instances(
            ImageId=latest_ami['ImageId'],
            MinCount=1,
            MaxCount=1,
            InstanceType='t3.micro',
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'Name', 'Value': 'CIRA-Test-Instance'},
                    {'Key': 'Project', 'Value': 'CIRA'},
                    {'Key': 'CreatedBy', 'Value': 'Setup-Script'}
                ]
            }]
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        print(f"OK: Created successfully! ID: {instance_id}")
        print("   Instance will be ready in 1-2 minutes")
        
    except Exception as e:
        print(f"FAIL: Error: {e}")

# Run the tests
if __name__ == "__main__":
    print("=" * 50)
    print("AWS Connection Test - C.I.R.A Project")
    print("=" * 50)
    
    if test_connection():
        show_my_resources()
        create_first_test_instance()
    
    print("\nDone!")