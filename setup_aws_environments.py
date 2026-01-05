#!/usr/bin/env python3
"""
Setup AWS Environments for C.I.R.A
Creates and configures testing and production environments
"""

import boto3
import json
import sys
from dotenv import load_dotenv
import os

load_dotenv()

class EnvironmentSetup:
    """Setup AWS environments"""
    
    def __init__(self):
        self.region = os.getenv('AWS_REGION', 'us-east-1')
        self.ec2 = boto3.client('ec2', region_name=self.region)
        self.s3 = boto3.client('s3')
        self.cloudtrail = boto3.client('cloudtrail', region_name=self.region)
    
    def verify_credentials(self):
        """Verify AWS credentials work"""
        try:
            print("Verifying AWS credentials...")
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            print(f"OK: Connected as {identity['Arn']}")
            print(f"Account: {identity['Account']}")
            return True
        except Exception as e:
            print(f"FAIL: {e}")
            return False
    
    def setup_cloudtrail(self):
        """Enable CloudTrail"""
        try:
            print("\nSetting up CloudTrail...")
            
            trail_name = 'cira-cloudtrail'
            bucket_name = f'cira-cloudtrail-logs-{os.getenv("AWS_REGION")}'
            
            try:
                self.cloudtrail.describe_trails(trailNameList=[trail_name])
                print("OK: CloudTrail already configured")
                return True
            except:
                print("Creating CloudTrail...")
                
                try:
                    self.s3.create_bucket(Bucket=bucket_name)
                    print(f"OK: Created S3 bucket: {bucket_name}")
                except:
                    print(f"INFO: Bucket already exists: {bucket_name}")
                
                self.cloudtrail.create_trail(
                    Name=trail_name,
                    S3BucketName=bucket_name,
                    IsMultiRegionTrail=True
                )
                print(f"OK: Created CloudTrail: {trail_name}")
                return True
        
        except Exception as e:
            print(f"FAIL: {e}")
            return False
    
    def setup_vpc_flow_logs(self):
        """Enable VPC Flow Logs"""
        try:
            print("\nSetting up VPC Flow Logs...")
            
            vpcs = self.ec2.describe_vpcs()
            
            for vpc in vpcs['Vpcs']:
                vpc_id = vpc['VpcId']
                print(f"Checking VPC: {vpc_id}...")
                
                try:
                    flow_logs = self.ec2.describe_flow_logs(
                        Filter=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                    )
                    
                    if flow_logs['FlowLogs']:
                        print(f"OK: VPC Flow Logs already enabled for {vpc_id}")
                    else:
                        print(f"INFO: VPC Flow Logs not enabled for {vpc_id}")
                
                except Exception as e:
                    print(f"ERROR: {e}")
            
            return True
        
        except Exception as e:
            print(f"FAIL: {e}")
            return False
    
    def list_resources(self):
        """List existing resources"""
        try:
            print("\nExisting Resources:")
            print("=" * 50)
            
            instances = self.ec2.describe_instances()
            ec2_count = sum(1 for r in instances['Reservations'] for i in r['Instances'])
            print(f"EC2 Instances: {ec2_count}")
            
            buckets = self.s3.list_buckets()
            print(f"S3 Buckets: {len(buckets['Buckets'])}")
            
            vpcs = self.ec2.describe_vpcs()
            print(f"VPCs: {len(vpcs['Vpcs'])}")
            
            return True
        
        except Exception as e:
            print(f"FAIL: {e}")
            return False
    
    def create_test_resources(self):
        """Create test resources"""
        answer = input("\nCreate test resources? (yes/no): ").strip().lower()
        
        if answer != 'yes':
            print("Skipped.")
            return
        
        try:
            print("Creating test resources...")
            
            images = self.ec2.describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                    {'Name': 'state', 'Values': ['available']}
                ]
            )
            
            if images['Images']:
                latest_ami = sorted(images['Images'], 
                                   key=lambda x: x['CreationDate'], 
                                   reverse=True)[0]
                
                response = self.ec2.run_instances(
                    ImageId=latest_ami['ImageId'],
                    MinCount=1,
                    MaxCount=1,
                    InstanceType='t3.micro',
                    TagSpecifications=[{
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': 'CIRA-Test-Instance'},
                            {'Key': 'Environment', 'Value': 'testing'},
                            {'Key': 'Project', 'Value': 'CIRA'}
                        ]
                    }]
                )
                
                instance_id = response['Instances'][0]['InstanceId']
                print(f"OK: Created test instance: {instance_id}")
        
        except Exception as e:
            print(f"FAIL: {e}")
    
    def run_setup(self):
        """Run complete setup"""
        print("=" * 50)
        print("C.I.R.A AWS Environment Setup")
        print("=" * 50)
        
        if not self.verify_credentials():
            print("\nFAIL: Cannot verify credentials. Check .env file.")
            sys.exit(1)
        
        self.setup_cloudtrail()
        self.setup_vpc_flow_logs()
        self.list_resources()
        self.create_test_resources()
        
        print("\n" + "=" * 50)
        print("Setup Complete!")
        print("=" * 50)
        print("\nNext steps:")
        print("1. Run: python aws_cspm_scanner.py")
        print("2. Run: python api.py")
        print("3. Visit: http://localhost:5000/")

if __name__ == "__main__":
    setup = EnvironmentSetup()
    setup.run_setup()