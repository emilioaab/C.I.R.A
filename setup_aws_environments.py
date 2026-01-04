#!/usr/bin/env python3
"""
AWS Environments Builder for C.I.R.A Project
============================================
Creates two separate environments:
1. Production - Simulates a real company with proper security
2. Testing - Intentionally vulnerable for security testing
"""

import boto3
import json
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class EnvironmentBuilder:
    def __init__(self, environment_type):
        """
        Initialize the environment builder
        Args:
            environment_type: 'production' or 'testing'
        """
        self.env_type = environment_type
        self.ec2 = boto3.client('ec2',
            region_name=os.getenv('AWS_REGION'),
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
        self.s3 = boto3.client('s3',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
        self.iam = boto3.client('iam',
            aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
            aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
        )
        
    def create_production_environment(self):
        """Build a secure production environment that simulates a real company"""
        print("🏢 Building Production Environment...")
        print("   This simulates a properly secured company infrastructure")
        
        results = {}
        
        try:
            # 1. Create VPC with proper segmentation
            print("\n📍 Creating VPC...")
            vpc = self.ec2.create_vpc(CidrBlock='10.0.0.0/16')
            vpc_id = vpc['Vpc']['VpcId']
            
            # Add Name tag
            self.ec2.create_tags(
                Resources=[vpc_id],
                Tags=[
                    {'Key': 'Name', 'Value': 'CIRA-Production-VPC'},
                    {'Key': 'Environment', 'Value': 'production'},
                    {'Key': 'Project', 'Value': 'CIRA'}
                ]
            )
            results['vpc_id'] = vpc_id
            print(f"   ✅ VPC created: {vpc_id}")
            
            # 2. Create Internet Gateway
            print("\n🌐 Creating Internet Gateway...")
            igw = self.ec2.create_internet_gateway()
            igw_id = igw['InternetGateway']['InternetGatewayId']
            self.ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            
            # 3. Create Subnets
            print("\n🔧 Creating Subnets...")
            
            # Public subnet
            public_subnet = self.ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock='10.0.1.0/24',
                AvailabilityZone=f"{os.getenv('AWS_REGION')}a"
            )
            public_subnet_id = public_subnet['Subnet']['SubnetId']
            
            self.ec2.create_tags(
                Resources=[public_subnet_id],
                Tags=[{'Key': 'Name', 'Value': 'CIRA-Prod-Public-Subnet'}]
            )
            
            # Private subnet
            private_subnet = self.ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock='10.0.2.0/24',
                AvailabilityZone=f"{os.getenv('AWS_REGION')}a"
            )
            private_subnet_id = private_subnet['Subnet']['SubnetId']
            
            self.ec2.create_tags(
                Resources=[private_subnet_id],
                Tags=[{'Key': 'Name', 'Value': 'CIRA-Prod-Private-Subnet'}]
            )
            
            print(f"   ✅ Public Subnet: {public_subnet_id}")
            print(f"   ✅ Private Subnet: {private_subnet_id}")
            
            # 4. Create Security Groups with proper rules
            print("\n🔒 Creating Security Groups...")
            
            # Web server security group - Only HTTP/HTTPS
            web_sg = self.ec2.create_security_group(
                GroupName='cira-prod-web-sg',
                Description='Production Web Servers - Restricted Access',
                VpcId=vpc_id
            )
            web_sg_id = web_sg['GroupId']
            
            # Allow only HTTP and HTTPS from internet
            self.ec2.authorize_security_group_ingress(
                GroupId=web_sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP from Internet'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from Internet'}]
                    }
                ]
            )
            print(f"   ✅ Web Security Group: {web_sg_id}")
            
            # Database security group - Only from web servers
            db_sg = self.ec2.create_security_group(
                GroupName='cira-prod-db-sg',
                Description='Production Database - Internal Only',
                VpcId=vpc_id
            )
            db_sg_id = db_sg['GroupId']
            
            # Allow only from web security group
            self.ec2.authorize_security_group_ingress(
                GroupId=db_sg_id,
                IpPermissions=[
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 3306,
                        'ToPort': 3306,
                        'UserIdGroupPairs': [{'GroupId': web_sg_id, 'Description': 'MySQL from web servers'}]
                    }
                ]
            )
            print(f"   ✅ Database Security Group: {db_sg_id}")
            
            # 5. Launch EC2 Instances
            print("\n💻 Launching EC2 Instances...")
            
            # Get latest Amazon Linux 2 AMI
            images = self.ec2.describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                    {'Name': 'state', 'Values': ['available']}
                ]
            )
            latest_ami = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
            
            # Determine Free Tier instance type (t3.micro is usually free tier now)
            instance_type = 't3.micro'  # Changed from t2.micro to t3.micro
            
            # Web servers (2 instances for redundancy)
            instances = []
            for i in range(2):
                instance = self.ec2.run_instances(
                    ImageId=latest_ami,
                    MinCount=1,
                    MaxCount=1,
                    InstanceType=instance_type,
                    SecurityGroupIds=[web_sg_id],
                    SubnetId=public_subnet_id,
                    TagSpecifications=[{
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': f'CIRA-Prod-Web-{i+1}'},
                            {'Key': 'Environment', 'Value': 'production'},
                            {'Key': 'Type', 'Value': 'WebServer'}
                        ]
                    }]
                )
                instance_id = instance['Instances'][0]['InstanceId']
                instances.append(instance_id)
                print(f"   ✅ Web Server {i+1}: {instance_id}")
            
            # Database server (in private subnet)
            db_instance = self.ec2.run_instances(
                ImageId=latest_ami,
                MinCount=1,
                MaxCount=1,
                InstanceType=instance_type,  # Using same instance_type variable
                SecurityGroupIds=[db_sg_id],
                SubnetId=private_subnet_id,
                TagSpecifications=[{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'CIRA-Prod-Database'},
                        {'Key': 'Environment', 'Value': 'production'},
                        {'Key': 'Type', 'Value': 'Database'}
                    ]
                }]
            )
            db_instance_id = db_instance['Instances'][0]['InstanceId']
            print(f"   ✅ Database Server: {db_instance_id}")
            
            # 6. Create S3 Bucket with encryption and versioning
            print("\n📦 Creating Secure S3 Bucket...")
            
            bucket_name = f'cira-prod-data-{datetime.now().strftime("%Y%m%d%H%M%S")}'
            self.s3.create_bucket(Bucket=bucket_name)
            
            # Enable encryption
            self.s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                }
            )
            
            # Enable versioning
            self.s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Block all public access
            self.s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            print(f"   ✅ Secure S3 Bucket: {bucket_name}")
            results['bucket'] = bucket_name
            
            print("\n✅ Production environment created successfully!")
            print("   This environment follows security best practices")
            
        except Exception as e:
            print(f"\n❌ Error creating production environment: {e}")
            
        return results
    
    def create_vulnerable_testing_environment(self):
        """Build an intentionally vulnerable environment for testing"""
        print("\n🎯 Building Vulnerable Testing Environment...")
        print("   ⚠️  WARNING: This environment has INTENTIONAL security vulnerabilities!")
        print("   ⚠️  Use for testing ONLY - Never use in production!")
        
        results = {}
        
        try:
            # 1. Create VPC
            print("\n📍 Creating VPC...")
            vpc = self.ec2.create_vpc(CidrBlock='172.16.0.0/16')
            vpc_id = vpc['Vpc']['VpcId']
            
            self.ec2.create_tags(
                Resources=[vpc_id],
                Tags=[
                    {'Key': 'Name', 'Value': 'CIRA-Testing-VPC-VULNERABLE'},
                    {'Key': 'Environment', 'Value': 'testing'},
                    {'Key': 'VULNERABLE', 'Value': 'YES'}
                ]
            )
            results['vpc_id'] = vpc_id
            print(f"   ✅ VPC created: {vpc_id}")
            
            # 2. Create Internet Gateway
            igw = self.ec2.create_internet_gateway()
            igw_id = igw['InternetGateway']['InternetGatewayId']
            self.ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
            
            # 3. Create public subnet
            subnet = self.ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock='172.16.1.0/24',
                AvailabilityZone=f"{os.getenv('AWS_REGION')}a"
            )
            subnet_id = subnet['Subnet']['SubnetId']
            
            self.ec2.create_tags(
                Resources=[subnet_id],
                Tags=[{'Key': 'Name', 'Value': 'CIRA-Test-Vulnerable-Subnet'}]
            )
            
            # 4. VULNERABILITY: Wide-open Security Group
            print("\n⚠️  Creating VULNERABLE Security Group...")
            vulnerable_sg = self.ec2.create_security_group(
                GroupName='cira-test-vulnerable-sg',
                Description='INTENTIONALLY VULNERABLE - All ports open',
                VpcId=vpc_id
            )
            vulnerable_sg_id = vulnerable_sg['GroupId']
            
            # VULNERABILITY: All ports open to the world!
            self.ec2.authorize_security_group_ingress(
                GroupId=vulnerable_sg_id,
                IpPermissions=[{
                    'IpProtocol': '-1',  # All protocols
                    'FromPort': -1,
                    'ToPort': -1,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'VULNERABLE - All traffic allowed'}]
                }]
            )
            print(f"   ⚠️  Vulnerable Security Group: {vulnerable_sg_id}")
            print("      - ALL ports open to 0.0.0.0/0")
            
            # 5. Launch vulnerable instances
            print("\n💻 Launching VULNERABLE Instances...")
            
            # Get AMI
            images = self.ec2.describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                    {'Name': 'state', 'Values': ['available']}
                ]
            )
            latest_ami = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
            
            # Use t3.micro for Free Tier compatibility
            instance_type = 't3.micro'
            
            # VULNERABILITY: Instance with bad configuration
            vulnerable_user_data = '''#!/bin/bash
# VULNERABLE CONFIGURATIONS - DO NOT USE IN PRODUCTION!

# Install services
yum update -y
yum install -y httpd mysql telnet-server

# VULNERABILITY 1: Weak passwords
useradd admin
echo "admin:password123" | chpasswd

# VULNERABILITY 2: Enable root SSH
sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config
echo "root:toor" | chpasswd
systemctl restart sshd

# VULNERABILITY 3: Telnet service (unencrypted)
systemctl start telnet.socket
systemctl enable telnet.socket

# VULNERABILITY 4: MySQL with no root password
systemctl start mysqld
mysql -e "UPDATE mysql.user SET Password='' WHERE User='root';"
mysql -e "FLUSH PRIVILEGES;"

# VULNERABILITY 5: Web server with directory listing
systemctl start httpd
echo "Options +Indexes" > /etc/httpd/conf.d/listing.conf
systemctl restart httpd

# VULNERABILITY 6: Store fake credentials in web root
echo "aws_access_key_id=AKIAFAKEKEY123456789" > /var/www/html/config.txt
echo "aws_secret_access_key=FakeSecretKey1234567890abcdefghijklmnop" >> /var/www/html/config.txt
'''
            
            # Launch vulnerable instances
            vulnerable_instances = []
            for i in range(2):
                instance = self.ec2.run_instances(
                    ImageId=latest_ami,
                    MinCount=1,
                    MaxCount=1,
                    InstanceType=instance_type,  # Changed to use variable
                    SecurityGroupIds=[vulnerable_sg_id],
                    SubnetId=subnet_id,
                    UserData=vulnerable_user_data,
                    TagSpecifications=[{
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'Name', 'Value': f'CIRA-Test-Vulnerable-{i+1}'},
                            {'Key': 'Environment', 'Value': 'testing'},
                            {'Key': 'VULNERABLE', 'Value': 'YES'},
                            {'Key': 'Vulnerabilities', 'Value': 'OpenPorts,WeakPasswords,RootSSH,Telnet'}
                        ]
                    }]
                )
                instance_id = instance['Instances'][0]['InstanceId']
                vulnerable_instances.append(instance_id)
                print(f"   ⚠️  Vulnerable Instance {i+1}: {instance_id}")
            
            print("\n   Vulnerabilities in these instances:")
            print("   • All ports open (0-65535)")
            print("   • Weak passwords (admin:password123, root:toor)")
            print("   • Root SSH enabled")
            print("   • Telnet service running (unencrypted)")
            print("   • MySQL with no root password")
            print("   • Web server with directory listing")
            print("   • Fake AWS credentials exposed")
            
            # 6. VULNERABILITY: Public S3 Bucket
            print("\n📦 Creating VULNERABLE S3 Bucket...")
            
            vulnerable_bucket = f'cira-test-public-{datetime.now().strftime("%Y%m%d%H%M%S")}'
            self.s3.create_bucket(Bucket=vulnerable_bucket)
            
            # VULNERABILITY: Make bucket public
            bucket_policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "PublicReadGetObject",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{vulnerable_bucket}/*",
                        f"arn:aws:s3:::{vulnerable_bucket}"
                    ]
                }]
            }
            
            self.s3.put_bucket_policy(
                Bucket=vulnerable_bucket,
                Policy=json.dumps(bucket_policy)
            )
            
            # Upload fake sensitive data
            self.s3.put_object(
                Bucket=vulnerable_bucket,
                Key='passwords.txt',
                Body='admin:password123\nroot:toor\nuser:12345',
                ContentType='text/plain'
            )
            
            self.s3.put_object(
                Bucket=vulnerable_bucket,
                Key='credit_cards.csv',
                Body='name,card_number,cvv\nJohn Doe,4111111111111111,123\nJane Smith,5500000000000004,456',
                ContentType='text/csv'
            )
            
            print(f"   ⚠️  Public S3 Bucket: {vulnerable_bucket}")
            print("      - Public read access enabled")
            print("      - Contains fake sensitive data")
            results['bucket'] = vulnerable_bucket
            
            # 7. VULNERABILITY: IAM User with excessive permissions
            print("\n👤 Creating VULNERABLE IAM User...")
            
            try:
                vulnerable_user = self.iam.create_user(
                    UserName='cira-test-vulnerable-user',
                    Tags=[
                        {'Key': 'Environment', 'Value': 'testing'},
                        {'Key': 'VULNERABLE', 'Value': 'YES'}
                    ]
                )
                
                # VULNERABILITY: Attach AdministratorAccess policy
                self.iam.attach_user_policy(
                    UserName='cira-test-vulnerable-user',
                    PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
                )
                
                # Create access key
                access_key = self.iam.create_access_key(UserName='cira-test-vulnerable-user')
                
                print(f"   ⚠️  Vulnerable IAM User: cira-test-vulnerable-user")
                print("      - Has AdministratorAccess policy")
                print("      - Access key created (store securely for testing)")
                
                # Store the access key info (for testing only!)
                results['vulnerable_access_key'] = access_key['AccessKey']['AccessKeyId']
                
            except self.iam.exceptions.EntityAlreadyExistsException:
                print("   ⚠️  IAM User already exists")
            
            print("\n✅ Vulnerable testing environment created!")
            print("\n⚠️  CRITICAL REMINDERS:")
            print("   • This environment is INTENTIONALLY INSECURE")
            print("   • Use ONLY for testing C.I.R.A detection capabilities")
            print("   • DELETE this environment when testing is complete")
            print("   • NEVER use these configurations in production")
            
        except Exception as e:
            print(f"\n❌ Error creating testing environment: {e}")
            
        return results

def cleanup_environment(env_type):
    """Helper function to clean up resources"""
    print(f"\n🧹 Cleaning up {env_type} environment...")
    
    ec2 = boto3.client('ec2',
        region_name=os.getenv('AWS_REGION'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
    )
    
    # Find and terminate instances
    instances = ec2.describe_instances(
        Filters=[
            {'Name': 'tag:Environment', 'Values': [env_type]},
            {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
        ]
    )
    
    instance_ids = []
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_ids.append(instance['InstanceId'])
    
    if instance_ids:
        ec2.terminate_instances(InstanceIds=instance_ids)
        print(f"   ✅ Terminated {len(instance_ids)} instances")
    
    print("   Cleanup complete!")

# Main execution
if __name__ == "__main__":
    print("=" * 60)
    print("        C.I.R.A - AWS Environment Setup")
    print("=" * 60)
    print("\nThis script will create two AWS environments:")
    print("1. Production - Secure, best-practices environment")
    print("2. Testing - Intentionally vulnerable for security testing")
    print("\n⚠️  Make sure you understand AWS pricing before proceeding!")
    print("   Most resources use t3.micro (Free Tier eligible)")
    
    choice = input("\nWhat would you like to do?\n1. Create Production Environment\n2. Create Testing Environment\n3. Create Both\n4. Cleanup Existing\n5. Exit\n\nChoice (1-5): ")
    
    if choice == '1':
        builder = EnvironmentBuilder('production')
        builder.create_production_environment()
        
    elif choice == '2':
        confirm = input("\n⚠️  This will create VULNERABLE resources. Continue? (yes/no): ")
        if confirm.lower() == 'yes':
            builder = EnvironmentBuilder('testing')
            builder.create_vulnerable_testing_environment()
        else:
            print("Cancelled.")
            
    elif choice == '3':
        builder = EnvironmentBuilder('production')
        prod_results = builder.create_production_environment()
        
        confirm = input("\n⚠️  Now create VULNERABLE testing environment? (yes/no): ")
        if confirm.lower() == 'yes':
            builder = EnvironmentBuilder('testing')
            test_results = builder.create_vulnerable_testing_environment()
        
    elif choice == '4':
        cleanup_type = input("\nCleanup which environment? (production/testing/both): ")
        if cleanup_type == 'both':
            cleanup_environment('production')
            cleanup_environment('testing')
        elif cleanup_type in ['production', 'testing']:
            cleanup_environment(cleanup_type)
        
    else:
        print("Exiting...")
    
    print("\n✅ Script complete!")
    print("\nNext steps:")
    print("1. Check AWS Console to see your resources")
    print("2. Run C.I.R.A to scan these environments")
    print("3. Compare security findings between environments")
    print("\nRemember to DELETE resources when done to avoid charges!")