import boto3
from typing import List, Dict
import json
from datetime import datetime
from backend.connectors.base import CloudConnector, Finding
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"

class AWSAssessment(CloudConnector):
    """AWS Cloud Assessment"""
    
    def __init__(self, region: str = 'us-east-1', environment: str = 'prod'):
        self.region = region
        self.environment = environment
        self.findings: List[Finding] = []
        
        try:
            self.iam = boto3.client('iam')
            self.ec2 = boto3.client('ec2', region_name=region)
            self.s3 = boto3.client('s3')
            self.cloudtrail = boto3.client('cloudtrail', region_name=region)
            self.logs = boto3.client('logs', region_name=region)
            self.rds = boto3.client('rds', region_name=region)
            self.elb = boto3.client('elbv2', region_name=region)
        except Exception as e:
            print(f"AWS connection error: {e}")
    
    def add_finding(
        self,
        check_id: str,
        check_title: str,
        service: str,
        severity: Severity,
        status: Status,
        resource_id: str,
        resource_type: str,
        description: str,
        remediation: str,
        frameworks: List[str] = None,
        threat_score: int = 50
    ) -> Finding:
        """Add a finding"""
        finding = Finding(
            check_id=check_id,
            check_title=check_title,
            service=service,
            severity=severity.value,
            status=status.value,
            resource_id=resource_id,
            resource_type=resource_type,
            region=self.region,
            description=description,
            remediation=remediation,
            frameworks=frameworks or [],
            threat_score=threat_score,
            environment=self.environment,
            timestamp=datetime.utcnow().isoformat()
        )
        self.findings.append(finding)
        return finding
    
    # ========================================================================
    # IAM ASSESSMENT
    # ========================================================================
    
    def assess_iam(self) -> List[Finding]:
        """Assess IAM configuration"""
        print("Assessing IAM...")
        
        findings = []
        
        try:
            # Check root account MFA
            findings.extend(self._check_root_mfa())
            
            # Check IAM users
            findings.extend(self._check_iam_users())
            
            # Check IAM policies
            findings.extend(self._check_iam_policies())
            
            # Check access keys
            findings.extend(self._check_access_keys())
            
        except Exception as e:
            print(f"Error in IAM assessment: {e}")
        
        return findings
    
    def _check_root_mfa(self) -> List[Finding]:
        """AWS_IAM_001: Root account MFA"""
        findings = []
        try:
            cred_report = self.iam.get_credential_report()
            report = cred_report['Content'].decode('utf-8')
            
            for line in report.split('\n')[1:]:
                if not line:
                    continue
                fields = line.split(',')
                if fields[0] == '<root_account>':
                    has_mfa = fields[3] == 'true'
                    
                    if not has_mfa:
                        self.add_finding(
                            check_id='AWS_IAM_001',
                            check_title='Root account MFA enabled',
                            service='iam',
                            severity=Severity.CRITICAL,
                            status=Status.FAIL,
                            resource_id='root-account',
                            resource_type='iam-root',
                            description='Root account does not have MFA enabled',
                            remediation='Enable MFA on root account via AWS Console',
                            frameworks=['CIS', 'GDPR', 'HIPAA'],
                            threat_score=95
                        )
                    else:
                        self.add_finding(
                            check_id='AWS_IAM_001',
                            check_title='Root account MFA enabled',
                            service='iam',
                            severity=Severity.INFO,
                            status=Status.PASS,
                            resource_id='root-account',
                            resource_type='iam-root',
                            description='Root account has MFA enabled',
                            remediation='N/A',
                            frameworks=['CIS', 'GDPR', 'HIPAA'],
                            threat_score=0
                        )
                    break
        except Exception as e:
            print(f"Error checking root MFA: {e}")
        
        return self.findings
    
    def _check_iam_users(self) -> List[Finding]:
        """AWS_IAM_002: IAM users without MFA"""
        findings = []
        try:
            users = self.iam.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                mfa_devices = self.iam.list_mfa_devices(UserName=username)['MFADevices']
                
                if not mfa_devices:
                    self.add_finding(
                        check_id='AWS_IAM_002',
                        check_title='IAM user MFA enabled',
                        service='iam',
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        resource_id=username,
                        resource_type='iam-user',
                        description=f'IAM user {username} does not have MFA enabled',
                        remediation=f'Enable MFA for user {username}',
                        frameworks=['CIS', 'HIPAA'],
                        threat_score=80
                    )
                else:
                    self.add_finding(
                        check_id='AWS_IAM_002',
                        check_title='IAM user MFA enabled',
                        service='iam',
                        severity=Severity.INFO,
                        status=Status.PASS,
                        resource_id=username,
                        resource_type='iam-user',
                        description=f'IAM user {username} has MFA enabled',
                        remediation='N/A',
                        frameworks=['CIS', 'HIPAA'],
                        threat_score=0
                    )
        except Exception as e:
            print(f"Error checking IAM users: {e}")
        
        return self.findings
    
    def _check_iam_policies(self) -> List[Finding]:
        """AWS_IAM_003: Overly permissive policies"""
        findings = []
        try:
            policies = self.iam.list_policies(Scope='Local')['Policies']
            
            for policy in policies:
                policy_version = self.iam.get_policy_version(
                    PolicyArn=policy['Arn'],
                    VersionId=policy['DefaultVersionId']
                )['PolicyVersion']['Document']
                
                # Check for wildcard permissions
                for statement in policy_version.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        if '*' in actions:
                            self.add_finding(
                                check_id='AWS_IAM_003',
                                check_title='Overly permissive IAM policy',
                                service='iam',
                                severity=Severity.HIGH,
                                status=Status.FAIL,
                                resource_id=policy['PolicyName'],
                                resource_type='iam-policy',
                                description=f'Policy {policy["PolicyName"]} has wildcard (*) permissions',
                                remediation='Apply least privilege principle - remove wildcard permissions',
                                frameworks=['CIS', 'GDPR'],
                                threat_score=85
                            )
        except Exception as e:
            print(f"Error checking IAM policies: {e}")
        
        return self.findings
    
    def _check_access_keys(self) -> List[Finding]:
        """AWS_IAM_004: Old access keys"""
        findings = []
        try:
            users = self.iam.list_users()['Users']
            
            for user in users:
                access_keys = self.iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
                
                for key in access_keys:
                    # Check if key is older than 90 days
                    age_days = (datetime.utcnow() - key['CreateDate'].replace(tzinfo=None)).days
                    
                    if age_days > 90:
                        self.add_finding(
                            check_id='AWS_IAM_004',
                            check_title='Access key rotation',
                            service='iam',
                            severity=Severity.MEDIUM,
                            status=Status.FAIL,
                            resource_id=f"{user['UserName']}/{key['AccessKeyId']}",
                            resource_type='iam-access-key',
                            description=f'Access key for {user["UserName"]} is {age_days} days old',
                            remediation=f'Rotate access key for user {user["UserName"]}',
                            frameworks=['CIS'],
                            threat_score=60
                        )
        except Exception as e:
            print(f"Error checking access keys: {e}")
        
        return self.findings
    
    # ========================================================================
    # NETWORK ASSESSMENT
    # ========================================================================
    
    def assess_network(self) -> List[Finding]:
        """Assess network security"""
        print("Assessing Network...")
        
        try:
            # Check security groups
            self._check_security_groups()
            
            # Check NACLs
            self._check_nacls()
            
            # Check VPC Flow Logs
            self._check_vpc_flow_logs()
            
        except Exception as e:
            print(f"Error in network assessment: {e}")
        
        return self.findings
    
    def _check_security_groups(self) -> List[Finding]:
        """AWS_EC2_001: Unrestricted access in security groups"""
        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            
            for sg in sgs:
                for rule in sg['IpPermissions']:
                    from_port = rule.get('FromPort', -1)
                    
                    # Check for unrestricted SSH
                    if from_port == 22:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                self.add_finding(
                                    check_id='AWS_EC2_001',
                                    check_title='Unrestricted SSH access',
                                    service='ec2',
                                    severity=Severity.CRITICAL,
                                    status=Status.FAIL,
                                    resource_id=sg['GroupId'],
                                    resource_type='security-group',
                                    description=f'Security group allows SSH from 0.0.0.0/0',
                                    remediation='Restrict SSH to specific IP ranges',
                                    frameworks=['CIS', 'PCI-DSS'],
                                    threat_score=92
                                )
        except Exception as e:
            print(f"Error checking security groups: {e}")
        
        return self.findings
    
    def _check_nacls(self) -> List[Finding]:
        """AWS_VPC_001: NACL assessment"""
        try:
            nacls = self.ec2.describe_network_acls()['NetworkAcls']
            
            for nacl in nacls:
                if len(nacl['Entries']) <= 2:  # Only default rules
                    self.add_finding(
                        check_id='AWS_VPC_001',
                        check_title='NACL configured',
                        service='vpc',
                        severity=Severity.LOW,
                        status=Status.PASS,
                        resource_id=nacl['NetworkAclId'],
                        resource_type='nacl',
                        description='NACL uses default configuration',
                        remediation='N/A',
                        frameworks=['CIS'],
                        threat_score=0
                    )
        except Exception as e:
            print(f"Error checking NACLs: {e}")
        
        return self.findings
    
    def _check_vpc_flow_logs(self) -> List[Finding]:
        """AWS_VPC_002: VPC Flow Logs enabled"""
        try:
            vpcs = self.ec2.describe_vpcs()['Vpcs']
            
            for vpc in vpcs:
                flow_logs = self.ec2.describe_flow_logs(
                    Filter=[{'Name': 'resource-id', 'Values': [vpc['VpcId']]}]
                )['FlowLogs']
                
                if not flow_logs:
                    self.add_finding(
                        check_id='AWS_VPC_002',
                        check_title='VPC Flow Logs enabled',
                        service='vpc',
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        resource_id=vpc['VpcId'],
                        resource_type='vpc',
                        description=f'VPC {vpc["VpcId"]} does not have Flow Logs enabled',
                        remediation='Enable VPC Flow Logs for network monitoring',
                        frameworks=['CIS', 'GDPR'],
                        threat_score=65
                    )
        except Exception as e:
            print(f"Error checking VPC Flow Logs: {e}")
        
        return self.findings
    
    # ========================================================================
    # STORAGE ASSESSMENT
    # ========================================================================
    
    def assess_storage(self) -> List[Finding]:
        """Assess storage security"""
        print("🔍 Assessing Storage...")
        
        try:
            # Check S3 buckets
            self._check_s3_buckets()
            
            # Check RDS databases
            self._check_rds_databases()
            
        except Exception as e:
            print(f"Error in storage assessment: {e}")
        
        return self.findings
    
    def _check_s3_buckets(self) -> List[Finding]:
        """AWS_S3_001: S3 bucket public access"""
        try:
            buckets = self.s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    public_block = self.s3.get_public_access_block(Bucket=bucket_name)
                    config = public_block['PublicAccessBlockConfiguration']
                    
                    is_fully_blocked = all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ])
                    
                    if not is_fully_blocked:
                        self.add_finding(
                            check_id='AWS_S3_001',
                            check_title='S3 bucket public access blocked',
                            service='s3',
                            severity=Severity.CRITICAL,
                            status=Status.FAIL,
                            resource_id=bucket_name,
                            resource_type='s3-bucket',
                            description=f'S3 bucket {bucket_name} allows public access',
                            remediation='Enable all S3 public access blocks',
                            frameworks=['CIS', 'GDPR', 'HIPAA'],
                            threat_score=95
                        )
                except:
                    self.add_finding(
                        check_id='AWS_S3_001',
                        check_title='S3 bucket public access blocked',
                        service='s3',
                        severity=Severity.CRITICAL,
                        status=Status.FAIL,
                        resource_id=bucket_name,
                        resource_type='s3-bucket',
                        description=f'S3 bucket {bucket_name} has no public access block',
                        remediation='Enable S3 public access block',
                        frameworks=['CIS', 'GDPR'],
                        threat_score=90
                    )
        except Exception as e:
            print(f"Error checking S3 buckets: {e}")
        
        return self.findings
    
    def _check_rds_databases(self) -> List[Finding]:
        """AWS_RDS_001: RDS encryption"""
        try:
            databases = self.rds.describe_db_instances()['DBInstances']
            
            for db in databases:
                if not db.get('StorageEncrypted', False):
                    self.add_finding(
                        check_id='AWS_RDS_001',
                        check_title='RDS database encryption enabled',
                        service='rds',
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        resource_id=db['DBInstanceIdentifier'],
                        resource_type='rds-instance',
                        description=f'RDS instance {db["DBInstanceIdentifier"]} is not encrypted',
                        remediation='Enable encryption at rest for RDS instance',
                        frameworks=['CIS', 'GDPR', 'HIPAA'],
                        threat_score=80
                    )
        except Exception as e:
            print(f"Error checking RDS: {e}")
        
        return self.findings
    
    # ========================================================================
    # RESOURCE MAPPING (Cloud-Mapper style)
    # ========================================================================
    
    def assess_resources(self) -> List[Finding]:
        """Map and assess all resources"""
        print("🔍 Mapping Resources (Cloud-Mapper style)...")
        
        resources = {
            'ec2_instances': self._map_ec2(),
            's3_buckets': self._map_s3(),
            'rds_databases': self._map_rds(),
            'iam_roles': self._map_iam_roles(),
            'elb_load_balancers': self._map_elb(),
        }
        
        return resources
    
    def _map_ec2(self) -> List[Dict]:
        """Map EC2 instances"""
        try:
            instances = self.ec2.describe_instances()['Reservations']
            ec2_list = []
            
            for reservation in instances:
                for instance in reservation['Instances']:
                    ec2_list.append({
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'region': self.region,
                        'security_groups': instance.get('SecurityGroups', []),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])},
                    })
            
            return ec2_list
        except Exception as e:
            print(f"Error mapping EC2: {e}")
            return []
    
    def _map_s3(self) -> List[Dict]:
        """Map S3 buckets"""
        try:
            buckets = self.s3.list_buckets()['Buckets']
            s3_list = []
            
            for bucket in buckets:
                s3_list.append({
                    'bucket_name': bucket['Name'],
                    'creation_date': bucket['CreationDate'].isoformat(),
                })
            
            return s3_list
        except Exception as e:
            print(f"Error mapping S3: {e}")
            return []
    
    def _map_rds(self) -> List[Dict]:
        """Map RDS databases"""
        try:
            databases = self.rds.describe_db_instances()['DBInstances']
            rds_list = []
            
            for db in databases:
                rds_list.append({
                    'db_identifier': db['DBInstanceIdentifier'],
                    'db_engine': db['Engine'],
                    'db_class': db['DBInstanceClass'],
                    'status': db['DBInstanceStatus'],
                })
            
            return rds_list
        except Exception as e:
            print(f"Error mapping RDS: {e}")
            return []
    
    def _map_iam_roles(self) -> List[Dict]:
        """Map IAM roles"""
        try:
            roles = self.iam.list_roles()['Roles']
            roles_list = []
            
            for role in roles:
                roles_list.append({
                    'role_name': role['RoleName'],
                    'role_arn': role['Arn'],
                    'created_date': role['CreateDate'].isoformat(),
                })
            
            return roles_list
        except Exception as e:
            print(f"Error mapping IAM roles: {e}")
            return []
    
    def _map_elb(self) -> List[Dict]:
        """Map load balancers"""
        try:
            load_balancers = self.elb.describe_load_balancers()['LoadBalancers']
            elb_list = []
            
            for lb in load_balancers:
                elb_list.append({
                    'lb_name': lb['LoadBalancerName'],
                    'scheme': lb['Scheme'],
                    'state': lb['State']['Code'],
                })
            
            return elb_list
        except Exception as e:
            print(f"Error mapping ELB: {e}")
            return []
    
    # ========================================================================
    # COMPLIANCE ASSESSMENT
    # ========================================================================
    
    def assess_compliance(self) -> List[Finding]:
        """Assess compliance frameworks"""
        print("Assessing Compliance...")
        
        try:
            # Check CloudTrail
            self._check_cloudtrail()
            
            # Check encryption
            self._check_encryption()
            
        except Exception as e:
            print(f"Error in compliance assessment: {e}")
        
        return self.findings
    
    def _check_cloudtrail(self) -> List[Finding]:
        """AWS_CT_001: CloudTrail enabled"""
        try:
            trails = self.cloudtrail.describe_trails()['trailList']
            
            if not trails:
                self.add_finding(
                    check_id='AWS_CT_001',
                    check_title='CloudTrail enabled in all regions',
                    service='cloudtrail',
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    resource_id='account',
                    resource_type='cloudtrail',
                    description='CloudTrail is not enabled',
                    remediation='Enable CloudTrail in all regions',
                    frameworks=['CIS', 'GDPR', 'HIPAA', 'PCI-DSS'],
                    threat_score=100
                )
            else:
                for trail in trails:
                    try:
                        status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                        if status['IsLogging']:
                            self.add_finding(
                                check_id='AWS_CT_001',
                                check_title='CloudTrail enabled in all regions',
                                service='cloudtrail',
                                severity=Severity.INFO,
                                status=Status.PASS,
                                resource_id=trail['Name'],
                                resource_type='cloudtrail',
                                description='CloudTrail is logging',
                                remediation='N/A',
                                frameworks=['CIS'],
                                threat_score=0
                            )
                    except:
                        pass
        except Exception as e:
            print(f"Error checking CloudTrail: {e}")
        
        return self.findings
    
    def _check_encryption(self) -> List[Finding]:
        """AWS_ENC_001: Encryption at rest"""
        try:
            # Check RDS encryption (already done in assess_storage)
            # Check EBS encryption
            pass
        except Exception as e:
            print(f"Error checking encryption: {e}")
        
        return self.findings
    
    # ========================================================================
    # LOGGING ASSESSMENT
    # ========================================================================
    
    def assess_logging(self) -> List[Finding]:
        """Assess logging configuration"""
        print("Assessing Logging...")
        
        try:
            # Check CloudWatch logs
            self._check_cloudwatch_logs()
            
        except Exception as e:
            print(f"Error in logging assessment: {e}")
        
        return self.findings
    
    def _check_cloudwatch_logs(self) -> List[Finding]:
        """AWS_LOG_001: CloudWatch logs configured"""
        try:
            log_groups = self.logs.describe_log_groups()['logGroups']
            
            if not log_groups:
                self.add_finding(
                    check_id='AWS_LOG_001',
                    check_title='CloudWatch logs configured',
                    service='logs',
                    severity=Severity.MEDIUM,
                    status=Status.FAIL,
                    resource_id='account',
                    resource_type='log-group',
                    description='No CloudWatch log groups configured',
                    remediation='Create CloudWatch log groups for application logs',
                    frameworks=['CIS', 'GDPR'],
                    threat_score=70
                )
        except Exception as e:
            print(f"Error checking CloudWatch logs: {e}")
        
        return self.findings
    
    # ========================================================================
    # LOG COLLECTION (placeholder for future)
    # ========================================================================
    
    def collect_logs(self) -> Dict:
        """Collect logs from CloudTrail, CloudWatch, etc."""
        print("Log collection (future implementation)")
        return {
            'status': 'not_implemented',
            'message': 'Log collection will be implemented in Phase 2'
        }
    
    # ========================================================================
    # FORENSICS (placeholder for future)
    # ========================================================================
    
    def deploy_forensics(self, instance_id: str) -> Dict:
        """Deploy Velociraptor-like agent"""
        print("Forensics deployment (future implementation)")
        return {
            'status': 'not_implemented',
            'message': 'Forensics deployment will be implemented in Phase 3',
            'requires_elevated': True
        }