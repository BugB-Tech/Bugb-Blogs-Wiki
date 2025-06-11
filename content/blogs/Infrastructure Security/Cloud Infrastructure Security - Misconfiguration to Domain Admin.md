---
title: "Cloud Infrastructure Security: From Misconfiguration to Domain Admin"
slug: "cloud-infrastructure-security-misconfiguration-domain-admin"
date: "2025-06-12"
author: "BugB Security Team"
authorTitle: "Security Researchers"
excerpt: "Comprehensive guide to identifying and exploiting cloud infrastructure misconfigurations across AWS, Azure, and GCP, demonstrating complete compromise through privilege escalation chains."
category: "infrastructure-security"
---

# Cloud Infrastructure Security: From Misconfiguration to Domain Admin

Cloud infrastructure has become the backbone of modern digital transformation, but its complexity and rapid deployment cycles have created unprecedented security challenges. A single misconfigured IAM policy, an overly permissive storage bucket, or an exposed API endpoint can provide attackers with the initial foothold needed to compromise entire cloud environments.

This comprehensive analysis explores systematic approaches to cloud security assessment, demonstrating how minor misconfigurations can be chained together to achieve complete infrastructure compromise across AWS, Azure, and Google Cloud Platform.

## Cloud Security Landscape Overview

### The Multi-Cloud Security Challenge

Modern organizations typically operate across multiple cloud providers, each with unique security models and potential attack vectors:

| Cloud Provider | Market Share | Primary Attack Vectors | Common Misconfigurations |
|----------------|--------------|------------------------|-------------------------|
| **AWS** | 32% | IAM privilege escalation, S3 bucket exposure, Lambda injection | Overpermissive IAM policies, public S3 buckets, security group misconfigurations |
| **Microsoft Azure** | 23% | Azure AD privilege escalation, storage account exposure, function app vulnerabilities | Weak Azure AD configurations, public storage containers, network security group gaps |
| **Google Cloud** | 10% | IAM policy exploitation, Cloud Storage exposure, Cloud Function injection | Broad IAM bindings, public GCS buckets, firewall rule misconfigurations |
| **Multi-Cloud** | 35% | Cross-cloud privilege escalation, federated identity abuse, shared resource exposure | Inconsistent security policies, identity federation vulnerabilities |

### Cloud Attack Kill Chain

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloud Attack Kill Chain                  │
├─────────────────────────────────────────────────────────────┤
│ 1. Reconnaissance    │ → Cloud service enumeration          │
│                      │   Subdomain discovery                │
│                      │   Public resource identification     │
├─────────────────────────────────────────────────────────────┤
│ 2. Initial Access    │ → Credential exposure                │
│                      │   Public storage access              │
│                      │   API endpoint exploitation          │
├─────────────────────────────────────────────────────────────┤
│ 3. Execution         │ → Serverless function abuse          │
│                      │   Container runtime exploitation     │
│                      │   Virtual machine compromise         │
├─────────────────────────────────────────────────────────────┤
│ 4. Persistence       │ → IAM policy modification            │
│                      │   Service principal creation         │
│                      │   Backdoor deployment                │
├─────────────────────────────────────────────────────────────┤
│ 5. Privilege Escalation │ → IAM role assumption            │
│                         │   Policy attachment abuse        │
│                         │   Cross-service exploitation     │
├─────────────────────────────────────────────────────────────┤
│ 6. Defense Evasion   │ → Logging manipulation              │
│                      │   Identity masquerading             │
│                      │   Resource tagging abuse            │
├─────────────────────────────────────────────────────────────┤
│ 7. Discovery         │ → Resource enumeration              │
│                      │   Network topology mapping          │
│                      │   Data classification               │
├─────────────────────────────────────────────────────────────┤
│ 8. Lateral Movement  │ → Cross-service access              │
│                      │   Network pivoting                  │
│                      │   Identity chaining                 │
├─────────────────────────────────────────────────────────────┤
│ 9. Collection        │ → Data exfiltration                 │
│                      │   Credential harvesting             │
│                      │   Configuration extraction          │
├─────────────────────────────────────────────────────────────┤
│ 10. Impact           │ → Resource destruction              │
│                      │   Service disruption                │
│                      │   Ransom deployment                 │
└─────────────────────────────────────────────────────────────┘
```

---

## AWS Security Assessment Framework

### AWS Service Enumeration and Discovery

#### Automated AWS Reconnaissance

```python
#!/usr/bin/env python3
"""
AWS Security Assessment Framework
Comprehensive AWS environment security evaluation
"""

import boto3
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from botocore.exceptions import ClientError, NoCredentialsError

class AWSSecurityAssessor:
    def __init__(self, profile_name=None, region='us-east-1'):
        try:
            if profile_name:
                self.session = boto3.Session(profile_name=profile_name)
            else:
                self.session = boto3.Session()
            
            self.region = region
            self.findings = []
            self.services = {}
            
            # Initialize service clients
            self._initialize_clients()
            
        except NoCredentialsError:
            print("[!] No AWS credentials configured")
            self.session = None
    
    def _initialize_clients(self):
        """Initialize AWS service clients"""
        service_list = [
            'iam', 'ec2', 's3', 'lambda', 'rds', 'ecs', 'eks',
            'cloudformation', 'cloudtrail', 'config', 'guardduty',
            'securityhub', 'organizations', 'sts', 'kms'
        ]
        
        for service in service_list:
            try:
                self.services[service] = self.session.client(service, region_name=self.region)
            except Exception as e:
                print(f"[!] Failed to initialize {service} client: {e}")
    
    def enumerate_aws_environment(self):
        """Comprehensive AWS environment enumeration"""
        print("[*] Starting AWS environment enumeration...")
        
        enumeration_results = {
            "account_info": self.get_account_information(),
            "iam_analysis": self.analyze_iam_configuration(),
            "ec2_analysis": self.analyze_ec2_security(),
            "s3_analysis": self.analyze_s3_security(),
            "lambda_analysis": self.analyze_lambda_security(),
            "network_analysis": self.analyze_network_security(),
            "logging_analysis": self.analyze_logging_configuration()
        }
        
        return enumeration_results
    
    def get_account_information(self):
        """Get basic AWS account information"""
        try:
            sts = self.services['sts']
            identity = sts.get_caller_identity()
            
            # Get account aliases
            iam = self.services['iam']
            try:
                aliases = iam.list_account_aliases()['AccountAliases']
            except:
                aliases = []
            
            # Get organizations information
            try:
                org = self.session.client('organizations')
                org_info = org.describe_organization()['Organization']
            except:
                org_info = None
            
            account_info = {
                "account_id": identity['Account'],
                "user_arn": identity['Arn'],
                "user_id": identity['UserId'],
                "account_aliases": aliases,
                "organization": org_info
            }
            
            return account_info
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_iam_configuration(self):
        """Comprehensive IAM security analysis"""
        iam_findings = []
        
        try:
            iam = self.services['iam']
            
            # Analyze users
            users = iam.list_users()['Users']
            for user in users:
                username = user['UserName']
                
                # Check for console access
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    
                    # Check password policy compliance
                    try:
                        pwd_policy = iam.get_account_password_policy()['PasswordPolicy']
                        if not pwd_policy.get('RequireSymbols', False):
                            iam_findings.append({
                                "type": "WEAK_PASSWORD_POLICY",
                                "severity": "MEDIUM",
                                "resource": "Account Password Policy",
                                "description": "Password policy doesn't require symbols"
                            })
                    except:
                        iam_findings.append({
                            "type": "NO_PASSWORD_POLICY",
                            "severity": "HIGH",
                            "resource": "Account Password Policy",
                            "description": "No account password policy configured"
                        })
                        
                except ClientError:
                    pass  # User doesn't have console access
                
                # Check for access keys
                access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in access_keys:
                    key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    if key_age > 90:
                        iam_findings.append({
                            "type": "OLD_ACCESS_KEY",
                            "severity": "MEDIUM",
                            "resource": f"User: {username}",
                            "description": f"Access key is {key_age} days old"
                        })
                
                # Check for dangerous inline policies
                inline_policies = iam.list_user_policies(UserName=username)['PolicyNames']
                for policy_name in inline_policies:
                    policy_doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                    if self._check_dangerous_policy(policy_doc['PolicyDocument']):
                        iam_findings.append({
                            "type": "DANGEROUS_INLINE_POLICY",
                            "severity": "HIGH",
                            "resource": f"User: {username}, Policy: {policy_name}",
                            "description": "User has dangerous inline policy permissions"
                        })
            
            # Analyze roles
            roles = iam.list_roles()['Roles']
            for role in roles:
                role_name = role['RoleName']
                
                # Check trust policy
                trust_policy = role['AssumeRolePolicyDocument']
                if self._check_overpermissive_trust_policy(trust_policy):
                    iam_findings.append({
                        "type": "OVERPERMISSIVE_TRUST_POLICY",
                        "severity": "HIGH",
                        "resource": f"Role: {role_name}",
                        "description": "Role has overpermissive trust policy"
                    })
                
                # Check attached policies
                attached_policies = iam.list_attached_role_policies(RoleName=role_name)
                for policy in attached_policies['AttachedPolicies']:
                    if 'FullAccess' in policy['PolicyName']:
                        iam_findings.append({
                            "type": "FULL_ACCESS_POLICY",
                            "severity": "HIGH",
                            "resource": f"Role: {role_name}",
                            "policy": policy['PolicyName'],
                            "description": "Role has AWS managed FullAccess policy"
                        })
            
            # Check for unused credentials
            credential_report = self._generate_credential_report()
            for user_report in credential_report:
                if user_report.get('password_last_used') == 'N/A' and user_report.get('access_key_1_last_used_date'):
                    last_used = user_report['access_key_1_last_used_date']
                    if last_used and (datetime.now() - datetime.strptime(last_used, '%Y-%m-%dT%H:%M:%S+00:00')).days > 90:
                        iam_findings.append({
                            "type": "UNUSED_CREDENTIALS",
                            "severity": "MEDIUM",
                            "resource": f"User: {user_report['user']}",
                            "description": "User has unused credentials for over 90 days"
                        })
            
            return iam_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def _check_dangerous_policy(self, policy_document):
        """Check if policy contains dangerous permissions"""
        dangerous_patterns = [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "iam:*"},
            {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
        ]
        
        statements = policy_document.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            for pattern in dangerous_patterns:
                if all(statement.get(k) == v for k, v in pattern.items()):
                    return True
        
        return False
    
    def _check_overpermissive_trust_policy(self, trust_policy):
        """Check for overpermissive trust relationships"""
        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            principal = statement.get('Principal', {})
            
            # Check for wildcard principals
            if principal == "*" or principal.get('AWS') == "*":
                return True
            
            # Check for broad service principals
            if isinstance(principal.get('Service'), list):
                if len(principal['Service']) > 5:  # Arbitrary threshold
                    return True
        
        return False
    
    def analyze_s3_security(self):
        """Analyze S3 bucket security configurations"""
        s3_findings = []
        
        try:
            s3 = self.services['s3']
            
            # List all buckets
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check bucket ACL
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            s3_findings.append({
                                "type": "PUBLIC_BUCKET_ACL",
                                "severity": "CRITICAL",
                                "resource": f"S3 Bucket: {bucket_name}",
                                "description": "Bucket has public read/write ACL"
                            })
                except ClientError:
                    pass
                
                # Check bucket policy
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy['Policy'])
                    
                    if self._check_public_bucket_policy(policy_doc):
                        s3_findings.append({
                            "type": "PUBLIC_BUCKET_POLICY",
                            "severity": "CRITICAL",
                            "resource": f"S3 Bucket: {bucket_name}",
                            "description": "Bucket has public access policy"
                        })
                except ClientError:
                    pass
                
                # Check public access block
                try:
                    public_access_block = s3.get_public_access_block(Bucket=bucket_name)
                    config = public_access_block['PublicAccessBlockConfiguration']
                    
                    if not all([
                        config.get('BlockPublicAcls', False),
                        config.get('IgnorePublicAcls', False),
                        config.get('BlockPublicPolicy', False),
                        config.get('RestrictPublicBuckets', False)
                    ]):
                        s3_findings.append({
                            "type": "INCOMPLETE_PUBLIC_ACCESS_BLOCK",
                            "severity": "HIGH",
                            "resource": f"S3 Bucket: {bucket_name}",
                            "description": "Bucket doesn't have complete public access block"
                        })
                except ClientError:
                    s3_findings.append({
                        "type": "NO_PUBLIC_ACCESS_BLOCK",
                        "severity": "HIGH",
                        "resource": f"S3 Bucket: {bucket_name}",
                        "description": "Bucket has no public access block configuration"
                    })
                
                # Check encryption
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    s3_findings.append({
                        "type": "UNENCRYPTED_BUCKET",
                        "severity": "HIGH",
                        "resource": f"S3 Bucket: {bucket_name}",
                        "description": "Bucket is not encrypted"
                    })
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        s3_findings.append({
                            "type": "VERSIONING_DISABLED",
                            "severity": "MEDIUM",
                            "resource": f"S3 Bucket: {bucket_name}",
                            "description": "Bucket versioning is not enabled"
                        })
                except ClientError:
                    pass
            
            return s3_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def _check_public_bucket_policy(self, policy_doc):
        """Check if bucket policy allows public access"""
        statements = policy_doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if (statement.get('Effect') == 'Allow' and 
                statement.get('Principal') == '*'):
                return True
        
        return False
    
    def analyze_ec2_security(self):
        """Analyze EC2 security configurations"""
        ec2_findings = []
        
        try:
            ec2 = self.services['ec2']
            
            # Analyze security groups
            security_groups = ec2.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                
                # Check for overly permissive inbound rules
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Check for dangerous ports
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)
                            
                            dangerous_ports = [22, 3389, 1433, 3306, 5432, 6379, 27017]
                            
                            for port in dangerous_ports:
                                if from_port <= port <= to_port:
                                    ec2_findings.append({
                                        "type": "OPEN_DANGEROUS_PORT",
                                        "severity": "CRITICAL",
                                        "resource": f"Security Group: {sg_id}",
                                        "port": port,
                                        "description": f"Security group allows {port} from 0.0.0.0/0"
                                    })
            
            # Analyze instances
            instances = ec2.describe_instances()
            
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    
                    # Check for public IP assignment
                    if instance.get('PublicIpAddress'):
                        ec2_findings.append({
                            "type": "PUBLIC_INSTANCE",
                            "severity": "MEDIUM",
                            "resource": f"EC2 Instance: {instance_id}",
                            "description": "Instance has public IP address"
                        })
                    
                    # Check for IMDSv1 (instance metadata service)
                    metadata_options = instance.get('MetadataOptions', {})
                    if metadata_options.get('HttpTokens') != 'required':
                        ec2_findings.append({
                            "type": "IMDSV1_ENABLED",
                            "severity": "MEDIUM",
                            "resource": f"EC2 Instance: {instance_id}",
                            "description": "Instance allows IMDSv1 (security risk)"
                        })
            
            return ec2_findings
            
        except Exception as e:
            return [{"error": str(e)}]

# AWS privilege escalation techniques
class AWSPrivilegeEscalator:
    def __init__(self, session):
        self.session = session
        self.escalation_paths = []
    
    def find_escalation_paths(self):
        """Identify potential privilege escalation paths"""
        escalation_methods = [
            self.check_iam_policy_attachment(),
            self.check_role_assumption(),
            self.check_lambda_execution(),
            self.check_cloudformation_execution(),
            self.check_ec2_role_attachment()
        ]
        
        return [method for method in escalation_methods if method]
    
    def check_iam_policy_attachment(self):
        """Check for IAM policy attachment privileges"""
        try:
            iam = self.session.client('iam')
            
            # Check if current identity can attach policies
            try:
                iam.list_attached_user_policies(UserName='test-user-that-does-not-exist')
            except ClientError as e:
                if 'NoSuchEntity' in str(e):
                    return {
                        "method": "IAM_POLICY_ATTACHMENT",
                        "description": "Can attach IAM policies to users/roles",
                        "exploitation": "Attach AdministratorAccess policy to gain full privileges"
                    }
            
        except Exception:
            pass
        
        return None
    
    def check_role_assumption(self):
        """Check for assumable roles with higher privileges"""
        try:
            iam = self.session.client('iam')
            sts = self.session.client('sts')
            
            # Get current identity
            current_identity = sts.get_caller_identity()
            current_arn = current_identity['Arn']
            
            # List roles and check trust policies
            roles = iam.list_roles()['Roles']
            
            for role in roles:
                trust_policy = role['AssumeRolePolicyDocument']
                
                # Check if current identity can assume this role
                if self._can_assume_role(current_arn, trust_policy):
                    # Check if role has higher privileges
                    role_policies = iam.list_attached_role_policies(RoleName=role['RoleName'])
                    
                    for policy in role_policies['AttachedPolicies']:
                        if 'Admin' in policy['PolicyName'] or 'FullAccess' in policy['PolicyName']:
                            return {
                                "method": "ROLE_ASSUMPTION",
                                "role": role['RoleName'],
                                "description": f"Can assume role {role['RoleName']} with elevated privileges",
                                "exploitation": f"aws sts assume-role --role-arn {role['Arn']} --role-session-name escalation"
                            }
            
        except Exception as e:
            pass
        
        return None
    
    def _can_assume_role(self, current_arn, trust_policy):
        """Check if current identity can assume role based on trust policy"""
        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                principal = statement.get('Principal', {})
                
                # Check for wildcard
                if principal == '*':
                    return True
                
                # Check for specific ARN
                aws_principal = principal.get('AWS')
                if aws_principal:
                    if isinstance(aws_principal, list):
                        if current_arn in aws_principal or '*' in aws_principal:
                            return True
                    elif aws_principal == current_arn or aws_principal == '*':
                        return True
        
        return False

# AWS lateral movement techniques  
def enumerate_aws_resources():
    """Enumerate AWS resources for lateral movement"""
    enumeration_script = '''
#!/bin/bash
# AWS Resource Enumeration Script

echo "[*] Starting AWS resource enumeration..."

# Check current identity
echo "[*] Current identity:"
aws sts get-caller-identity

# Enumerate S3 buckets
echo "[*] S3 Buckets:"
aws s3 ls

# Check accessible buckets
echo "[*] Checking bucket access:"
for bucket in $(aws s3 ls | awk '{print $3}'); do
    echo "Checking bucket: $bucket"
    aws s3 ls s3://$bucket/ --max-items 10 2>/dev/null && echo "  [+] Accessible"
done

# Enumerate EC2 instances
echo "[*] EC2 Instances:"
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress,PrivateIpAddress]' --output table

# Enumerate Lambda functions
echo "[*] Lambda Functions:"
aws lambda list-functions --query 'Functions[*].[FunctionName,Runtime,Role]' --output table

# Enumerate RDS instances
echo "[*] RDS Instances:"
aws rds describe-db-instances --query 'DBInstances[*].[DBInstanceIdentifier,Engine,PubliclyAccessible,VpcId]' --output table

# Enumerate IAM users and roles
echo "[*] IAM Users:"
aws iam list-users --query 'Users[*].[UserName,CreateDate]' --output table

echo "[*] IAM Roles:"
aws iam list-roles --query 'Roles[*].[RoleName,CreateDate]' --output table

# Check for secrets in Systems Manager
echo "[*] Systems Manager Parameters:"
aws ssm describe-parameters --query 'Parameters[*].[Name,Type]' --output table

# Enumerate security groups
echo "[*] Security Groups:"
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupId,GroupName,VpcId]' --output table

echo "[*] Resource enumeration complete"
'''
    return enumeration_script
```

---

## Azure Security Assessment Framework

### Azure Active Directory and Resource Analysis

```python
#!/usr/bin/env python3
"""
Azure Security Assessment Framework
Comprehensive Azure environment security evaluation
"""

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
import requests
import json

class AzureSecurityAssessor:
    def __init__(self, subscription_id, tenant_id=None, client_id=None, client_secret=None):
        self.subscription_id = subscription_id
        
        # Initialize credential
        if client_id and client_secret and tenant_id:
            self.credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
        else:
            self.credential = DefaultAzureCredential()
        
        # Initialize management clients
        self.resource_client = ResourceManagementClient(self.credential, subscription_id)
        self.compute_client = ComputeManagementClient(self.credential, subscription_id)
        self.storage_client = StorageManagementClient(self.credential, subscription_id)
        self.network_client = NetworkManagementClient(self.credential, subscription_id)
        self.auth_client = AuthorizationManagementClient(self.credential, subscription_id)
        self.keyvault_client = KeyVaultManagementClient(self.credential, subscription_id)
        
        self.findings = []
    
    def enumerate_azure_environment(self):
        """Comprehensive Azure environment enumeration"""
        print("[*] Starting Azure environment enumeration...")
        
        enumeration_results = {
            "subscription_info": self.get_subscription_info(),
            "resource_analysis": self.analyze_resources(),
            "storage_analysis": self.analyze_storage_security(),
            "network_analysis": self.analyze_network_security(),
            "vm_analysis": self.analyze_vm_security(),
            "rbac_analysis": self.analyze_rbac_configuration(),
            "keyvault_analysis": self.analyze_keyvault_security()
        }
        
        return enumeration_results
    
    def get_subscription_info(self):
        """Get Azure subscription information"""
        try:
            # Get subscription details
            subscription = next(self.resource_client.subscriptions.list())
            
            # Get resource groups
            resource_groups = list(self.resource_client.resource_groups.list())
            
            subscription_info = {
                "subscription_id": self.subscription_id,
                "subscription_name": subscription.display_name,
                "tenant_id": subscription.tenant_id,
                "state": subscription.state,
                "resource_group_count": len(resource_groups),
                "resource_groups": [rg.name for rg in resource_groups]
            }
            
            return subscription_info
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_storage_security(self):
        """Analyze Azure Storage account security"""
        storage_findings = []
        
        try:
            # List all storage accounts
            storage_accounts = list(self.storage_client.storage_accounts.list())
            
            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4]
                
                # Get storage account properties
                account_details = self.storage_client.storage_accounts.get_properties(
                    resource_group, account_name
                )
                
                # Check for public access
                if (hasattr(account_details, 'allow_blob_public_access') and 
                    account_details.allow_blob_public_access):
                    storage_findings.append({
                        "type": "PUBLIC_BLOB_ACCESS_ENABLED",
                        "severity": "HIGH",
                        "resource": f"Storage Account: {account_name}",
                        "description": "Storage account allows public blob access"
                    })
                
                # Check encryption
                if (hasattr(account_details, 'encryption') and 
                    account_details.encryption and
                    not account_details.encryption.services.blob.enabled):
                    storage_findings.append({
                        "type": "BLOB_ENCRYPTION_DISABLED",
                        "severity": "HIGH",
                        "resource": f"Storage Account: {account_name}",
                        "description": "Blob encryption is disabled"
                    })
                
                # Check for HTTPS enforcement
                if not account_details.enable_https_traffic_only:
                    storage_findings.append({
                        "type": "HTTPS_NOT_ENFORCED",
                        "severity": "MEDIUM",
                        "resource": f"Storage Account: {account_name}",
                        "description": "HTTPS traffic is not enforced"
                    })
                
                # Check network access rules
                if (hasattr(account_details, 'network_rule_set') and
                    account_details.network_rule_set and
                    account_details.network_rule_set.default_action == 'Allow'):
                    storage_findings.append({
                        "type": "UNRESTRICTED_NETWORK_ACCESS",
                        "severity": "HIGH",
                        "resource": f"Storage Account: {account_name}",
                        "description": "Storage account allows unrestricted network access"
                    })
                
                # Check for shared access signature policies
                try:
                    # This requires additional permissions and may not always be accessible
                    keys = self.storage_client.storage_accounts.list_keys(
                        resource_group, account_name
                    )
                    if len(keys.keys) > 0:
                        storage_findings.append({
                            "type": "STORAGE_KEYS_ACCESSIBLE",
                            "severity": "INFO",
                            "resource": f"Storage Account: {account_name}",
                            "description": "Storage account keys are accessible (potential security risk)"
                        })
                except:
                    pass
            
            return storage_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_network_security(self):
        """Analyze Azure network security configurations"""
        network_findings = []
        
        try:
            # Analyze Network Security Groups
            nsgs = list(self.network_client.network_security_groups.list_all())
            
            for nsg in nsgs:
                nsg_name = nsg.name
                
                # Check security rules
                for rule in nsg.security_rules:
                    # Check for overly permissive inbound rules
                    if (rule.direction == 'Inbound' and 
                        rule.access == 'Allow' and
                        rule.source_address_prefix == '*'):
                        
                        # Check for dangerous ports
                        if rule.destination_port_range:
                            port_ranges = [rule.destination_port_range]
                        else:
                            port_ranges = rule.destination_port_ranges or []
                        
                        dangerous_ports = ['22', '3389', '1433', '3306', '5432']
                        
                        for port_range in port_ranges:
                            if any(port in port_range for port in dangerous_ports):
                                network_findings.append({
                                    "type": "DANGEROUS_INBOUND_RULE",
                                    "severity": "CRITICAL",
                                    "resource": f"NSG: {nsg_name}, Rule: {rule.name}",
                                    "description": f"NSG allows {port_range} from any source"
                                })
            
            # Analyze Virtual Networks
            vnets = list(self.network_client.virtual_networks.list_all())
            
            for vnet in vnets:
                # Check for subnets without NSGs
                for subnet in vnet.subnets:
                    if not subnet.network_security_group:
                        network_findings.append({
                            "type": "SUBNET_WITHOUT_NSG",
                            "severity": "MEDIUM",
                            "resource": f"VNet: {vnet.name}, Subnet: {subnet.name}",
                            "description": "Subnet doesn't have an associated NSG"
                        })
            
            return network_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_vm_security(self):
        """Analyze Azure VM security configurations"""
        vm_findings = []
        
        try:
            # List all VMs
            vms = list(self.compute_client.virtual_machines.list_all())
            
            for vm in vms:
                vm_name = vm.name
                resource_group = vm.id.split('/')[4]
                
                # Check for managed identity
                if not vm.identity:
                    vm_findings.append({
                        "type": "NO_MANAGED_IDENTITY",
                        "severity": "MEDIUM",
                        "resource": f"VM: {vm_name}",
                        "description": "VM doesn't have managed identity configured"
                    })
                
                # Check for disk encryption
                if vm.storage_profile and vm.storage_profile.os_disk:
                    if not vm.storage_profile.os_disk.encryption_settings:
                        vm_findings.append({
                            "type": "UNENCRYPTED_OS_DISK",
                            "severity": "HIGH",
                            "resource": f"VM: {vm_name}",
                            "description": "VM OS disk is not encrypted"
                        })
                
                # Check network interfaces for public IPs
                if vm.network_profile:
                    for nic_ref in vm.network_profile.network_interfaces:
                        nic_id = nic_ref.id
                        nic_name = nic_id.split('/')[-1]
                        nic_rg = nic_id.split('/')[4]
                        
                        try:
                            nic = self.network_client.network_interfaces.get(nic_rg, nic_name)
                            
                            for ip_config in nic.ip_configurations:
                                if ip_config.public_ip_address:
                                    vm_findings.append({
                                        "type": "VM_WITH_PUBLIC_IP",
                                        "severity": "MEDIUM",
                                        "resource": f"VM: {vm_name}",
                                        "description": "VM has public IP address"
                                    })
                        except:
                            pass
            
            return vm_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_rbac_configuration(self):
        """Analyze Azure RBAC configuration"""
        rbac_findings = []
        
        try:
            # Get role assignments
            role_assignments = list(self.auth_client.role_assignments.list())
            
            # Get role definitions for analysis
            role_definitions = {
                rd.id: rd for rd in self.auth_client.role_definitions.list('/subscriptions/' + self.subscription_id)
            }
            
            for assignment in role_assignments:
                role_def = role_definitions.get(assignment.role_definition_id)
                
                if role_def:
                    # Check for overly broad assignments
                    if ('*' in assignment.scope and 
                        'Owner' in role_def.role_name):
                        rbac_findings.append({
                            "type": "BROAD_OWNER_ASSIGNMENT",
                            "severity": "CRITICAL",
                            "resource": f"Principal: {assignment.principal_id}",
                            "description": "Principal has Owner role at broad scope"
                        })
                    
                    # Check for service principal assignments
                    if assignment.principal_type == 'ServicePrincipal':
                        if 'Contributor' in role_def.role_name or 'Owner' in role_def.role_name:
                            rbac_findings.append({
                                "type": "ELEVATED_SERVICE_PRINCIPAL",
                                "severity": "HIGH",
                                "resource": f"Service Principal: {assignment.principal_id}",
                                "description": "Service principal has elevated permissions"
                            })
            
            return rbac_findings
            
        except Exception as e:
            return [{"error": str(e)}]

# Azure privilege escalation techniques
class AzurePrivilegeEscalator:
    def __init__(self, credential, subscription_id):
        self.credential = credential
        self.subscription_id = subscription_id
    
    def find_escalation_paths(self):
        """Find Azure privilege escalation paths"""
        
        escalation_paths = []
        
        # Check for Automation Account privileges
        automation_path = self.check_automation_account_access()
        if automation_path:
            escalation_paths.append(automation_path)
        
        # Check for Key Vault access
        keyvault_path = self.check_keyvault_access()
        if keyvault_path:
            escalation_paths.append(keyvault_path)
        
        # Check for Virtual Machine access
        vm_path = self.check_vm_access()
        if vm_path:
            escalation_paths.append(vm_path)
        
        return escalation_paths
    
    def check_automation_account_access(self):
        """Check for Automation Account privilege escalation"""
        try:
            # Azure Automation can run scripts with elevated privileges
            return {
                "method": "AUTOMATION_ACCOUNT_ESCALATION",
                "description": "Access to Automation Account allows script execution with elevated privileges",
                "exploitation": "Create runbook with PowerShell script to add user to admin groups"
            }
        except:
            return None
    
    def check_vm_access(self):
        """Check for VM-based privilege escalation"""
        try:
            # VM access can lead to managed identity abuse
            return {
                "method": "VM_MANAGED_IDENTITY_ABUSE", 
                "description": "VM access with managed identity can escalate privileges",
                "exploitation": "Use VM's managed identity to access other Azure resources"
            }
        except:
            return None

# Azure lateral movement techniques
def enumerate_azure_resources():
    """Enumerate Azure resources for lateral movement"""
    enumeration_script = '''
#!/bin/bash
# Azure Resource Enumeration Script

echo "[*] Starting Azure resource enumeration..."

# Check current identity
echo "[*] Current identity:"
az account show

# List subscriptions
echo "[*] Subscriptions:"
az account list --output table

# List resource groups
echo "[*] Resource Groups:"
az group list --output table

# List storage accounts
echo "[*] Storage Accounts:"
az storage account list --output table

# Check storage account access
echo "[*] Checking storage account access:"
for storage in $(az storage account list --query '[].name' -o tsv); do
    echo "Checking storage account: $storage"
    az storage container list --account-name $storage 2>/dev/null && echo "  [+] Accessible"
done

# List virtual machines
echo "[*] Virtual Machines:"
az vm list --output table

# List key vaults
echo "[*] Key Vaults:"
az keyvault list --output table

# Check key vault access
echo "[*] Checking Key Vault access:"
for vault in $(az keyvault list --query '[].name' -o tsv); do
    echo "Checking vault: $vault"
    az keyvault secret list --vault-name $vault 2>/dev/null && echo "  [+] Accessible"
done

# List role assignments
echo "[*] Role Assignments:"
az role assignment list --all --output table

# List function apps
echo "[*] Function Apps:"
az functionapp list --output table

# List SQL servers
echo "[*] SQL Servers:"
az sql server list --output table

echo "[*] Azure resource enumeration complete"
'''
    return enumeration_script
```

---

## Google Cloud Platform Security Assessment

### GCP IAM and Resource Analysis

```python
#!/usr/bin/env python3
"""
Google Cloud Platform Security Assessment Framework
Comprehensive GCP environment security evaluation
"""

from google.cloud import asset_v1
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import resource_manager
from google.cloud import iam
from google.cloud import secretmanager
import json
from google.auth import default

class GCPSecurityAssessor:
    def __init__(self, project_id):
        self.project_id = project_id
        
        # Initialize credentials
        self.credentials, self.project = default()
        
        # Initialize clients
        self.asset_client = asset_v1.AssetServiceClient(credentials=self.credentials)
        self.storage_client = storage.Client(project=project_id, credentials=self.credentials)
        self.compute_client = compute_v1.InstancesClient(credentials=self.credentials)
        self.resource_manager_client = resource_manager.Client(credentials=self.credentials)
        self.iam_client = iam.Client(credentials=self.credentials)
        
        self.findings = []
    
    def enumerate_gcp_environment(self):
        """Comprehensive GCP environment enumeration"""
        print("[*] Starting GCP environment enumeration...")
        
        enumeration_results = {
            "project_info": self.get_project_info(),
            "iam_analysis": self.analyze_iam_configuration(),
            "storage_analysis": self.analyze_cloud_storage_security(),
            "compute_analysis": self.analyze_compute_security(),
            "network_analysis": self.analyze_network_security(),
            "secrets_analysis": self.analyze_secrets_security()
        }
        
        return enumeration_results
    
    def get_project_info(self):
        """Get GCP project information"""
        try:
            # Get project details
            project = self.resource_manager_client.get_project(self.project_id)
            
            project_info = {
                "project_id": self.project_id,
                "project_name": project.name,
                "project_number": project.project_number,
                "lifecycle_state": project.lifecycle_state,
                "creation_time": project.create_time
            }
            
            return project_info
            
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_iam_configuration(self):
        """Analyze GCP IAM configuration"""
        iam_findings = []
        
        try:
            # Get IAM policy for project
            resource_name = f"projects/{self.project_id}"
            
            # List assets to get IAM policies
            request = asset_v1.ListAssetsRequest(
                parent=resource_name,
                content_type=asset_v1.ContentType.IAM_POLICY
            )
            
            assets = self.asset_client.list_assets(request=request)
            
            for asset in assets:
                if asset.iam_policy:
                    for binding in asset.iam_policy.bindings:
                        # Check for overly broad permissions
                        if binding.role in ['roles/owner', 'roles/editor']:
                            for member in binding.members:
                                if member.startswith('allUsers') or member.startswith('allAuthenticatedUsers'):
                                    iam_findings.append({
                                        "type": "PUBLIC_ELEVATED_ACCESS",
                                        "severity": "CRITICAL",
                                        "resource": asset.name,
                                        "role": binding.role,
                                        "member": member,
                                        "description": f"Public access with {binding.role} role"
                                    })
                        
                        # Check for service account key usage
                        if 'serviceAccount:' in str(binding.members):
                            for member in binding.members:
                                if member.startswith('serviceAccount:'):
                                    iam_findings.append({
                                        "type": "SERVICE_ACCOUNT_BINDING",
                                        "severity": "INFO",
                                        "resource": asset.name,
                                        "service_account": member,
                                        "role": binding.role,
                                        "description": "Service account has IAM binding"
                                    })
                        
                        # Check for primitive roles
                        primitive_roles = ['roles/viewer', 'roles/editor', 'roles/owner']
                        if binding.role in primitive_roles:
                            iam_findings.append({
                                "type": "PRIMITIVE_ROLE_USAGE",
                                "severity": "MEDIUM",
                                "resource": asset.name,
                                "role": binding.role,
                                "description": "Using primitive roles instead of predefined/custom roles"
                            })
            
            return iam_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_cloud_storage_security(self):
        """Analyze Cloud Storage security configurations"""
        storage_findings = []
        
        try:
            # List all buckets
            buckets = self.storage_client.list_buckets()
            
            for bucket in buckets:
                bucket_name = bucket.name
                
                # Check bucket IAM policy
                policy = bucket.get_iam_policy()
                
                for binding in policy.bindings:
                    for member in binding['members']:
                        # Check for public access
                        if member in ['allUsers', 'allAuthenticatedUsers']:
                            storage_findings.append({
                                "type": "PUBLIC_BUCKET_ACCESS",
                                "severity": "CRITICAL",
                                "resource": f"Cloud Storage Bucket: {bucket_name}",
                                "member": member,
                                "role": binding['role'],
                                "description": f"Bucket has public access with {binding['role']} role"
                            })
                
                # Check bucket ACLs
                try:
                    acl = bucket.acl
                    for grant in acl:
                        if hasattr(grant, 'entity') and grant.entity in ['allUsers', 'allAuthenticatedUsers']:
                            storage_findings.append({
                                "type": "PUBLIC_BUCKET_ACL",
                                "severity": "CRITICAL",
                                "resource": f"Cloud Storage Bucket: {bucket_name}",
                                "entity": grant.entity,
                                "description": "Bucket has public ACL"
                            })
                except:
                    pass
                
                # Check for uniform bucket-level access
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    storage_findings.append({
                        "type": "UNIFORM_ACCESS_DISABLED",
                        "severity": "MEDIUM",
                        "resource": f"Cloud Storage Bucket: {bucket_name}",
                        "description": "Uniform bucket-level access is not enabled"
                    })
                
                # Check encryption
                if not bucket.encryption_configuration:
                    storage_findings.append({
                        "type": "DEFAULT_ENCRYPTION_ONLY",
                        "severity": "MEDIUM",
                        "resource": f"Cloud Storage Bucket: {bucket_name}",
                        "description": "Bucket uses only default encryption"
                    })
            
            return storage_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_compute_security(self):
        """Analyze Compute Engine security"""
        compute_findings = []
        
        try:
            # List zones and instances
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = zones_client.list(project=self.project_id)
            
            for zone in zones:
                zone_name = zone.name
                
                # List instances in zone
                instances = self.compute_client.list(project=self.project_id, zone=zone_name)
                
                for instance in instances:
                    instance_name = instance.name
                    
                    # Check for external IP
                    for interface in instance.network_interfaces:
                        if interface.access_configs:
                            for access_config in interface.access_configs:
                                if access_config.nat_ip:
                                    compute_findings.append({
                                        "type": "INSTANCE_WITH_EXTERNAL_IP",
                                        "severity": "MEDIUM",
                                        "resource": f"Compute Instance: {instance_name}",
                                        "external_ip": access_config.nat_ip,
                                        "description": "Instance has external IP address"
                                    })
                    
                    # Check service account
                    if instance.service_accounts:
                        for sa in instance.service_accounts:
                            # Check for default service account
                            if 'compute@developer.gserviceaccount.com' in sa.email:
                                compute_findings.append({
                                    "type": "DEFAULT_SERVICE_ACCOUNT",
                                    "severity": "MEDIUM",
                                    "resource": f"Compute Instance: {instance_name}",
                                    "description": "Instance uses default Compute service account"
                                })
                            
                            # Check for overly broad scopes
                            if 'https://www.googleapis.com/auth/cloud-platform' in sa.scopes:
                                compute_findings.append({
                                    "type": "BROAD_SERVICE_ACCOUNT_SCOPE",
                                    "severity": "HIGH",
                                    "resource": f"Compute Instance: {instance_name}",
                                    "description": "Instance service account has cloud-platform scope"
                                })
                    
                    # Check for SSH keys
                    if hasattr(instance, 'metadata') and instance.metadata:
                        for item in instance.metadata.items:
                            if item.key == 'ssh-keys':
                                compute_findings.append({
                                    "type": "SSH_KEYS_IN_METADATA",
                                    "severity": "INFO",
                                    "resource": f"Compute Instance: {instance_name}",
                                    "description": "Instance has SSH keys in metadata"
                                })
            
            return compute_findings
            
        except Exception as e:
            return [{"error": str(e)}]
    
    def analyze_network_security(self):
        """Analyze GCP network security"""
        network_findings = []
        
        try:
            # Analyze firewall rules
            firewalls_client = compute_v1.FirewallsClient(credentials=self.credentials)
            firewalls = firewalls_client.list(project=self.project_id)
            
            for firewall in firewalls:
                firewall_name = firewall.name
                
                # Check for overly permissive rules
                if firewall.direction == 'INGRESS' and firewall.allowed:
                    for source_range in firewall.source_ranges:
                        if source_range == '0.0.0.0/0':
                            for allowed_rule in firewall.allowed:
                                # Check for dangerous ports
                                dangerous_ports = ['22', '3389', '1433', '3306', '5432']
                                
                                if allowed_rule.ports:
                                    for port in allowed_rule.ports:
                                        if any(dp in port for dp in dangerous_ports):
                                            network_findings.append({
                                                "type": "DANGEROUS_FIREWALL_RULE",
                                                "severity": "CRITICAL",
                                                "resource": f"Firewall Rule: {firewall_name}",
                                                "port": port,
                                                "description": f"Firewall allows {port} from 0.0.0.0/0"
                                            })
                                else:
                                    # No ports specified means all ports
                                    network_findings.append({
                                        "type": "OPEN_FIREWALL_RULE",
                                        "severity": "CRITICAL",
                                        "resource": f"Firewall Rule: {firewall_name}",
                                        "description": "Firewall allows all ports from 0.0.0.0/0"
                                    })
            
            return network_findings
            
        except Exception as e:
            return [{"error": str(e)}]

# GCP privilege escalation techniques
class GCPPrivilegeEscalator:
    def __init__(self, project_id, credentials):
        self.project_id = project_id
        self.credentials = credentials
    
    def find_escalation_paths(self):
        """Find GCP privilege escalation paths"""
        escalation_paths = []
        
        # Check for IAM policy modification privileges
        iam_path = self.check_iam_modification()
        if iam_path:
            escalation_paths.append(iam_path)
        
        # Check for service account key creation
        sa_key_path = self.check_service_account_key_creation()
        if sa_key_path:
            escalation_paths.append(sa_key_path)
        
        # Check for Compute instance access
        compute_path = self.check_compute_access()
        if compute_path:
            escalation_paths.append(compute_path)
        
        return escalation_paths
    
    def check_iam_modification(self):
        """Check for IAM policy modification privileges"""
        try:
            # This would require actual permission checking
            return {
                "method": "IAM_POLICY_MODIFICATION",
                "description": "Can modify IAM policies to grant additional privileges",
                "exploitation": "Add roles/owner binding to current user"
            }
        except:
            return None
    
    def check_service_account_key_creation(self):
        """Check for service account key creation privileges"""
        try:
            return {
                "method": "SERVICE_ACCOUNT_KEY_CREATION",
                "description": "Can create service account keys for privilege escalation",
                "exploitation": "Create key for high-privilege service account"
            }
        except:
            return None

# GCP lateral movement techniques
def enumerate_gcp_resources():
    """Enumerate GCP resources for lateral movement"""
    enumeration_script = '''
#!/bin/bash
# GCP Resource Enumeration Script

echo "[*] Starting GCP resource enumeration..."

# Check current identity
echo "[*] Current identity:"
gcloud auth list

# Get project info
echo "[*] Current project:"
gcloud config get-value project

# List projects
echo "[*] Accessible projects:"
gcloud projects list

# List Compute instances
echo "[*] Compute instances:"
gcloud compute instances list

# List Cloud Storage buckets
echo "[*] Cloud Storage buckets:"
gsutil ls

# Check bucket access
echo "[*] Checking bucket access:"
for bucket in $(gsutil ls | sed 's|gs://||' | sed 's|/||'); do
    echo "Checking bucket: $bucket"
    gsutil ls gs://$bucket/ 2>/dev/null | head -10 && echo "  [+] Accessible"
done

# List Cloud Functions
echo "[*] Cloud Functions:"
gcloud functions list

# List Cloud SQL instances
echo "[*] Cloud SQL instances:"
gcloud sql instances list

# List Kubernetes clusters
echo "[*] GKE clusters:"
gcloud container clusters list

# List IAM service accounts
echo "[*] Service accounts:"
gcloud iam service-accounts list

# List secrets
echo "[*] Secret Manager secrets:"
gcloud secrets list

# List firewall rules
echo "[*] Firewall rules:"
gcloud compute firewall-rules list

echo "[*] GCP resource enumeration complete"
'''
    return enumeration_script
```

---

## Cross-Cloud Attack Scenarios

### Multi-Cloud Privilege Escalation Chains

```python
#!/usr/bin/env python3
"""
Cross-Cloud Attack Framework
Multi-cloud privilege escalation and lateral movement
"""

class CrossCloudAttacker:
    def __init__(self):
        self.cloud_credentials = {}
        self.attack_paths = []
    
    def discover_cloud_connections(self):
        """Discover connections between cloud providers"""
        connections = {
            "aws_to_azure": self.check_aws_azure_federation(),
            "azure_to_gcp": self.check_azure_gcp_federation(),
            "gcp_to_aws": self.check_gcp_aws_federation(),
            "shared_resources": self.check_shared_resources()
        }
        
        return connections
    
    def check_aws_azure_federation(self):
        """Check for AWS-Azure identity federation"""
        try:
            # Look for Azure AD SAML integration with AWS
            federation_indicators = [
                "SAML identity providers in AWS",
                "Azure AD enterprise applications",
                "Cross-cloud service principals"
            ]
            
            return {
                "method": "SAML_FEDERATION",
                "indicators": federation_indicators,
                "exploitation": "Use Azure AD credentials to access AWS resources"
            }
        except:
            return None
    
    def check_shared_resources(self):
        """Check for shared resources across clouds"""
        shared_resources = {
            "container_registries": ["ECR", "ACR", "GCR"],
            "secret_managers": ["AWS Secrets Manager", "Azure Key Vault", "GCP Secret Manager"],
            "identity_systems": ["AWS IAM", "Azure AD", "GCP IAM"],
            "monitoring_tools": ["CloudWatch", "Azure Monitor", "GCP Cloud Monitoring"]
        }
        
        return shared_resources
    
    def execute_cross_cloud_attack(self, initial_cloud, target_cloud):
        """Execute cross-cloud attack scenario"""
        
        attack_scenario = {
            "initial_access": self.get_initial_access(initial_cloud),
            "credential_harvesting": self.harvest_credentials(initial_cloud),
            "lateral_movement": self.lateral_movement_to_target(initial_cloud, target_cloud),
            "privilege_escalation": self.escalate_in_target(target_cloud),
            "persistence": self.establish_persistence(target_cloud)
        }
        
        return attack_scenario
    
    def get_initial_access(self, cloud_provider):
        """Get initial access to cloud environment"""
        if cloud_provider == "aws":
            return {
                "method": "S3_BUCKET_EXPOSURE",
                "description": "Access exposed S3 bucket containing credentials",
                "next_steps": ["Enumerate IAM permissions", "Look for cross-cloud references"]
            }
        elif cloud_provider == "azure":
            return {
                "method": "STORAGE_ACCOUNT_EXPOSURE", 
                "description": "Access exposed Azure Storage account",
                "next_steps": ["Check for service principal keys", "Enumerate subscriptions"]
            }
        elif cloud_provider == "gcp":
            return {
                "method": "GCS_BUCKET_EXPOSURE",
                "description": "Access exposed GCS bucket",
                "next_steps": ["Look for service account keys", "Enumerate projects"]
            }
    
    def harvest_credentials(self, cloud_provider):
        """Harvest credentials from compromised cloud environment"""
        if cloud_provider == "aws":
            return {
                "targets": [
                    "EC2 instance metadata service",
                    "Lambda environment variables",
                    "Systems Manager Parameter Store",
                    "Secrets Manager",
                    "S3 buckets with configuration files"
                ],
                "tools": ["aws cli", "curl", "custom scripts"]
            }
        elif cloud_provider == "azure":
            return {
                "targets": [
                    "Azure Instance Metadata Service",
                    "Key Vault secrets",
                    "Storage account connection strings",
                    "Function App configuration",
                    "Azure DevOps service connections"
                ],
                "tools": ["az cli", "REST API calls", "PowerShell"]
            }
        elif cloud_provider == "gcp":
            return {
                "targets": [
                    "Compute metadata service",
                    "Secret Manager",
                    "Cloud Storage configuration files",
                    "Cloud Function environment variables",
                    "GKE service account tokens"
                ],
                "tools": ["gcloud cli", "curl", "kubectl"]
            }

def generate_cross_cloud_persistence():
    """Generate cross-cloud persistence mechanisms"""
    persistence_techniques = {
        "aws_backdoors": [
            "Create IAM user with programmatic access",
            "Attach policy to existing role", 
            "Create Lambda function with scheduled execution",
            "Modify S3 bucket notification to trigger function",
            "Create CloudFormation stack with backdoor resources"
        ],
        "azure_backdoors": [
            "Create service principal with certificate authentication",
            "Add user to existing Azure AD group",
            "Create Logic App with timer trigger",
            "Modify existing Function App code",
            "Create Automation Account runbook"
        ],
        "gcp_backdoors": [
            "Create service account with JSON key",
            "Add IAM binding to existing service account",
            "Create Cloud Scheduler job",
            "Modify existing Cloud Function",
            "Create Deployment Manager template"
        ],
        "cross_cloud_backdoors": [
            "Federated identity abuse across clouds",
            "Shared container registry poisoning",
            "Cross-cloud secret synchronization",
            "Multi-cloud monitoring tool abuse",
            "Terraform state file manipulation"
        ]
    }
    
    return persistence_techniques
```

---

## Cloud Security Monitoring and Detection

### Comprehensive Cloud Monitoring Framework

```python
#!/usr/bin/env python3
"""
Cloud Security Monitoring Framework
Unified monitoring across AWS, Azure, and GCP
"""

import json
import time
from datetime import datetime, timedelta

class CloudSecurityMonitor:
    def __init__(self):
        self.monitoring_rules = []
        self.alerts = []
        self.baseline_metrics = {}
    
    def setup_monitoring(self):
        """Setup comprehensive cloud security monitoring"""
        monitoring_config = {
            "aws_monitoring": self.setup_aws_monitoring(),
            "azure_monitoring": self.setup_azure_monitoring(), 
            "gcp_monitoring": self.setup_gcp_monitoring(),
            "cross_cloud_monitoring": self.setup_cross_cloud_monitoring()
        }
        
        return monitoring_config
    
    def setup_aws_monitoring(self):
        """Setup AWS-specific monitoring"""
        aws_rules = [
            {
                "name": "Root Account Usage",
                "description": "Monitor root account login attempts",
                "cloudtrail_filter": "$.userIdentity.type = Root",
                "severity": "CRITICAL"
            },
            {
                "name": "IAM Policy Changes",
                "description": "Monitor IAM policy modifications",
                "cloudtrail_filter": "$.eventName = AttachUserPolicy OR $.eventName = DetachUserPolicy",
                "severity": "HIGH"
            },
            {
                "name": "S3 Bucket Policy Changes",
                "description": "Monitor S3 bucket policy modifications",
                "cloudtrail_filter": "$.eventName = PutBucketPolicy OR $.eventName = DeleteBucketPolicy",
                "severity": "HIGH"
            },
            {
                "name": "Unusual API Activity",
                "description": "Detect unusual API call patterns",
                "metric": "API calls per minute > baseline + 3 standard deviations",
                "severity": "MEDIUM"
            },
            {
                "name": "Failed Authentication Attempts",
                "description": "Monitor failed login attempts",
                "cloudtrail_filter": "$.errorCode = SigninFailure",
                "threshold": "5 attempts in 5 minutes",
                "severity": "MEDIUM"
            }
        ]
        
        return aws_rules
    
    def setup_azure_monitoring(self):
        """Setup Azure-specific monitoring"""
        azure_rules = [
            {
                "name": "Global Admin Role Assignment",
                "description": "Monitor Global Administrator role assignments",
                "activity_log_filter": "Microsoft.Authorization/roleAssignments/write",
                "severity": "CRITICAL"
            },
            {
                "name": "Storage Account Key Regeneration",
                "description": "Monitor storage account key regeneration",
                "activity_log_filter": "Microsoft.Storage/storageAccounts/regeneratekey/action",
                "severity": "HIGH"
            },
            {
                "name": "Network Security Group Changes",
                "description": "Monitor NSG rule modifications",
                "activity_log_filter": "Microsoft.Network/networkSecurityGroups/securityRules/write",
                "severity": "HIGH"
            },
            {
                "name": "Bulk Download Activity",
                "description": "Detect bulk download from storage accounts",
                "metric": "Download bytes > 1GB in 10 minutes",
                "severity": "MEDIUM"
            },
            {
                "name": "Service Principal Activity",
                "description": "Monitor service principal authentication",
                "signin_filter": "ServicePrincipal authentication",
                "severity": "INFO"
            }
        ]
        
        return azure_rules
    
    def setup_gcp_monitoring(self):
        """Setup GCP-specific monitoring"""
        gcp_rules = [
            {
                "name": "Project IAM Policy Changes",
                "description": "Monitor project-level IAM policy changes",
                "audit_log_filter": "protoPayload.methodName:SetIamPolicy",
                "severity": "HIGH"
            },
            {
                "name": "Service Account Key Creation",
                "description": "Monitor service account key creation",
                "audit_log_filter": "protoPayload.methodName:google.iam.admin.v1.IAM.CreateServiceAccountKey",
                "severity": "HIGH"
            },
            {
                "name": "Firewall Rule Changes",
                "description": "Monitor firewall rule modifications",
                "audit_log_filter": "resource.type=gce_firewall_rule",
                "severity": "HIGH"
            },
            {
                "name": "Storage Bucket ACL Changes",
                "description": "Monitor GCS bucket ACL changes",
                "audit_log_filter": "protoPayload.methodName:storage.setIamPermissions",
                "severity": "MEDIUM"
            },
            {
                "name": "Compute Instance Creation",
                "description": "Monitor VM instance creation",
                "audit_log_filter": "protoPayload.methodName:v1.compute.instances.insert",
                "severity": "INFO"
            }
        ]
        
        return gcp_rules
    
    def setup_cross_cloud_monitoring(self):
        """Setup cross-cloud monitoring rules"""
        cross_cloud_rules = [
            {
                "name": "Simultaneous Multi-Cloud Activity",
                "description": "Detect simultaneous activity across multiple clouds",
                "correlation": "API calls within 5 minutes across different cloud providers",
                "severity": "HIGH"
            },
            {
                "name": "Cross-Cloud Credential Usage",
                "description": "Detect same credentials used across clouds",
                "correlation": "User identity matches across AWS, Azure, GCP",
                "severity": "CRITICAL"
            },
            {
                "name": "Federated Identity Abuse",
                "description": "Detect abuse of federated identities",
                "indicators": ["Token usage patterns", "Cross-cloud access patterns"],
                "severity": "HIGH"
            },
            {
                "name": "Resource Synchronization Anomalies",
                "description": "Detect unusual resource synchronization",
                "metrics": ["Resource creation timing", "Configuration similarities"],
                "severity": "MEDIUM"
            }
        ]
        
        return cross_cloud_rules
    
    def analyze_security_events(self, events):
        """Analyze security events for threats"""
        threat_analysis = {
            "high_priority_alerts": [],
            "anomaly_detection": [],
            "attack_patterns": [],
            "recommendations": []
        }
        
        # Analyze event patterns
        for event in events:
            # Check for known attack patterns
            if self._matches_attack_pattern(event):
                threat_analysis["attack_patterns"].append(event)
            
            # Anomaly detection
            if self._is_anomalous(event):
                threat_analysis["anomaly_detection"].append(event)
            
            # High priority event detection
            if self._is_high_priority(event):
                threat_analysis["high_priority_alerts"].append(event)
        
        # Generate recommendations
        threat_analysis["recommendations"] = self._generate_recommendations(threat_analysis)
        
        return threat_analysis
    
    def _matches_attack_pattern(self, event):
        """Check if event matches known attack patterns"""
        attack_patterns = [
            "credential_stuffing",
            "privilege_escalation",
            "lateral_movement", 
            "data_exfiltration",
            "persistence_establishment"
        ]
        
        # Implement pattern matching logic
        return False  # Placeholder
    
    def _is_anomalous(self, event):
        """Detect anomalous events using statistical analysis"""
        # Implement anomaly detection logic
        return False  # Placeholder
    
    def _is_high_priority(self, event):
        """Identify high priority security events"""
        high_priority_indicators = [
            "root_account_usage",
            "admin_role_assignment",
            "bulk_data_access",
            "off_hours_activity",
            "unusual_geo_location"
        ]
        
        # Check event against high priority indicators
        return False  # Placeholder
    
    def _generate_recommendations(self, threat_analysis):
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if threat_analysis["high_priority_alerts"]:
            recommendations.append({
                "priority": "IMMEDIATE",
                "action": "Investigate high priority alerts immediately",
                "details": "Review user activity and validate legitimacy"
            })
        
        if threat_analysis["attack_patterns"]:
            recommendations.append({
                "priority": "HIGH",
                "action": "Implement additional monitoring for detected attack patterns",
                "details": "Enhance detection rules and response procedures"
            })
        
        if threat_analysis["anomaly_detection"]:
            recommendations.append({
                "priority": "MEDIUM", 
                "action": "Review anomalous activities for potential threats",
                "details": "Validate against business requirements and user behavior"
            })
        
        return recommendations
```

---

## Conclusion and Defense Strategies

Cloud infrastructure security requires a comprehensive, multi-layered approach that accounts for the unique challenges of each cloud provider while maintaining consistency across hybrid and multi-cloud environments. The attack vectors demonstrated throughout this guide underscore the critical importance of implementing robust security controls from the ground up.

### Universal Cloud Security Principles

1. **Identity and Access Management (IAM) Hardening**
   - Implement least privilege access across all cloud platforms
   - Use role-based access control with regular reviews
   - Enable multi-factor authentication for all accounts
   - Monitor and rotate credentials regularly

2. **Network Security Controls**
   - Implement defense-in-depth network architecture
   - Use network segmentation and micro-segmentation
   - Deploy Web Application Firewalls (WAF) and DDoS protection
   - Monitor network traffic for anomalies

3. **Data Protection and Encryption**
   - Encrypt data at rest and in transit across all platforms
   - Implement proper key management practices
   - Use customer-managed encryption keys where appropriate
   - Regular backup and disaster recovery testing

4. **Continuous Monitoring and Logging**
   - Enable comprehensive audit logging across all services
   - Implement real-time security monitoring and alerting
   - Use Security Information and Event Management (SIEM) systems
   - Regular security assessments and penetration testing

### Cloud-Specific Security Recommendations

#### AWS Security Hardening
```yaml
AWS_Security_Checklist:
  IAM:
    - Enable MFA for all users
    - Use IAM roles instead of access keys where possible
    - Implement SCPs (Service Control Policies)
    - Regular access review and cleanup
  
  Storage:
    - Enable S3 Block Public Access
    - Use S3 bucket encryption
    - Implement S3 access logging
    - Regular bucket permission audits
  
  Compute:
    - Use IMDSv2 for EC2 instances
    - Implement VPC flow logs
    - Use AWS Systems Manager for patch management
    - Enable GuardDuty and Security Hub
  
  Network:
    - Implement VPC with private subnets
    - Use NACLs and Security Groups properly
    - Enable VPC Flow Logs
    - Deploy AWS WAF for web applications
```

#### Azure Security Hardening
```yaml
Azure_Security_Checklist:
  Identity:
    - Enable Azure AD Conditional Access
    - Implement Privileged Identity Management (PIM)
    - Use Managed Identity for services
    - Enable Azure AD Identity Protection
  
  Storage:
    - Disable storage account public access
    - Enable storage encryption with customer keys
    - Implement storage access logging
    - Use Azure Storage firewall rules
  
  Compute:
    - Enable Azure Disk Encryption
    - Use Azure Bastion for secure access
    - Implement Azure Update Management
    - Enable Azure Security Center
  
  Network:
    - Implement Network Security Groups properly
    - Use Azure Firewall for centralized protection
    - Enable Network Watcher for monitoring
    - Deploy Application Gateway with WAF
```

#### GCP Security Hardening
```yaml
GCP_Security_Checklist:
  IAM:
    - Use predefined roles instead of primitive roles
    - Implement Cloud Identity and IAM Recommender
    - Enable audit logging for all services
    - Use service account best practices
  
  Storage:
    - Enable uniform bucket-level access
    - Use customer-managed encryption keys
    - Implement Cloud Storage audit logs
    - Set appropriate bucket permissions
  
  Compute:
    - Use minimal base images for containers
    - Enable OS Login for SSH access
    - Implement Cloud Security Command Center
    - Use shielded VMs for enhanced security
  
  Network:
    - Implement VPC firewall rules properly
    - Use Cloud Armor for DDoS protection
    - Enable VPC Flow Logs
    - Deploy Cloud Load Balancing with security policies
```

### Future of Cloud Security

As cloud technologies continue to evolve, several trends will shape the future security landscape:

1. **Zero Trust Architecture Adoption**
   - Identity-centric security models
   - Continuous verification and validation
   - Microsegmentation and encryption everywhere

2. **AI-Powered Security Operations**
   - Machine learning for threat detection
   - Automated incident response
   - Predictive security analytics

3. **Cloud-Native Security Tools**
   - Container and serverless security platforms
   - Infrastructure as Code (IaC) security scanning
   - Policy as Code implementations

4. **Regulatory Compliance Evolution**
   - Enhanced data sovereignty requirements
   - Cloud-specific compliance frameworks
   - Automated compliance monitoring

### Key Takeaways

The complexity of modern cloud environments creates both unprecedented opportunities and significant security challenges. Organizations that succeed in securing their cloud infrastructure will be those that:

- **Adopt a security-first mindset** from the initial design phase
- **Implement comprehensive monitoring** across all cloud platforms
- **Maintain consistent security policies** across hybrid and multi-cloud environments
- **Invest in security training** for development and operations teams
- **Regularly assess and update** their security posture

Cloud security is not a destination but a continuous journey of assessment, improvement, and adaptation to emerging threats. The techniques and methodologies presented in this guide provide the foundation for building resilient, secure cloud infrastructure that can withstand both current and future attack vectors.

Remember: in the cloud, security is a shared responsibility, but the ultimate accountability for protecting your data and applications remains with your organization. Choose your security controls wisely, implement them comprehensively, and monitor them continuously.
