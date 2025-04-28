import json
import boto3
import datetime
import uuid
import os
import io
import csv
import time

# Initialize Boto3 clients (best practice outside the handler for potential reuse)
session = boto3.Session()
region = session.region_name or 'us-east-1' # Fallback region if needed

s3_client = boto3.client('s3') # S3 client is often global, but operations might need region awareness
ec2_client = session.client('ec2', region_name=region)
iam_client = session.client('iam') # IAM is global, no region needed
config_client = session.client('config', region_name=region)
analyzer_client = session.client('accessanalyzer', region_name=region)
dynamodb_resource = session.resource('dynamodb', region_name=region) # Use resource for easier DynamoDB interaction
sns_client = session.client('sns', region_name=region)

# --- Configuration (Get from Environment Variables) ---
FINDINGS_TABLE_NAME = os.environ.get('FINDINGS_TABLE_NAME')
LOGS_BUCKET_NAME = os.environ.get('LOGS_BUCKET_NAME')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

# --- Global Definitions ---
sensitive_ports = {
    22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
    1433: 'MSSQL', 27017: 'MongoDB', 6379: 'Redis'
}

# Add checks to ensure required variables are set
if not FINDINGS_TABLE_NAME:
    print("ERROR: Environment variable 'FINDINGS_TABLE_NAME' is not set!")
    raise ValueError("Missing required environment variable: FINDINGS_TABLE_NAME")

if not SNS_TOPIC_ARN:
    print("WARNING: Environment variable 'SNS_TOPIC_ARN' is not set. Critical alerts will not be sent.")

if not LOGS_BUCKET_NAME:
     print("WARNING: Environment variable 'LOGS_BUCKET_NAME' is not set. Reports will not be uploaded to S3.")


print(f"Using Table: {FINDINGS_TABLE_NAME}")
if SNS_TOPIC_ARN:
    print(f"Using SNS Topic: {SNS_TOPIC_ARN}")
if LOGS_BUCKET_NAME:
    print(f"Using Logs Bucket: {LOGS_BUCKET_NAME}")


# Get the DynamoDB table object
try:
    findings_table = dynamodb_resource.Table(FINDINGS_TABLE_NAME)
    print(f"Successfully connected to DynamoDB table: {FINDINGS_TABLE_NAME}")
except Exception as e:
    print(f"ERROR: Could not connect to DynamoDB table '{FINDINGS_TABLE_NAME}': {e}")
    raise

# --- Helper Functions ---

def store_findings_dynamodb(findings_list, table):
    """Stores a list of finding dictionaries into the specified DynamoDB table."""
    if not findings_list:
        print("DynamoDB Store: No findings to store.")
        return 0

    stored_count = 0
    try:
        with table.batch_writer() as batch:
            for finding in findings_list:
                if not all(k in finding for k in ['FindingID', 'AccountID', 'Region', 'Timestamp']):
                     print(f"WARNING: Skipping finding due to missing essential keys: {finding.get('FindingID', 'N/A')}")
                     continue
                print(f"  - Storing Finding: {finding['CheckName']} - {finding.get('ResourceID', 'N/A')} - Severity: {finding['Severity']}")
                batch.put_item(Item=finding)
                stored_count += 1
        print(f"DynamoDB Store: Successfully stored {stored_count} findings.")
        return stored_count
    except Exception as e:
        print(f"ERROR storing findings to DynamoDB: {e}")
        return stored_count


def send_sns_alert(critical_findings, topic_arn, audit_run_id, timestamp, account_id, region):
    """Sends an SNS notification summarizing critical findings."""
    if not critical_findings:
        print("SNS Alert: No critical findings to report.")
        return False

    if not topic_arn:
        print("SNS Alert: SNS_TOPIC_ARN not configured. Skipping alert.")
        return False

    message_body_lines = [
        f"🚨 Critical Security Findings Detected in AWS Account {account_id} (Region: {region}) 🚨",
        f"Audit Run ID: {audit_run_id}", f"Time: {timestamp}", f"Total Critical Findings: {len(critical_findings)}", "="*40
    ]

    for finding in critical_findings:
        message_body_lines.append(f"Check: {finding.get('CheckName', 'N/A')}")
        message_body_lines.append(f"Resource Type: {finding.get('ResourceType', 'N/A')}")
        message_body_lines.append(f"Resource ID: {finding.get('ResourceID', 'N/A')}")
        message_body_lines.append(f"Description: {finding.get('FindingDescription', 'No description provided.')}")
        message_body_lines.append(f"Severity: {finding.get('Severity', 'N/A')}")
        message_body_lines.append("-" * 20)

    message_body = "\n".join(message_body_lines)
    subject = f"Critical AWS Security Alert ({len(critical_findings)} findings) - Account {account_id}"

    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=message_body,
            Subject=subject
        )
        print(f"SNS Alert: Successfully sent notification for {len(critical_findings)} critical findings. Message ID: {response.get('MessageId')}")
        return True
    except Exception as e:
        print(f"ERROR sending SNS notification: {e}")
        return False


# --- Check Functions ---

def check_port_range(from_port, to_port, ip_protocol, sensitive_ports_map, cidr):
    """
    Checks if a rule's port range and protocol match any sensitive ports.
    Returns a reason string if a match is found, otherwise None.
    Handles 'All Traffic' (-1) protocol.
    """
    if ip_protocol is not None:
        ip_protocol = str(ip_protocol).lower()

    if ip_protocol not in ['tcp', '6', '-1']:
        return None

    try:
        if from_port is None or to_port is None:
            for port, name in sensitive_ports_map.items():
                 return f"allows ALL traffic (TCP/All Protocol) from {cidr}, implicitly including sensitive port {name} ({port})"
            return f"allows ALL traffic (TCP/All Protocol) from {cidr}, which may include sensitive services"


        rule_start = int(from_port)
        rule_end = int(to_port)

        for port, name in sensitive_ports_map.items():
            if rule_start <= port <= rule_end:
                return f"allows access to {name} (Port {port}) from {cidr}"

    except (ValueError, TypeError) as e:
        print(f"WARNING: Could not parse port numbers '{from_port}'-'{to_port}'. Error: {e}. Skipping range check for this rule.")
        return None

    return None


def create_sg_finding(account_id, region, audit_run_id, ts, sg_id, sg_name, reason):
     """Helper to create a standardized finding dictionary for Security Groups."""
     return {
         'FindingID': str(uuid.uuid4()),
         'AccountID': account_id,
         'Region': region,
         'ResourceType': 'SecurityGroup',
         'ResourceID': sg_id,
         'CheckName': 'SecurityGroupUnrestrictedAccess',
         'FindingDescription': f"Security Group '{sg_name}' ({sg_id}) {reason}",
         'Severity': 'Critical',
         'Timestamp': ts,
         'Status': 'OPEN',
         'AuditRunID': audit_run_id
     }

# Based on analysis of gemini.txt, this function exists
def check_s3_public_access(account_id, region, audit_run_id, ts):
    """
    Checks S3 buckets for public access settings, policies, or ACLs.
    Returns a list of finding dictionaries.
    """
    print("--- Starting S3 Public Access Check ---")
    findings_list = []

    try:
        local_s3_client = boto3.client('s3')
        response = local_s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        print(f"Found {len(buckets)} buckets globally to check.")

        for bucket in buckets:
            bucket_name = bucket['Name']
            print(f"Checking Bucket: {bucket_name}")
            is_public = False
            public_reason = []

            try:
                bucket_location_response = local_s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_region = bucket_location_response.get('LocationConstraint') or 'us-east-1'
            except Exception as loc_e:
                 print(f"WARNING: Could not get location for bucket {bucket_name}. Using default S3 client. Error: {loc_e}")


            # --- Check Bucket Policy Status ---
            try:
                bps_response = local_s3_client.get_bucket_policy_status(Bucket=bucket_name)
                if bps_response.get('PolicyStatus', {}).get('IsPublic', False):
                    is_public = True
                    public_reason.append("Bucket policy allows public access.")
                    print(f"ALERT: Bucket {bucket_name} policy status IS PUBLIC.")
            except local_s3_client.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                    print(f"Bucket {bucket_name}: No bucket policy found.")
                elif e.response['Error']['Code'] == 'AccessDenied':
                    print(f"WARNING: Access Denied trying to get Bucket Policy Status for {bucket_name}. Skipping policy check.")
                else:
                    print(f"ERROR getting Bucket Policy Status for {bucket_name}: {e}")


            # --- Check Bucket ACLs ---
            if not is_public:
                try:
                    acl_response = local_s3_client.get_bucket_acl(Bucket=bucket_name)
                    grants = acl_response.get('Grants', [])
                    for grant in grants:
                        grantee = grant.get('Grantee', {})
                        uri = grantee.get('URI', '')
                        if uri == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            is_public = True
                            public_reason.append(f"ACL grants permission ({grant.get('Permission')}) to AllUsers.")
                            print(f"ALERT: Bucket {bucket_name} ACL grants public access (AllUsers).")
                            break
                        if uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers':
                            is_public = True
                            public_reason.append(f"ACL grants permission ({grant.get('Permission')}) to AuthenticatedUsers.")
                            print(f"ALERT: Bucket {bucket_name} ACL grants access to AuthenticatedUsers.")
                            break

                except local_s3_client.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'AccessDenied':
                        print(f"WARNING: Access Denied trying to get Bucket ACL for {bucket_name}. Skipping ACL check.")
                    else:
                        print(f"ERROR getting Bucket ACL for {bucket_name}: {e}")

            # --- Create Finding if Public ---
            if is_public:
                finding_description = f"Bucket '{bucket_name}' is publicly accessible. Reasons: {'; '.join(public_reason)}"
                finding = {
                    'FindingID': str(uuid.uuid4()),
                    'AccountID': account_id,
                    'Region': region,
                    'ResourceType': 'S3Bucket',
                    'ResourceID': bucket_name,
                    'CheckName': 'S3PublicAccess',
                    'FindingDescription': finding_description,
                    'Severity': 'Critical',
                    'Timestamp': ts,
                    'Status': 'OPEN',
                    'AuditRunID': audit_run_id
                }
                findings_list.append(finding)

    except boto3.exceptions.ClientError as e:
         print(f"ERROR listing S3 buckets: {e}. Check permissions (s3:ListAllMyBuckets).")
         findings_list.append({
             'FindingID': str(uuid.uuid4()), 'AccountID': account_id, 'Region': region,
             'ResourceType': 'AWSAccount', 'ResourceID': account_id, 'CheckName': 'S3AccessError',
             'FindingDescription': f'Could not list/check S3 buckets due to error: {e}',
             'Severity': 'Info', 'Timestamp': ts, 'Status': 'ERROR', 'AuditRunID': audit_run_id
         })

    except Exception as e:
        print(f"An unexpected error occurred during S3 checks: {e}")


    print(f"--- Finished S3 Public Access Check. Found {len(findings_list)} potential public buckets/errors. ---")
    return findings_list


# Based on analysis of gemini.txt, these functions exist
def check_iam_permissions(account_id, region, audit_run_id, ts):
    """
    Checks for overly permissive IAM policies (e.g., Allow *:* on roles)
    and leverages IAM Access Analyzer for external access findings.
    Returns a list of finding dictionaries.
    """
    print("--- Starting IAM Permission Check ---")
    findings_list = []
    processed_policy_arns = set()

    # === Part 1: Check IAM Access Analyzer Findings ===
    try:
        analyzers_response = analyzer_client.list_analyzers(type='ACCOUNT')
        analyzers = analyzers_response.get('analyzers', [])

        if not analyzers:
            print(f"IAM Access Analyzer: No ACCOUNT analyzers found in region {region}. Skipping this check.")
        else:
            analyzer_arn = analyzers[0]['arn']
            print(f"IAM Access Analyzer: Found analyzer {analyzer_arn}. Checking active findings...")

            paginator = analyzer_client.get_paginator('list_findings')
            page_iterator = paginator.paginate(analyzerArn=analyzer_arn, filter={'status': {'eq': ['ACTIVE']}})

            aa_finding_count = 0
            for page in page_iterator:
                for finding in page.get('findings', []):
                    aa_finding_count += 1
                    finding_id_aa = finding.get('id')
                    resource_arn = finding.get('resource')
                    resource_type = finding.get('resourceType')
                    condition_keys = finding.get('condition', {})
                    action = finding.get('action', ['N/A'])[0]
                    is_public = finding.get('isPublic', False)
                    principal_info = json.dumps(finding.get('principal', {}))

                    severity = 'High'
                    if is_public:
                        severity = 'Critical'
                    elif 'externalPrincipal' in finding.get('principal', {}):
                         severity = 'High'
                    else:
                        severity = 'Medium'

                    description = f"IAM Access Analyzer finding '{finding_id_aa}': Resource '{resource_arn}' ({resource_type}) potentially grants access"
                    if is_public:
                        description += f" publicly to principal {principal_info}"
                    elif 'externalPrincipal' in finding.get('principal', {}):
                         description += f" externally to principal {principal_info}"
                    else:
                         description += f" to principal {principal_info}"
                    description += f" for action(s) like '{action}'."

                    print(f"ALERT: {description}")

                    finding_dict = {
                        'FindingID': str(uuid.uuid4()),
                        'AccountID': account_id,
                        'Region': region,
                        'ResourceType': resource_type,
                        'ResourceID': resource_arn,
                        'CheckName': 'IAMAccessAnalyzerFinding',
                        'FindingDescription': description,
                        'Severity': severity,
                        'Timestamp': ts,
                        'Status': 'OPEN',
                        'AuditRunID': audit_run_id,
                        'Reference': finding_id_aa
                    }
                    findings_list.append(finding_dict)
            print(f"IAM Access Analyzer: Checked {aa_finding_count} active findings.")

    except analyzer_client.exceptions.AccessDeniedException:
        print(f"IAM Access Analyzer: Access Denied in region {region}. Ensure Lambda role has access-analyzer:ListAnalyzers and access-analyzer:ListFindings permissions. Skipping check.")
    except Exception as e:
        print(f"ERROR checking IAM Access Analyzer findings in region {region}: {e}")


    # === Part 2: Check Attached Role Policies for Allow *:* pattern ===
    print("\nChecking IAM Roles for overly permissive attached/inline policies...")
    try:
        paginator = iam_client.get_paginator('list_roles')
        role_iterator = paginator.paginate()

        role_count = 0
        for page in role_iterator:
            for role in page.get('Roles', []):
                role_count += 1
                role_name = role['RoleName']
                role_arn = role['Arn']

                if role_arn.startswith("arn:aws:iam::aws:role/") or "/aws-service-role/" in role_arn:
                    continue
                print(f"Checking Role: {role_name} ({role_arn})")

                # --- Check attached managed policies ---
                try:
                    attached_policies_response = iam_client.list_attached_role_policies(RoleName=role_name)
                    for policy in attached_policies_response.get('AttachedPolicies', []):
                        policy_arn = policy['PolicyArn']
                        policy_name = policy['PolicyName']

                        if policy_arn not in processed_policy_arns:
                            processed_policy_arns.add(policy_arn)

                            is_risky, reason = check_policy_document_for_risks(policy_arn)
                            if is_risky:
                                print(f"ALERT: Role '{role_name}' has risky attached policy '{policy_name}'. Reason: {reason}")
                                finding_dict = {
                                    'FindingID': str(uuid.uuid4()), 'AccountID': account_id, 'Region': 'global',
                                    'ResourceType': 'IAMRole', 'ResourceID': role_arn,
                                    'CheckName': 'IAMRiskyManagedPolicyAttachment',
                                    'FindingDescription': f"Role '{role_name}' has attached policy '{policy_name}' ({policy_arn}) identified as risky. Reason: {reason}",
                                    'Severity': 'High',
                                    'Timestamp': ts, 'Status': 'OPEN', 'AuditRunID': audit_run_id,
                                    'AssociatedResource': policy_arn
                                }
                                if reason == "Allows Action=* on Resource=*" or "iam:" in reason or "sts:" in reason:
                                    finding_dict['Severity'] = 'Critical'
                                findings_list.append(finding_dict)

                except iam_client.exceptions.NoSuchEntityException:
                    print(f"  Role {role_name} seems to have been deleted during scan. Skipping.")
                    continue
                except iam_client.exceptions.AccessDeniedException:
                    print(f"WARNING: Access Denied listing attached policies for role {role_name}. Skipping.")
                except Exception as e:
                    print(f"ERROR listing attached policies for role {role_name}: {e}")

                # --- Check inline policies ---
                try:
                    inline_policies_response = iam_client.list_role_policies(RoleName=role_name)
                    for policy_name in inline_policies_response.get('PolicyNames', []):
                        try:
                            policy_doc_response = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                            policy_document = policy_doc_response.get('PolicyDocument', {})

                            is_risky, reason = parse_policy_statements(policy_document, f"Inline policy '{policy_name}' on role '{role_name}'")
                            if is_risky:
                                print(f"ALERT: Role '{role_name}' has risky inline policy '{policy_name}'. Reason: {reason}")
                                finding_dict = {
                                    'FindingID': str(uuid.uuid4()), 'AccountID': account_id, 'Region': 'global',
                                    'ResourceType': 'IAMRole', 'ResourceID': role_arn,
                                    'CheckName': 'IAMRiskyInlinePolicy',
                                    'FindingDescription': f"Role '{role_name}' has inline policy '{policy_name}' identified as risky. Reason: {reason}",
                                    'Severity': 'High',
                                    'Timestamp': ts, 'Status': 'OPEN', 'AuditRunID': audit_run_id,
                                    'AssociatedResource': f"InlinePolicy:{policy_name}"
                                }
                                if reason == "Allows Action=* on Resource=*" or "iam:" in reason or "sts:" in reason:
                                    finding_dict['Severity'] = 'Critical'
                                findings_list.append(finding_dict)

                        except iam_client.exceptions.NoSuchEntityException:
                            print(f"    Inline policy {policy_name} seems to have been deleted during scan. Skipping.")
                        except iam_client.exceptions.AccessDeniedException:
                            print(f"WARNING: Access Denied getting inline policy {policy_name} for role {role_name}. Skipping.")
                        except Exception as e:
                            print(f"ERROR getting/parsing inline policy {policy_name} for role {role_name}: {e}")

                except iam_client.exceptions.NoSuchEntityException:
                    print(f"  Role {role_name} seems to have been deleted during scan. Skipping inline check.")
                    continue
                except iam_client.exceptions.AccessDeniedException:
                    print(f"WARNING: Access Denied listing inline policies for role {role_name}. Skipping.")
                except Exception as e:
                    print(f"ERROR listing inline policies for role {role_name}: {e}")

        print(f"Checked {role_count} IAM roles for policy risks.")

    except iam_client.exceptions.AccessDeniedException:
        print("IAM Role Check: Access Denied. Ensure Lambda role has required IAM list/get permissions. Skipping role policy checks.")
    except Exception as e:
        print(f"An unexpected error occurred during IAM Role checks: {e}")


    print(f"--- Finished IAM Permission Check. Found {len(findings_list)} potential issues. ---")
    return findings_list


def check_policy_document_for_risks(policy_arn):
    """
    Gets the default version of a managed policy and checks its statements for risks.
    Returns (True, reason_string) if risky, otherwise (False, None).
    """
    try:
        # Need to get the default version ID first
        policy_response = iam_client.get_policy(PolicyArn=policy_arn)
        default_version_id = policy_response.get('Policy', {}).get('DefaultVersionId')

        if default_version_id:
            version_response = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
            policy_document = version_response.get('PolicyVersion', {}).get('Document', {})
            # Document is already a dictionary parsed from JSON by boto3
            return parse_policy_statements(policy_document, policy_arn)
        else:
            print(f"  Could not get default version ID for policy {policy_arn}")
            return False, None
    except iam_client.exceptions.NoSuchEntityException:
        return False, None
    except iam_client.exceptions.AccessDeniedException:
        print(f"WARNING: AccessDenied getting policy/version for {policy_arn}. Skipping check.")
        return False, None
    except json.JSONDecodeError as e:
         print(f"ERROR decoding policy JSON for {policy_arn} (should be pre-parsed by boto3): {e}")
         return False, None
    except Exception as e:
        print(f"ERROR getting/parsing policy document for {policy_arn}: {e}")
        return False, None


def parse_policy_statements(policy_document, policy_identifier):
    """
    Parses the Statement list within a policy document dictionary for common risks.
    Returns (True, reason_string) if risky, otherwise (False, None).
    """
    if not isinstance(policy_document, dict) or 'Statement' not in policy_document:
        return False, None

    statements = policy_document['Statement']
    if not isinstance(statements, list):
        statements = [statements] # Ensure statements is always a list

    for statement in statements:
        if not isinstance(statement, dict):
            # Handle unexpected format
            print(f"WARNING: Skipping non-dictionary statement in {policy_identifier}: {statement}")
            continue

        effect = statement.get('Effect')
        action = statement.get('Action')
        resource = statement.get('Resource')

        if effect == 'Allow':
            # Ensure Action and Resource are lists for consistent checking
            action_list = []
            if isinstance(action, list): action_list = action
            elif isinstance(action, str): action_list = [action]
            # Handle None or other types if necessary, though not expected for Allow statement Actions

            resource_list = []
            if isinstance(resource, list): resource_list = resource
            elif isinstance(resource, str): resource_list = [resource]
            # Handle None or other types if necessary

            # Check for common overly permissive patterns
            # Check for Admin Wildcard (*:*)
            if '*' in action_list and '*' in resource_list:
                return True, "Allows Action=* on Resource=*"
            # Check for risky service wildcards
            if 'iam:*' in action_list and '*' in resource_list:
                return True, "Allows risky action 'iam:*' on Resource=*"
            if 'sts:*' in action_list and '*' in resource_list:
                 return True, "Allows risky action 'sts:*' on Resource=*"
            # Add other risky patterns if needed, e.g., s3:*, ec2:* with Resource=*

    return False, None # No risky statements found


def check_security_groups(account_id, region, audit_run_id, ts):
    """
    Checks EC2 Security Groups for inbound rules allowing unrestricted access
    (0.0.0.0/0 or ::/0) to sensitive ports.
    Returns a list of finding dictionaries.
    """
    print("--- Starting Security Group Check ---")
    findings_list = []

    print(f"Checking for unrestricted access (0.0.0.0/0 or ::/0) to ports: {list(sensitive_ports.keys())}")

    sg_count = 0
    sg_processed_count = 0
    try:
        paginator = ec2_client.get_paginator('describe_security_groups')
        page_iterator = paginator.paginate()

        for page in page_iterator:
            for sg in page.get('SecurityGroups', []):
                sg_count += 1
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                # Simple progress indicator for large accounts
                sg_processed_count += 1
                if sg_processed_count % 50 == 0:
                    print(f"Checked {sg_processed_count} security groups...")

                sg_findings = {} # Use a dict to store unique findings for this SG based on reason

                # Iterate through inbound rules (IpPermissions)
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    ip_protocol = rule.get('IpProtocol')

                    # Check IPv4 ranges for 0.0.0.0/0
                    for ip_range in rule.get('IpRanges', []):
                        # Check if the source is 0.0.0.0/0
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            # Check if the port range/protocol matches a sensitive port
                            reason = check_port_range(from_port, to_port, ip_protocol, sensitive_ports, "0.0.0.0/0")
                            if reason and reason not in sg_findings: # Avoid duplicate findings for the same reason on the same SG
                                print(f"ALERT: Security Group '{sg_name}' ({sg_id}) {reason}")
                                finding = create_sg_finding(account_id, region, audit_run_id, ts, sg_id, sg_name, reason)
                                sg_findings[reason] = finding # Store by reason


                    # Check IPv6 ranges for ::/0
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        if ipv6_range.get('CidrIpv6') == '::/0':
                            # Check if the port range/protocol matches a sensitive port
                            reason = check_port_range(from_port, to_port, ip_protocol, sensitive_ports, "::/0")
                            if reason and reason not in sg_findings: # Avoid duplicate findings
                                print(f"ALERT: Security Group '{sg_name}' ({sg_id}) {reason}")
                                finding = create_sg_finding(account_id, region, audit_run_id, ts, sg_id, sg_name, reason)
                                sg_findings[reason] = finding # Store by reason

                # Add findings found for this SG to the main list
                findings_list.extend(sg_findings.values())

        print(f"Finished checking {sg_count} security groups.")

    except ec2_client.exceptions.ClientError as e:
         if e.response['Error']['Code'] == 'AccessDenied':
             print("Security Group Check: Access Denied. Ensure Lambda role has ec2:DescribeSecurityGroups permission. Skipping check.")
         else:
             print(f"ERROR describing Security Groups: {e}")
         # Add a finding about the inability to check SGs? Optional.
         findings_list.append({
               'FindingID': str(uuid.uuid4()), 'AccountID': account_id, 'Region': region,
               'ResourceType': 'AWSAccount', 'ResourceID': account_id, 'CheckName': 'SecurityGroupAccessError',
               'FindingDescription': f'Could not check Security Groups due to error: {e}',
               'Severity': 'Info', 'Timestamp': ts, 'Status': 'ERROR', 'AuditRunID': audit_run_id
         })
    except Exception as e:
        print(f"An unexpected error occurred during Security Group checks: {e}")
        # Add a finding about the unexpected error? Optional.
        findings_list.append({
               'FindingID': str(uuid.uuid4()), 'AccountID': account_id, 'Region': region,
               'ResourceType': 'AWSAccount', 'ResourceID': account_id, 'CheckName': 'SecurityGroupUnexpectedError',
               'FindingDescription': f'Unexpected error during Security Group checks: {e}',
               'Severity': 'Info', 'Timestamp': ts, 'Status': 'ERROR', 'AuditRunID': audit_run_id
         })

    print(f"--- Finished Security Group Check. Found {len(findings_list)} potential issues. ---")
    return findings_list


# Based on analysis of gemini.txt, this function exists
def check_ec2_vulnerabilities(account_id, region, audit_run_id, ts):
    """
    Identifies EC2 instances with public IPs and overly permissive security groups
    attached (checking against the globally defined sensitive_ports).
    Returns a list of finding dictionaries.
    """
    print("--- Starting EC2 Vulnerability Check ---")
    findings_list = []

    try:
        paginator = ec2_client.get_paginator('describe_instances')
        instance_pages = paginator.paginate(
            # Filter for running instances
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )

        instance_count = 0
        vulnerable_instance_found = False # Flag to indicate if we found at least one instance to check
        for page in instance_pages:
            reservations = page.get('Reservations', [])
            for reservation in reservations:
                instances = reservation.get('Instances', [])
                for instance in instances:
                    instance_count += 1
                    instance_id = instance['InstanceId']
                    public_ip = instance.get('PublicIpAddress') # Check for public IP
                    # Try to get the instance name tag
                    instance_name = 'Unnamed'
                    for tag in instance.get('Tags', []):
                        if tag['Key'] == 'Name':
                            instance_name = tag['Value']
                            break
                    sg_associations = instance.get('SecurityGroups', []) # Get associated SGs

                    # Only proceed if the instance has a public IP and associated SGs
                    if public_ip and sg_associations:
                        if not vulnerable_instance_found:
                             print("Checking running instances with Public IPs...")
                             # Only print this once
                             vulnerable_instance_found = True

                        print(f"  Instance {instance_id} ({instance_name}) has public IP {public_ip}. Checking SGs: {[sg['GroupId'] for sg in sg_associations]}")


                        sg_ids = [sg['GroupId'] for sg in sg_associations] # Extract SG IDs

                        # If there are no SGs associated (unlikely but possible?), skip
                        if not sg_ids: continue

                        # Describe the associated Security Groups to get their rules
                        try:
                            sg_response = ec2_client.describe_security_groups(GroupIds=sg_ids)
                            security_groups_details = {sg['GroupId']: sg for sg in sg_response.get('SecurityGroups', [])}

                            # Iterate through each associated SG
                            for sg_id in sg_ids:
                                sg = security_groups_details.get(sg_id)
                                if not sg:
                                    # Log a warning if SG details couldn't be fetched (e.g., permissions)
                                    print(f"    Warning: Could not retrieve details for SG {sg_id} associated with {instance_id}")
                                    continue # Skip to the next SG for this instance

                                sg_name = sg.get('GroupName', sg_id) # Get SG name

                                # Check inbound rules of this SG
                                for rule in sg.get('IpPermissions', []):
                                    from_port = rule.get('FromPort')
                                    to_port = rule.get('ToPort')
                                    ip_protocol = rule.get('IpProtocol')

                                    # Check IPv4 ranges for 0.0.0.0/0 in this rule
                                    for ip_range in rule.get('IpRanges', []):
                                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                                            # If unrestricted IPv4 source, check if ports are sensitive
                                            reason = check_port_range(from_port, to_port, ip_protocol, sensitive_ports, "0.0.0.0/0")
                                            if reason:
                                                # Found a risky configuration
                                                finding_desc = f"Instance '{instance_name}' ({instance_id}) with Public IP {public_ip} is associated with SG '{sg_name}' ({sg_id}) which {reason}"
                                                print(f"    ALERT: {finding_desc}")
                                                # Add the finding to the list
                                                findings_list.append({
                                                    'FindingID': str(uuid.uuid4()),
                                                    'AccountID': account_id, 'Region': region,
                                                    'ResourceType': 'EC2Instance', 'ResourceID': instance_id,
                                                    'CheckName': 'EC2PublicIPWithOpenSG',
                                                    'FindingDescription': finding_desc,
                                                    'Severity': 'Critical', # This is a critical finding
                                                    'Timestamp': ts, 'Status': 'OPEN', 'AuditRunID': audit_run_id,
                                                    'AssociatedResource': sg_id # Link to the problematic SG
                                                })

                                    # Check IPv6 ranges for ::/0 in this rule
                                    for ipv6_range in rule.get('Ipv6Ranges', []):
                                        if ipv6_range.get('CidrIpv6') == '::/0':
                                            # If unrestricted IPv6 source, check if ports are sensitive
                                            reason = check_port_range(from_port, to_port, ip_protocol, sensitive_ports, "::/0")
                                            if reason:
                                                # Found a risky configuration
                                                finding_desc = f"Instance '{instance_name}' ({instance_id}) with Public IP {public_ip} is associated with SG '{sg_name}' ({sg_id}) which {reason}"
                                                print(f"    ALERT: {finding_desc}")
                                                # Add the finding to the list
                                                findings_list.append({
                                                     'FindingID': str(uuid.uuid4()),
                                                     'AccountID': account_id, 'Region': region,
                                                     'ResourceType': 'EC2Instance', 'ResourceID': instance_id,
                                                     'CheckName': 'EC2PublicIPWithOpenSG',
                                                     'FindingDescription': finding_desc,
                                                     'Severity': 'Critical', # This is a critical finding
                                                     'Timestamp': ts, 'Status': 'OPEN', 'AuditRunID': audit_run_id,
                                                     'AssociatedResource': sg_id
                                                })

                        except ec2_client.exceptions.ClientError as sg_e:
                             if 'AccessDenied' in str(sg_e):
                                 # Handle Access Denied for describing SGs
                                 print(f"    WARNING: Access Denied describing SGs for instance {instance_id}. Skipping SG check for this instance.")
                             else:
                                 # Handle other potential errors when describing SGs
                                 print(f"    ERROR analyzing SGs {sg_ids} for instance {instance_id}: {sg_e}")

        print(f"Checked {instance_count} running EC2 instances.")

    except ec2_client.exceptions.ClientError as e:
        # Handle Access Denied for describing instances
        if 'AccessDenied' in str(e):
             print(f"EC2 Vulnerability Check: Access Denied describing instances in region {region}. Ensure Lambda role has ec2:DescribeInstances permission. Skipping check.")
        else:
             # Handle other potential errors when describing instances
             print(f"ERROR during EC2 vulnerability check (describe_instances) in region {region}: {e}")
        # Add a finding about the inability to check EC2? Optional.


    except Exception as e:
        print(f"An unexpected error occurred during EC2 Vulnerability check in region {region}: {e}")
        # Add a finding about the unexpected error? Optional.


    print(f"--- Finished EC2 Vulnerability Check. Found {len(findings_list)} potential issues. ---")
    # Remove potential duplicate findings if an instance is flagged by multiple rules on the same SG
    unique_findings = list({f"{f['ResourceID']}-{f['FindingDescription']}": f for f in findings_list}.values())
    if len(unique_findings) < len(findings_list):
        print(f"Removed {len(findings_list) - len(unique_findings)} duplicate EC2 findings.")
    return unique_findings


# --- Report Generation Helper (MODIFIED to include latest.csv) ---
def generate_summary_report(findings_list):
    """Generate a plain text summary report for human-readable findings."""
    lines = []
    lines.append("🔐 AWS Security Audit Report")
    lines.append("=" * 80)
    lines.append(f"Total Findings: {len(findings_list)}\n")

    if not findings_list:
        lines.append("✅ No findings detected.")
    else:
        for f in findings_list:
            lines.append(f"[{f['Severity']}] {f['CheckName']}")
            lines.append(f"  Resource: {f['ResourceType']} — {f['ResourceID']}")
            lines.append(f"  Region: {f['Region']} | Time: {f['Timestamp']}")
            lines.append(f"  Description: {f['FindingDescription']}")
            lines.append("-" * 80)

    return "\n".join(lines)


def store_reports_to_s3(findings_list, run_id, timestamp):
    """Store findings as both .txt summary, dated .csv, AND latest.csv report in the S3 bucket."""
    LOGS_BUCKET_NAME = os.environ.get("LOGS_BUCKET_NAME")
    if not LOGS_BUCKET_NAME:
        print("❌ LOGS_BUCKET_NAME not set. Skipping S3 upload.")
        return

    date_prefix = timestamp.split("T")[0]
    text_key = f"audit-reports/{date_prefix}/report-{run_id}.txt"
    csv_key_dated = f"audit-reports/{date_prefix}/report-{run_id}.csv" # Dated CSV key
    csv_key_latest = "audit-reports/latest.csv" # Fixed key for the dashboard


    try:
        # 1. Generate the CSV content
        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)
        headers = [
            "FindingID", "AccountID", "Region", "ResourceType", "ResourceID",
            "CheckName", "FindingDescription", "Severity", "Timestamp", "Status", "AuditRunID"
        ]
        csv_writer.writerow(headers)

        for f in findings_list:
            row = [f.get(h, "") for h in headers]
            csv_writer.writerow(row)

        # Get the CSV content from the buffer
        csv_content = csv_buffer.getvalue().encode("utf-8")

        # 2. Upload the plain-text summary
        summary = generate_summary_report(findings_list)
        s3_client.put_object(
            Bucket=LOGS_BUCKET_NAME,
            Key=text_key,
            Body=summary.encode("utf-8"),
            ContentType="text/plain"
        )
        print(f"✅ Uploaded plain-text report to s3://{LOGS_BUCKET_NAME}/{text_key}")

        # 3. Upload the dated CSV report
        s3_client.put_object(
            Bucket=LOGS_BUCKET_NAME,
            Key=csv_key_dated,
            Body=csv_content, # Use the generated CSV content
            ContentType="text/csv"
        )
        print(f"✅ Uploaded dated CSV report to s3://{LOGS_BUCKET_NAME}/{csv_key_dated}")


        # 4. Upload the same CSV content as 'latest.csv' for the dashboard
        s3_client.put_object(
            Bucket=LOGS_BUCKET_NAME,
            Key=csv_key_latest, # Use the fixed key
            Body=csv_content, # Use the generated CSV content
            ContentType="text/csv"
        )
        print(f"✅ Uploaded latest.csv report for dashboard to s3://{LOGS_BUCKET_NAME}/{csv_key_latest}")


    except Exception as e:
        print(f"❌ ERROR uploading reports to S3: {e}")


# --- Main Handler Function ---
def lambda_handler(event, context):
    print(f"Starting Security Audit Function in {region}...")

    start_time = time.time()

    timestamp = datetime.datetime.utcnow().isoformat()
    audit_run_id = str(uuid.uuid4())

    try:
        # Extract Account ID and Region from the Lambda function ARN
        account_id = context.invoked_function_arn.split(':')[4]
        lambda_region = context.invoked_function_arn.split(':')[3]
    except (AttributeError, IndexError, TypeError):
        print("WARNING: Could not reliably determine Account ID or Region from context. Using fallback values.")
        account_id = "UNKNOWN_ACCOUNT"
        lambda_region = session.region_name or 'us-east-1' # Fallback to Boto3 determined region

    print(f"Audit Run ID: {audit_run_id}")
    print(f"Timestamp: {timestamp}")
    print(f"Account ID: {account_id}")
    print(f"Lambda Region: {lambda_region}")


    all_findings = [] # List to store all findings from all checks

    # --- Execute Check Functions ---
    # Pass account_id, region, audit_run_id, timestamp to each check function
    try:
        s3_findings = check_s3_public_access(account_id, region, audit_run_id, timestamp)
        all_findings.extend(s3_findings) # Add findings to the main list
    except Exception as e:
        print(f"FATAL ERROR during S3 check: {e}")
        # Consider adding an error finding to all_findings


    try:
        iam_findings = check_iam_permissions(account_id, region, audit_run_id, timestamp)
        all_findings.extend(iam_findings) # Add findings to the main list
    except Exception as e:
        print(f"FATAL ERROR during IAM check: {e}")
        # Consider adding an error finding to all_findings


    try:
        sg_findings = check_security_groups(account_id, region, audit_run_id, timestamp)
        all_findings.extend(sg_findings) # Add findings to the main list
    except Exception as e:
        print(f"FATAL ERROR during Security Group check: {e}")
        # Consider adding an error finding to all_findings


    try:
        ec2_findings = check_ec2_vulnerabilities(account_id, region, audit_run_id, timestamp)
        all_findings.extend(ec2_findings) # Add findings to the main list
    except Exception as e:
        print(f"FATAL ERROR during EC2 Vulnerability check: {e}")
        # Consider adding an error finding to all_findings


    # --- Processing Findings ---
    print(f"\n--- Processing {len(all_findings)} total findings from Audit Run {audit_run_id} ---")

    # Store all findings in DynamoDB
    if all_findings:
        stored_count = store_findings_dynamodb(all_findings, findings_table)
        print(f"Attempted to store {len(all_findings)} findings, successfully stored {stored_count}.")
    else:
        print("No findings generated in this run.")

    # Identify and report critical findings via SNS
    critical_findings_details = [f for f in all_findings if f.get('Severity') == 'Critical']
    if critical_findings_details:
        print(f"Found {len(critical_findings_details)} critical findings. Attempting SNS alert...")
        send_sns_alert(critical_findings_details, SNS_TOPIC_ARN, audit_run_id, timestamp, account_id, region)
    else:
        print("No critical findings to alert.")

    # Store reports in S3 (.txt, dated .csv, and latest.csv)
    store_reports_to_s3(all_findings, audit_run_id, timestamp)


    print(f"\n--- Security Audit Function Finished (Audit Run ID: {audit_run_id}) ---")
    # Return a meaningful response
    return {
        'statusCode': 200,
        'body': json.dumps(f'Audit Run {audit_run_id} completed. Found {len(all_findings)} findings.')
    }