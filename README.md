# AWS Security Audit Tool
# Project Overview
# This project implements an automated, serverless tool designed to scan an AWS environment for common security misconfigurations and vulnerabilities. Built using AWS native services including AWS Lambda, EventBridge, DynamoDB, S3, IAM, and IAM Access Analyzer, the tool helps identify risks in services like S3, IAM, and EC2 Security Groups, stores findings, generates reports, and sends alerts for critical issues.
# Features
# Automated Scanning: Scheduled execution via AWS EventBridge.
# Security Checks:
# Detects publicly accessible S3 buckets via policies or ACLs.
# Identifies overly permissive IAM policies attached to roles (looking for Action: "*" on Resource: "*" or broad service access like iam:*, sts:*).
# Leverages IAM Access Analyzer findings for external access analysis.
# Flags Security Groups allowing unrestricted inbound access (0.0.0.0/0 or ::/0) to sensitive ports (SSH, RDP, common database ports).
# Identifies running EC2 instances with public IPs exposed by risky Security Groups.
# Centralized Findings Storage: Stores all audit findings persistently in an Amazon DynamoDB table.
# Reporting: Generates human-readable text summaries and downloadable CSV reports, stored in Amazon S3.
# Live Dashboard: Provides a simple, static HTML dashboard hosted on S3 to view the latest audit findings.
# Critical Alerts: Sends notifications via Amazon SNS for critical security findings.
# Serverless Architecture: Cost-effective and scalable using managed AWS services.
# Architecture
#  The tool utilizes a serverless architecture pattern:
# graph TD
#     A[EventBridge Schedule] --> B(AWS Lambda - Audit Function);
#     B --> C(AWS SDK - Boto3);
#     C --> D(AWS S3 - List/Get Buckets);
#     C --> E(AWS EC2 - Describe Instances/SGs);
#     C --> F(AWS IAM - List/Get Policies/Roles);
#     C --> G(IAM Access Analyzer - List Findings);
#     B --> H(Amazon DynamoDB - Store Findings);
#     B --> I(Amazon S3 - Store Reports);
#     B --> J(Amazon SNS - Send Alerts);
#     I --> K(S3 Static Website Hosting);
#     K --> L(User Browser - Dashboard);

#     %% Styling (Optional - for better rendering in some Markdown viewers)
#     classDef default fill:#f9f,stroke:#333,stroke-width:2px;
#     class A,B,C,D,E,F,G,H,I,J,K,L default;


# EventBridge: Triggers the Lambda function on a schedule.
# Lambda: Executes the audit logic by calling various AWS APIs via Boto3.
# S3, EC2, IAM, Access Analyzer: Services audited by the Lambda function.
# DynamoDB: Stores structured findings.
# S3: Stores audit reports (.txt, .csv, latest.csv) and hosts the static HTML dashboard.
# SNS: Sends notifications for critical findings.
# Setup and Deployment
# This guide assumes you have an AWS account and the AWS CLI configured.
# Create AWS Resources:
# S3 Bucket: Create an S3 bucket to store audit reports and the static website content. Your bucket name is rk-security-audit-logs-83749.
# DynamoDB Table: Create a DynamoDB table named SecurityFindings with a Partition Key (ResourceARN, String) and Sort Key (Timestamp, String).
# SNS Topic: Create an SNS topic for critical alerts. Your topic name is CriticalSecurityAlerts. Subscribe your desired endpoint (e.g., email address) and confirm the subscription.
# Create IAM Policy:
# Go to the IAM Console -> Policies -> Create Policy.
# Select the JSON tab.
# Paste the following policy document, which is tailored to your resources (rk-security-audit-logs-83749, SecurityFindings, CriticalSecurityAlerts), Account ID (------------), and Region (ap-south-1).
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl"
            ],
            "Resource": "*"
        },
         {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::rk-security-audit-logs-83749/audit-reports/*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:ListRoles",
                "iam:ListAttachedRolePolicies",
                "iam:ListRolePolicies",
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRolePolicy"
            ],
            "Resource": "*"
        },
         {
            "Effect": "Allow",
            "Action": [
                "access-analyzer:ListAnalyzers",
                "access-analyzer:ListFindings"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "dynamodb:BatchWriteItem"
            ],
            "Resource": "arn:aws:dynamodb:ap-south-1:211125534020:table/SecurityFindings"
        },
        {
            "Effect": "Allow",
            "Action": [
                "sns:Publish"
            ],
            "Resource": "arn:aws:sns:ap-south-1:211125534020:CriticalSecurityAlerts"
        }
    ]
}


# Give the policy a name (e.g., SecurityAuditLambdaExecutionPolicy) and create it.
# Create/Update IAM Role:
# Go to the IAM Console -> Roles.
# Find your Lambda execution role (e.g., SecurityAuditLambdaRole).
# Attach the policy you just created to this role.
# Create Lambda Function:
# Go to the Lambda Console -> Functions -> Create function.
# Choose "Author from scratch".
# Function name: SecurityAuditFunction (or preferred).
# Runtime: Select a Python 3.x version.
# Architecture: x86_64.
# Execution role: Choose "Use an existing role" and select your SecurityAuditLambdaRole.
# Click "Create function".
# Upload Lambda Code:
# In the Lambda function code editor, replace the default code with the complete Python code for your Lambda function (as provided in our conversation).
# Click "Deploy".
# Configure Lambda Environment Variables:
# In the Lambda function configuration, go to "Environment variables".
# Add the following key-value pairs:
# FINDINGS_TABLE_NAME: SecurityFindings
# LOGS_BUCKET_NAME: rk-security-audit-logs-83749
# SNS_TOPIC_ARN: arn:aws:sns:ap-south-1:211125534020:CriticalSecurityAlerts
# Configure EventBridge Schedule:
# Go to EventBridge Console -> Schedules -> Create schedule.
# Name: DailySecurityAuditTrigger.
# Frequency: Configure a recurring schedule (e.g., rate(1 day) or cron(0 8 * * ? *) for 8 AM UTC).
# Target: Select AWS Lambda and choose your SecurityAuditFunction.
# Create the schedule.
# Configure S3 Static Website Hosting:
# Go to S3 Console -> Your reports bucket (rk-security-audit-logs-83749).
# Go to Properties -> Static website hosting -> Enable.
# Set Index document: index.html.
# Save changes.
# Upload HTML Dashboard File:
# Create the index.html file using the code provided in our conversation, ensuring you replaced "YOUR_BUCKET_NAME" with rk-security-audit-logs-83749.
# Upload index.html to the root of your S3 bucket.
# Configure S3 Bucket Policy for Public Access:
# Go to S3 Console -> Your reports bucket (rk-security-audit-logs-83749).
# Go to Permissions -> Bucket policy -> Edit.
# Paste the following policy, ensuring the bucket name is correct:
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": [
                "arn:aws:s3:::bucket-name/index.html",
                "arn:aws:s3:::bucket-name/audit-reports/latest.csv" ,
                "arn:aws:s3:::bucket-name/audit-reports/*"
            ]
        }
    ]
}


# Save changes.
# Usage
# The audit will run automatically based on the EventBridge schedule.
# To trigger manually for testing, go to the Lambda Console, select your function, go to the "Test" tab, configure a test event (a simple empty JSON {} is sufficient), and click "Test".
# Audit findings will be stored in the SecurityFindings DynamoDB table.
# Detailed reports (.txt, .csv) will be saved in your S3 bucket under the audit-reports/YYYY-MM-DD/ prefix.
# The latest findings can be viewed at your S3 static website endpoint URL (found in S3 bucket Properties -> Static website hosting).
# Critical findings will trigger email alerts via the configured SNS topic.
# Testing
# Refer to the "Testing and Validation" section in your Project Report for detailed test cases. Verify Lambda execution logs, DynamoDB entries, S3 reports, SNS emails, and the S3 dashboard.
# Permissions
# The necessary IAM permissions for the Lambda execution role are defined in the custom IAM policy attached to the role. Refer to the policy JSON above for details.
# Future Enhancements
# Refer to the "Future Work" section in your Project Report for potential improvements and extensions.
# Code
# The complete Lambda function code is available in lambda_security_function.py .
The static dashboard HTML is in index.html.
