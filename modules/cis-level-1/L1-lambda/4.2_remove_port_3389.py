import boto3

def lambda_handler(event, context):
    ec2 = boto3.client('ec2')
    groups = ec2.describe_security_groups()

    for group in groups['SecurityGroups']:
        for rule in group['IpPermissions']:
            if 'FromPort' in rule and rule['FromPort'] == 3389:
                for ip_range in rule['IpRanges']:
                    if ip_range['CidrIp'] == '0.0.0.0/0':
                        ec2.revoke_security_group_ingress(
                            GroupId=group['GroupId'],
                            IpPermissions=[
                                {
                                    'IpProtocol': 'tcp',
                                    'FromPort': 3389,
                                    'ToPort': 3389,
                                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                                }
                            ]
                        )
                        print(f"Revoked port 3389 access to 0.0.0.0/0 for security group {group['GroupName']} ({group['GroupId']})")
