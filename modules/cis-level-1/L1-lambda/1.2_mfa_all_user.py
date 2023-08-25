import boto3
from botocore.exceptions import ClientError

def add_policy_to_user_group(groupname, policy_arn):
    iam = boto3.client('iam')

    try:
        # Get the policy details
        policy_response = iam.get_policy(PolicyArn=policy_arn)

        # Attach the policy to the user group
        response = iam.attach_group_policy(GroupName=groupname, PolicyArn=policy_arn)
        print(f"Policy {policy_response['Policy']['PolicyName']} attached to group {groupname}")
        return response
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"Error: Group {groupname} not found.")
        else:
            print(f"Error: {e}")
        return None

def lambda_handler(event, context):
    # Replace these with the actual groupname and policy ARN
    groupname = '${mfa_iam_group}'
    policy_arn = '${policy_arn}'

    print(f"Attempting to attach policy to group: {groupname}")
    response = add_policy_to_user_group(groupname, policy_arn)
    if response:
        return {
            'statusCode': 200,
            'body': f'Policy attached successfully to group: {groupname}.'
        }
    else:
        return {
            'statusCode': 500,
            'body': f'Error attaching policy to group: {groupname}.'
        }