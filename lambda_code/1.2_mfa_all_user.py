import boto3

def lambda_handler(event, context):

    # Create an IAM client
    iam = boto3.client('iam')

    # Get all IAM groups
    groups = iam.list_groups()

    # Loop through each group and add policy if not already attached
    for group in groups['Groups']:
        group_name = group['GroupName']
        group_policies = iam.list_attached_group_policies(GroupName=group_name)
        policy_arns = [policy['PolicyArn'] for policy in group_policies['AttachedPolicies']]
        if '${policy_arn}' not in policy_arns:
            try:
                response = iam.attach_group_policy(
                    GroupName=group_name,
                    PolicyArn='${policy_arn}'
                )
                print(f"Added policy to {group_name}")
            except Exception as e:
                print(f"Error adding policy to {group_name}: {e}")
        else:
            print(f"Policy already attached to {group_name}")
