import boto3

def lambda_handler(event, context):
    iam_client = boto3.client('iam')

    # List all users
    response = iam_client.list_users()
    users = response['Users']

    for user in users:
        user_name = user['UserName']
        # Get the inline policies attached to the user
        inline_policies = iam_client.list_user_policies(UserName=user_name)['PolicyNames']

        # Delete the inline policies attached to the user
        for policy_name in inline_policies:
            response = iam_client.delete_user_policy(UserName=user_name, PolicyName=policy_name)
            print(f"Deleted inline policy {policy_name} from user {user_name}")
        # List attached policies
        response = iam_client.list_attached_user_policies(UserName=user_name)
        if len(response['AttachedPolicies']) > 0:
            # Detach each policy
            for policy in response['AttachedPolicies']:
                policy_arn = policy['PolicyArn']
                iam_client.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
            print(f'Direct policy attachments removed from user {user_name}')

    return 'All direct policy attachments removed from users'