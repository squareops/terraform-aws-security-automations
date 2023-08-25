import boto3

def lambda_handler(event, context):
    iam_client = boto3.client('iam')

    # Get all IAM users
    response = iam_client.list_users()
    users = response['Users']

    # Iterate over each user
    for user in users:
        username = user['UserName']

        # Get all access keys for the user
        response = iam_client.list_access_keys(UserName=username)
        access_keys = response['AccessKeyMetadata']

        # Check if the user has more than one access key
        if len(access_keys) > 1:

            # Deactivate all access keys except the oldest one
            for key in access_keys[1:]:
                access_key_id = key['AccessKeyId']
                iam_client.update_access_key(
                    UserName=username,
                    AccessKeyId=access_key_id,
                    Status='Inactive'
                )

    return {
        'statusCode': 200,
        'body': 'Access keys deactivated for IAM users with more than one access key'
    }
