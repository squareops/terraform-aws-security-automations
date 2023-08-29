import boto3

def send_email_notification(user_name):
    # Prepare the email message
    subject = "Multiple Active Access Keys Detected"
    body = f"Dear {user_name},\n\nWe noticed that you have multiple active access keys in your AWS account. For security reasons, we recommend maintaining only one active access key.\n\nPlease consider deactivating any unused access keys.\n\nBest regards,\nYour AWS Team"

    # Send the email using SNS
    sns_client = boto3.client('sns')
    topic_arn = "${sns_topic_arn}" # Replace with the ARN of your SNS topic
    sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=body
    )

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

        # Check if the user has more than one active access key
        active_keys = [key for key in access_keys if key['Status'] == 'Active']
        if len(active_keys) > 1:
            # Send email notification about multiple active access keys
            send_email_notification(username)

    return {
        'statusCode': 200,
        'body': 'Email notifications sent for IAM users with multiple active access keys'
    }
