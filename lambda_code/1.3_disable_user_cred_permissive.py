import boto3
import datetime
from dateutil.tz import tzutc
import time

def lambda_handler(event, context):
    iam = boto3.client('iam')
    cutoff_date = datetime.datetime.now(tzutc()) - datetime.timedelta(days=90)

    # Lists to store users with unused access keys and users with unused login credentials
    users_with_unused_access_keys = []
    users_with_unused_credentials = []

    users = iam.list_users()['Users']
    for user in users:
        access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        for access_key in access_keys:
            if access_key['Status'] == 'Active':
                access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])['AccessKeyLastUsed']
                if 'LastUsedDate' in access_key_last_used:
                    last_used_date = access_key_last_used['LastUsedDate'].replace(tzinfo=tzutc())
                    if last_used_date < cutoff_date:
                        users_with_unused_access_keys.append(user['UserName'])

        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        credential_report = iam.generate_credential_report()
        time.sleep(10)
        report = iam.get_credential_report()
        lines = report['Content'].decode('utf-8').splitlines()
        header = lines[0].split(',')
        data = {}
        for line in lines[1:]:
            fields = line.split(',')
            data[fields[0]] = dict(zip(header, fields))
        if data[user['UserName']]['password_enabled'] == 'true':
            password_last_used = data[user['UserName']]['password_last_used']
            if password_last_used != 'no_information':
                password_last_used_date = datetime.datetime.strptime(password_last_used, '%Y-%m-%dT%H:%M:%S+00:00').replace(tzinfo=tzutc())
                if password_last_used_date < cutoff_date:
                    users_with_unused_credentials.append(user['UserName'])
            else:
                # Consider users without password_last_used information as having unused credentials
                users_with_unused_credentials.append(user['UserName'])

    if users_with_unused_access_keys or users_with_unused_credentials:
        # Send email notification using SNS
        sns_client = boto3.client('sns')
        sns_topic_arn = "${sns_topic_arn}"
        subject = 'Unused AWS Credentials Report'
        message = 'The following users have unused credentials:\n\n'

        if users_with_unused_access_keys:
            message += 'Users with unused access keys:\n'
            message += '\n'.join(users_with_unused_access_keys)
            message += '\n\n'

        if users_with_unused_credentials:
            message += 'Users with unused login credentials:\n'
            message += '\n'.join(users_with_unused_credentials)

        sns_client.publish(TopicArn=sns_topic_arn, Subject=subject, Message=message)

    return {
        'statusCode': 200,
        'body': 'Unused AWS credentials checked successfully.'
    }
