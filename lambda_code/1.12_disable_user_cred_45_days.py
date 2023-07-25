import boto3
import datetime
from dateutil.tz import tzutc
import time

def lambda_handler(event, context):
    iam = boto3.client('iam')
    cutoff_date = datetime.datetime.now(tzutc()) - datetime.timedelta(days=45)

    users = iam.list_users()['Users']
    for user in users:
        access_keys = iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
        for access_key in access_keys:
            if access_key['Status'] == 'Active':
                access_key_last_used = iam.get_access_key_last_used(AccessKeyId=access_key['AccessKeyId'])['AccessKeyLastUsed']
                if 'LastUsedDate' in access_key_last_used:
                    last_used_date = access_key_last_used['LastUsedDate'].replace(tzinfo=tzutc())
                    if last_used_date < cutoff_date:
                        iam.update_access_key(UserName=user['UserName'], AccessKeyId=access_key['AccessKeyId'], Status='Inactive')
                        print(f"Access key {access_key} for user {user} has been disabled.")
                else:
                    iam.update_access_key(UserName=user['UserName'], AccessKeyId=access_key['AccessKeyId'], Status='Inactive')
                    print(f"Access key {access_key} for user {user} has been disabled.")
        # Check for unused user credentials
        mfa_devices = iam.list_mfa_devices(UserName=user['UserName'])['MFADevices']
        # if not mfa_devices:
        credential_report = iam.generate_credential_report()
        time.sleep(15)
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
                    iam.update_login_profile(UserName=user['UserName'], PasswordResetRequired=True)
                    print(f"User credentials for user {user} has been disabled.")
            else:
                iam.update_login_profile(UserName=user['UserName'], PasswordResetRequired=True)
                print(f"User credentials for user {user} has been disabled.")