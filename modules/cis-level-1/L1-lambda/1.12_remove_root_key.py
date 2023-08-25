1.12 [check112] Ensure no root account access key exists - iam [Critical]

import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    access_keys = iam.list_access_keys(UserName='root')['AccessKeyMetadata']
    for key in access_keys:
        if key['Status'] == 'Active':
            iam.update_access_key(
                AccessKeyId=key['AccessKeyId'],
                Status='Inactive',
                UserName='root'
            )
            print(f"Access key {key['AccessKeyId']} for root account has been disabled.")

This code uses the Boto3 library to interact with the AWS IAM service. It first retrieves a list of access keys for the root account using the list_access_keys method. Then, for each access key, the code checks whether its status is "Active", and if it is, it uses the update_access_key method to set the status to "Inactive", effectively disabling the key.

Note that this code assumes that the Lambda function has appropriate permissions to access and modify IAM policies and users. Also, be careful when running this code in production, as it will disable the root account access key. You may want to modify the code to include additional checks or to run in a development environment first.