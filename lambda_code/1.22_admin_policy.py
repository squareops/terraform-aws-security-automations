import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    paginator = iam.get_paginator('list_policies')
    for response in paginator.paginate(Scope='Local', PolicyUsageFilter='PermissionsPolicy'):
        for policy in response['Policies']:
            policy_doc = iam.get_policy_version(PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])['PolicyVersion']['Document']
            if policy_doc['Statement']:
                for statement in policy_doc['Statement']:
                    if statement['Effect'] == 'Allow' and statement['Action'] == '*' and statement['Resource'] == '*':
                    # If a policy with administrative privileges is found, send an alert
                        print(f'{policy}')
                        sns = boto3.client('sns')
                        sns.publish(
                            TopicArn= "${sns_topic_arn}",
                            Message=f'Policy {policy} grants administrative privileges {policy_doc}',
                            Subject='IAM Policy Alert'
                        )
                        print(f'Alert sent')
                       