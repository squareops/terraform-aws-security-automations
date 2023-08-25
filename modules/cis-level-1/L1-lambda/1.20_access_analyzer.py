import boto3

def lambda_handler(event, context):
    # Create a Boto3 client for EC2 to get a list of active regions
    ec2_client = boto3.client('ec2')
    active_regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]

    for region in active_regions:
        # Create a Boto3 client for Access Analyzer in the current region
        client = boto3.client('accessanalyzer', region_name=region)

        # Generate a unique analyzer name based on the region
        analyzer_name = f'MyAccessAnalyzer-{region}'

        # Create the Access Analyzer without tags
        response = client.create_analyzer(
            analyzerName=analyzer_name,
            type='ACCOUNT'
        )
        print(f"Access Analyzer created in region {region}: {response['arn']}")

    return {
        'statusCode': 200,
        'body': 'Access Analyzers created in all active regions.'
    }