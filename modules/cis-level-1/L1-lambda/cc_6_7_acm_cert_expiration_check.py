import boto3

def lambda_handler(event, context):
    # Initialize the SNS client
    sns_client = boto3.client('sns')
    
    # Get the list of active AWS regions
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    
    # Iterate through each region
    for region in regions:
        # Initialize the ACM client for the current region
        acm_client = boto3.client('acm', region_name=region)
        
        try:
            # List the ACM certificates in the current region
            response = acm_client.list_certificates()
            
            # Process each certificate in the region
            for certificate in response['CertificateSummaryList']:
                certificate_arn = certificate['CertificateArn']
                
                # Get the details of the ACM certificate
                certificate_details = acm_client.describe_certificate(CertificateArn=certificate_arn)
                certificate_name = certificate_details['Certificate']['DomainName']
                expiration_date = certificate_details['Certificate']['NotAfter']
                
                # Compose the email message
                subject = f'ACM Certificate Expiration Alert'
                message = f'The ACM certificate "{certificate_name}" with ARN {certificate_arn} ' \
                          f'in region {region} will expire on {expiration_date}.'
                
                # Replace 'your-topic-arn' with the ARN of your SNS topic
                topic_arn = "${sns_topic_arn}"
                
                # Publish the message to the SNS topic
                sns_client.publish(TopicArn=topic_arn, Subject=subject, Message=message)
        
        except Exception as e:
            print(f'Error in region {region}: {e}')
            # Handle any errors that occur during the process
            # You can choose to log the error or take appropriate actions based on your use case.