import boto3
import datetime

def send_notification(subject, message):
    sns_client = boto3.client('sns')
    
    # Replace 'TopicArn' with the ARN of your SNS topic
    topic_arn = "${sns_topic_arn}"
    
    sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=message
    )

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    email_subject = "SSL/TLS Certificate Expiration Notification"
    email_message = ""
    
    # List all SSL certificates in IAM
    response = iam_client.list_server_certificates()
    
    # Variable to track if any expired certificates are found
    found_expired_certificates = False
    
    for certificate in response['ServerCertificateMetadataList']:
        cert_name = certificate['ServerCertificateName']
        expiration_date = certificate['Expiration']
        
        # Check if the certificate has expired or is close to expiring (within 30 days)
        if (expiration_date - datetime.datetime.now(datetime.timezone.utc)).days <= 30:
            found_expired_certificates = True
            email_message += f"Certificate '{cert_name}' is expired or will expire soon. Expiration Date: {expiration_date}\n"
    
    if not found_expired_certificates:
        email_message = "No SSL/TLS certificates found in IAM."
    
    send_notification(email_subject, email_message)
    
    return {
        'statusCode': 200,
        'body': 'Email notification sent successfully'
    }