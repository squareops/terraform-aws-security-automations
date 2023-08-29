import boto3
from datetime import datetime

def lambda_handler(event, context):
    iam_client = boto3.client('iam')
    expired_certificates = []

    # List all server certificates
    response = iam_client.list_server_certificates()

    for cert in response['ServerCertificateMetadataList']:
        cert_name = cert['ServerCertificateName']
        expiration_date = cert['Expiration']
        if is_expired(expiration_date):
            # Certificate is expired, add it to the list
            expired_certificates.append(cert_name)
            delete_certificate(iam_client, cert_name)

    if expired_certificates:
        return {
            'statusCode': 200,
            'body': f"Deleted expired certificates: {', '.join(expired_certificates)}"
        }
    else:
        return {
            'statusCode': 404,
            'body': 'Not found: No expired certificates found in IAM.'
        }

def is_expired(expiration_date):
    # Convert expiration_date string to a datetime object
    expiration_date = datetime.strptime(expiration_date, '%Y-%m-%dT%H:%M:%SZ')
    # Check if the certificate is expired (current date is greater than the expiration date)
    return datetime.now() > expiration_date

def delete_certificate(iam_client, cert_name):
    try:
        # Delete the certificate
        iam_client.delete_server_certificate(ServerCertificateName=cert_name)
        print(f"Deleted expired certificate: {cert_name}")
    except Exception as e:
        print(f"Error deleting certificate {cert_name}: {e}")

# Uncomment the next line if you use this code outside of Lambda
# lambda_handler(None, None)
