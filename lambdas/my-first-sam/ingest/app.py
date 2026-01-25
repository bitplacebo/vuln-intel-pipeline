"""
AWS Lambda handler for fetching NVD CVE data and storing in S3.

This Lambda function fetches vulnerability data from the NVD API and stores
the results in an S3 bucket as JSON files.
"""
import json
import os
import boto3
from nvd_fetch import fetch_cves, cve_to_dict

# Initialize S3 client
s3_client = boto3.client('s3')

# Get environment variables
BUCKET_NAME = os.environ.get('BUCKET_NAME', 'sw-us-east-1-vuln-intel')
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')


def save_to_s3(cves, filename, bucket_name):
    """
    Save the fetched CVEs to an S3 bucket as JSON.

    Args:
        cves: List of CVE objects from NVD API
        filename: Name of the file to save (e.g., 'nvd_recent.json')
        bucket_name: Name of the S3 bucket

    Returns:
        dict: Response containing status and S3 location
    """
    try:
        # Convert CVE objects to dictionaries
        json_list = []
        for cve in cves:
            cve_dict = cve_to_dict(cve)
            json_list.append(cve_dict)

        # Convert to JSON string
        json_data = json.dumps(json_list, ensure_ascii=False, indent=4, default=str)

        # Upload to S3
        s3_key = f"raw/{filename}"
        s3_client.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=json_data,
            ContentType='application/json'
        )

        return {
            'success': True,
            'bucket': bucket_name,
            'key': s3_key,
            'size': len(json_data)
        }
    except Exception as e:
        print(f"Error saving data to S3: {e}")
        return {
            'success': False,
            'error': str(e)
        }


def lambda_handler(event, context):
    """
    AWS Lambda handler function.

    Event parameters:
        - range: Either "recent" for last 7 days or "YYYY-MM" for specific month
        - bucket: (Optional) Override the default bucket name

    Examples:
        {"range": "recent"}
        {"range": "2024-01"}
        {"range": "recent", "bucket": "my-custom-bucket"}
    """
    try:
        # Extract parameters from event
        # Support both direct invocation and API Gateway invocation
        if 'body' in event:
            # API Gateway passes body as string
            body = json.loads(event['body']) if isinstance(event['body'], str) else event['body']
        else:
            body = event

        # Get range parameter (default to "recent")
        p_range = body.get('range', 'recent')

        # Get bucket name (allow override from event)
        bucket_name = body.get('bucket', BUCKET_NAME)

        print(f"Fetching NVD data for range: {p_range}")
        print(f"Target S3 bucket: {bucket_name}")

        # Fetch CVE data from NVD
        vulnerabilities = fetch_cves(p_range)
        vulnerabilities_count = len(vulnerabilities)

        if not vulnerabilities:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'No vulnerabilities fetched.',
                    'count': 0,
                    'range': p_range
                })
            }

        print(f"Fetched {vulnerabilities_count} CVEs, uploading to S3...")

        # Save to S3
        filename = f"nvd_{p_range}.json"
        s3_result = save_to_s3(vulnerabilities, filename, bucket_name)

        if s3_result['success']:
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Successfully fetched and saved NVD data',
                    'count': vulnerabilities_count,
                    'range': p_range,
                    's3_location': f"s3://{s3_result['bucket']}/{s3_result['key']}",
                    'file_size_bytes': s3_result['size']
                })
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps({
                    'message': 'Failed to save data to S3',
                    'error': s3_result['error'],
                    'count': vulnerabilities_count
                })
            }

    except Exception as e:
        print(f"Error in lambda_handler: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error processing request',
                'error': str(e)
            })
        }
