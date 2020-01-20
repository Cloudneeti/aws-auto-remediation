'''
Ensure to enable Transfer Acceleration feature for faster data transfers for AWS S3 buckets
'''

from botocore.exceptions import ClientError

#def run_remediation(boto_session, rule, resource):
def run_remediation(s3_client, bucket_name):
    print("Executing remediation")

    try:
        result = s3_client..put_bucket_accelerate_configuration(Bucket=bucket_name, AccelerateConfiguration={'Status': 'Enabled'})

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Transfer Acceleration feature enabled for S3 Bucket : %s \n" % bucket_name

    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    print(str(responseCode)+'-'+output)   
    return responseCode,output