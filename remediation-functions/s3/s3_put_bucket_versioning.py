'''
Enable versioning on S3
'''

from botocore.exceptions import ClientError

def run_remediation(s3_client, bucket_name):
    print("Executing remediation")
    #Enable versioninig for bucket
    try:
        result = s3_client.put_bucket_versioning(
                    Bucket = bucket_name,
                    VersioningConfiguration =
                    {
                    'Status': 'Enabled'
                    }
                )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Bucket versioning enabled: %s \n" % bucket_name
                
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