'''
Ensure that S3 buckets are not publicly accessible
'''

from botocore.exceptions import ClientError

#def run_remediation(boto_session, rule, resource):
def run_remediation(s3_client, bucket_name):
    print("Executing remediation")

    try:
        result = s3_client.put_public_access_block(
                                            Bucket= bucket_name,
                                            PublicAccessBlockConfiguration={
                                                'BlockPublicAcls': True,
                                                'IgnorePublicAcls': True,
                                                'BlockPublicPolicy': True,
                                                'RestrictPublicBuckets': True
                                            }
                                        )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Block publicly access flags set to true for S3 Bucket : %s \n" % bucket_name

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