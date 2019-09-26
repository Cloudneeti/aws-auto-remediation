'''
Make bucket private
'''

from botocore.exceptions import ClientError

def run_remediation(s3_client, bucket_name):
    print("Executing remediation")            
            
    try:
        result = s3_client.put_bucket_acl(
                    Bucket=bucket_name,
                    ACL='private'
                )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Bucket is now private: %s \n" % bucket_name
                
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

