'''
AWS Kinesis Server Side Encryption
'''

from botocore.exceptions import ClientError

def run_remediation(kinesis, stream_name):
    print("Executing remediation")            

    encryption_status = False

    try:
        encryption_state = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']['EncryptionType']
        if encryption_state != 'NONE':
            encryption_status = True
    except:
        encryption_status = False    

    if not encryption_status:

        try:
            result = kinesis.start_stream_encryption(
                        StreamName=stream_name,
                        EncryptionType='KMS',
                        KeyId='aws/kinesis'
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Redshift cluster is now private: %s \n" % stream_name
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)

    else:
        responseCode = 200
        output = "Kinesis already remediated"

    print(str(responseCode)+'-'+output)
    return responseCode,output

