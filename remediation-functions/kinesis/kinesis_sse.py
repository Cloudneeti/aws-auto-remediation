'''
AWS Kinesis Server Side Encryption
'''

from botocore.exceptions import ClientError

def run_remediation(kinesis, stream_name):
    print("Executing remediation")            

    encryption_status = False

    try:
        response = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']
        encryption_state = response['EncryptionType']
        if encryption_state != 'NONE':
            encryption_status = True
    except:
        encryption_status = False    

    if not encryption_status:
        #verify instance state  
        while response['StreamStatus'] not in ['ACTIVE']:
            try:
                response = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)

        try:
            result = kinesis.start_stream_encryption(
                        StreamName=stream_name,
                        EncryptionType='KMS',
                        KeyId='alias/aws/kinesis'
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Kinesis SSE enabled for : %s \n" % stream_name
                    
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
        output = "Kinesis SSE already enabled for : %s \n" % stream_name

    print(str(responseCode)+'-'+output)
    return responseCode,output

