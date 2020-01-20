'''
Enable sqs queue Server-Side Encryption
'''

from botocore.exceptions import ClientError

def run_remediation(sqs, queue_url):
    print("Executing sqs queue remediation")
    queue_not_enabled_sse = True
    try:
        response = sqs.get_queue_attributes(QueueUrl = queue_url, AttributeNames = ['All'])['Attributes']
        if response['KmsMasterKeyId']:
            queue_not_enabled_sse = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if queue_not_enabled_sse:   
        try:
            result = sqs.set_queue_attributes(QueueUrl=queue_url,Attributes={"KmsMasterKeyId": "alias/aws/sqs","KmsDataKeyReusePeriodSeconds": "300"})
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled Server-Side Encryption for SQS : %s \n" % queue_url
                    
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