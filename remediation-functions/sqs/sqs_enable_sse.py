'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Enable sqs queue Server-Side Encryption
'''

from botocore.exceptions import ClientError

def run_remediation(sqs, queue_url):
    print("Executing sqs queue remediation")
    queue_not_enabled_sse = True
    
    #Verify sqs queue encryption
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
        #Enable sqs queue encryption   
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
    else:
        responseCode=200
        output='erver-Side Encryption already enabled for queue : '+queue_url
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output