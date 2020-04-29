'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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

