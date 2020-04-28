'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Kinesis firhose default encryption
'''
import time
from botocore.exceptions import ClientError

def run_remediation(kinesis_firehose,delivery_stream_name):
    print("Executing remediation")            
    firhose_encryption = False
    #Verify current Encryption for delivery stream 
    try:
        response = kinesis_firehose.describe_delivery_stream(DeliveryStreamName=delivery_stream_name)['DeliveryStreamDescription']
        if response['DeliveryStreamEncryptionConfiguration'] == {'Status': 'ENABLED'}:
            firhose_encryption = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not firhose_encryption:
        #Apply Encryption to delivery stream                  
        try:
            result = kinesis_firehose.start_delivery_stream_encryption(
                        DeliveryStreamName = delivery_stream_name,
                        DeliveryStreamEncryptionConfigurationInput = {'KeyType': 'AWS_OWNED_CMK'}
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Encryption with aws kms will be enabled within 30-seconds for delivery stream : %s \n" % delivery_stream_name
                    
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
        output='Encryption with aws kms is already enabled for delivery stream : '+ delivery_stream_name
        print(output)
        
    print(str(responseCode)+'-'+output)
    return responseCode,output

