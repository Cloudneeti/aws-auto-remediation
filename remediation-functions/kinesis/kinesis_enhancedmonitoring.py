'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

AWS Kinesis Enhanced Monitoring
'''

from botocore.exceptions import ClientError

def run_remediation(kinesis, stream_name):
    print("Executing remediation")            

    enhanced_monitoring = False
    #Verify monitoring status
    try:
        response = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']
        enhanced_monitoring_status = response['EnhancedMonitoring'][0]['ShardLevelMetrics']
        if enhanced_monitoring_status:
            enhanced_monitoring = True
    except:
        enhanced_monitoring = False    

    if not enhanced_monitoring:
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
        #Enable monitoring status
        try:
            result = kinesis.enable_enhanced_monitoring(
                        StreamName=stream_name,
                        ShardLevelMetrics=['ALL']
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enhanced monitoring enabled for kinesis stream : %s \n" % stream_name
                    
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
        output = "Enhanced monitoring already enabled for kinesis stream : %s \n" % stream_name

    print(str(responseCode)+'-'+output)
    return responseCode,output

