'''
AWS Kinesis Enhanced Monitoring
'''

from botocore.exceptions import ClientError

def run_remediation(kinesis, stream_name):
    print("Executing remediation")            

    enhanced_monitoring = False

    try:
        enhanced_monitoring_status = kinesis.describe_stream(StreamName=stream_name)['StreamDescription']['EnhancedMonitoring'][0]['ShardLevelMetrics']
        if enhanced_monitoring_status:
            enhanced_monitoring = True
    except:
        enhanced_monitoring = False    

    if not enhanced_monitoring:

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

