'''
Enable detailed monitoring of ec2 instance
'''

from botocore.exceptions import ClientError

def run_remediation(ec2, Instance_name):
    print("Executing ec2 remediation")            

    detailed_monitoring = False
    try:
        response=ec2.describe_instances(InstanceIds=[Instance_name])['Reservations'][0]['Instances'][0]['Monitoring']  #review with lambda
        if response['State'] == 'enabled':
            detailed_monitoring = True
    except:
        detailed_monitoring=False

    if not detailed_monitoring:   
        try:
            result = ec2.monitor_instances(InstanceIds=[Instance_name])

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Detailed monitoring is enabled for ec2 instance : %s \n" % Instance_name
                    
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
        output="Detailed monitoring is already enabled for ec2 instance  : %s \n" % Instance_name

    print(str(responseCode)+'-'+output)
    return responseCode,output