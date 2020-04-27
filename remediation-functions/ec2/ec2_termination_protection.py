'''
Enable ec2 instance termination protection
'''

from botocore.exceptions import ClientError

def run_remediation(ec2, Instance_name):
    print("Executing ec2 remediation")            

    termination_protection=False
    try:
        response=ec2.describe_instance_attribute(Attribute='disableApiTermination',InstanceId=Instance_name)
        termination_protection=response['DisableApiTermination']['Value']
    except:
        termination_protection=False

    if not termination_protection:   
        try:
            result = ec2.modify_instance_attribute(InstanceId=Instance_name,DisableApiTermination={'Value': True})

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "termination protection is enabled for ec2 instance : %s \n" % Instance_name
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error : " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    else:
        responseCode=200
        output="termination protection is already enabled for ec2 instance  : %s \n" % Instance_name

    print(str(responseCode)+'-'+output)
    return responseCode,output