'''
Enable Termination Protection feature for AWS CloudFormation stacks
'''

from botocore.exceptions import ClientError

def run_remediation(cloudformation, StackName):
    print("Executing cloudformation remediation")
    try:
        response = cloudformation.describe_stacks(StackName=StackName)['ContinuousBackupsDescription']
        termination_protection=response[0]['EnableTerminationProtection']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not termination_protection: 
        try:
            result = cloudformation.update_termination_protection(EnableTerminationProtection=True, StackName=StackName)

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled Termination Protection feature for CloudFormation stack : %s \n" % StackName
                    
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
        output = "CloudFormation stack is already compliant"

    print(str(responseCode)+'-'+output)
    return responseCode,output