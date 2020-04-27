'''
Enable Termination Protection feature for AWS CloudFormation stacks
'''

from botocore.exceptions import ClientError

def run_remediation(cloudformation, StackName):
    print("Executing cloudformation remediation")
    Stacklist = []
    termination_protection = False
    if StackName == '':
        stack_det = cloudformation.describe_stacks()['Stacks']
        for i in range(len(stack_det)):
            if not stack_det[i]['EnableTerminationProtection']:
                StackName = stack_det[i]['StackName']
                Stacklist.append(StackName)
        for stack in len(Stacklist): 
            try:
                result = cloudformation.update_termination_protection(EnableTerminationProtection=True, StackName=Stacklist[stack])

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "Enabled Termination Protection feature for CloudFormation stack : %s \n" % Stacklist[stack]
                        
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
    else:        
        try:
            response = cloudformation.describe_stacks(StackName=StackName)['Stacks']
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