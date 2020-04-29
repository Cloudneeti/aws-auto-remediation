'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
        for stack in range(len(Stacklist)): 
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