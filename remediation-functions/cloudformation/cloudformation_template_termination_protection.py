'''
Enable Termination Protection feature for AWS CloudFormation stacks
'''

from botocore.exceptions import ClientError

def run_remediation(cloudformation, table_name):
    print("Executing cloudformation remediation")

    current_retention = ''

    try:
        response = cloudformation.describe_continuous_backups(TableName=table_name)['ContinuousBackupsDescription']
        current_retention=response[0]['ContinuousBackupsStatus']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not current_retention: 
        try:
            result = cloudformation.update_termination_protection(EnableTerminationProtection=True, StackName='string')

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled Termination Protection feature for CloudFormation stack : %s \n" % table_name
                    
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