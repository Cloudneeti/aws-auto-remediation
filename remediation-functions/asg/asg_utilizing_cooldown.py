'''
Auto Scaling Groups to utilize cooldown periods
'''

from botocore.exceptions import ClientError

def run_remediation(autoscaling, table_name):
    print("Executing autoscaling remediation")

    current_retention = ''

    try:
        response = autoscaling.describe_continuous_backups(TableName=table_name)['ContinuousBackupsDescription']
        current_retention=response[0]['ContinuousBackupsStatus']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not current_retention: 
        try:
            result = autoscaling..update_auto_scaling_group(AutoScalingGroupName='string',DefaultCooldown=300)

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled asg to utilize cooldown periods : %s \n" % table_name
                    
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
        output = "autoscaling groups are already utilizing cooldown periods"

    print(str(responseCode)+'-'+output)
    return responseCode,output