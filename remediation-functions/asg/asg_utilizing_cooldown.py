'''
Auto Scaling Groups to utilize cooldown periods
'''

from botocore.exceptions import ClientError

def run_remediation(autoscaling, AutoScalingGroupName):
    print("Executing autoscaling remediation")
    applied_cooldown = False
    current_cooldown = ''
    try:
        response = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[AutoScalingGroupName])['AutoScalingGroups']
        current_cooldown=response[0]['DefaultCooldown']
        if current_cooldown:
            applied_cooldown = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not applied_cooldown: 
        try:
            result = autoscaling.update_auto_scaling_group(AutoScalingGroupName=AutoScalingGroupName,DefaultCooldown=300)

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled asg to utilize cooldown periods : %s \n" % AutoScalingGroupName
                    
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