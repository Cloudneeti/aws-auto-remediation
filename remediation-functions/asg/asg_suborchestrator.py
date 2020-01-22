'''
autoscaling sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from asg import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID, Region
    
    try:
        PolicyId = json.loads(event["body"])["PolicyId"]
    except:
        PolicyId = ''
        pass

    if not PolicyId:
        print("Executing auto-remediation")
        try:  # common code
            CustAccID, role_arn = common.getRoleArn_cwlogs(event)
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(role_arn)
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }

        try:
            Region = event["Region"]
            AutoScalingGroupName = event["AutoScalingGroupName"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            autoscaling = boto3.client('autoscaling', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }
        
        if "ASGCooldown" in str(records):
            try:
                autoscaling_continuous_backups.run_remediation(autoscaling,AutoScalingGroupName)
            except ClientError as e:
                print(e)
                return {  
                    'statusCode': 400,
                    'body': str(e)
                }
            except Exception as e:
                print(e)
                return {
                    'statusCode': 400,
                    'body': str(e)
                }   
        
        print('remediated-' + AutoScalingGroupName)
        #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps('remediated-' + AutoScalingGroupName)
        }

    else:
        print("CN-portal triggered remediation")
        try:
            CustAccID, role_arn = common.getRoleArn(event)
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(role_arn)
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }

        try:
            Region_name = json.loads(event["body"])["Region"]
            Region = common.getRegionName(Region_name)
            AutoScalingGroupName = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            autoscaling = boto3.client('autoscaling', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }

        try:
            if PolicyId == "ASGCooldown":  
                responseCode,output = autoscaling_continuous_backups.run_remediation(autoscaling,AutoScalingGroupName)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate asg: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate asg: " + str(e)

            # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }