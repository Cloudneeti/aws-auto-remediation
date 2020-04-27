'''
neptune instance sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from neptune_instance import *

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
            neptune_name = event["NeptuneInstanceName"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            neptune = boto3.client('neptune', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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

        if "NeptuneAutoMinorVersionUpgrade" in str(records):
            try:
                neptuneinstance_minorversionupgrade.run_remediation(neptune,neptune_name)
                print('remediated-' + neptune_name)
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
        
        if "NeptuneCpoyTagsToSnapshots" in str(records):
            try:
                neptuneinstance_copytagstosnapshot.run_remediation(neptune,neptune_name)
                print('remediated-' + neptune_name)
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
        
        if "NeptunePrivateAccess" in str(records):
            try:
                neptuneinstance_disable_public_access.run_remediation(neptune,neptune_name)
                print('remediated-' + neptune_name)
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
        
        #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps('remediated-' + neptune_name)
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
            neptune_name = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            neptune = boto3.client('neptune', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
            if PolicyId == "NeptuneAutoMinorVersionUpgrade":  
                responseCode,output = neptuneinstance_minorversionupgrade.run_remediation(neptune,neptune_name)
                
            if PolicyId == "NeptuneCpoyTagsToSnapshots":  
                responseCode,output = neptuneinstance_copytagstosnapshot.run_remediation(neptune,neptune_name)
                
            if PolicyId == "NeptunePrivateAccess":  
                responseCode,output = neptuneinstance_disable_public_accessw.run_remediation(neptune,neptune_name)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate neptune: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate neptune: " + str(e)

        # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }
