'''
Cloudtrail sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from cloudtrail import *

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
            Trail = event["Trail"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            cloudtrail_client = boto3.client('cloudtrail', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
        
        if "CTMultiRegionTrail" in str(records):
            try:
                cloudtrail_enable_multi_region_trail.run_remediation(cloudtrail_client,Trail)
                print('remediated-' + Trail)
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
        
        if "CTLogFileValidation" in str(records):
            try:
                cloudtrail_enable_log_file_validation.run_remediation(cloudtrail_client,Trail)
                print('remediated-' + Trail)
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
        
        if "CTIsLogging" in str(records):
            try:
                cloudtrail_enable_trail_logging.run_remediation(cloudtrail_client,Trail)
                print('remediated-' + Trail)
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
            'body': json.dumps('remediated-' + Trail)
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
            Trail = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            cloudtrail_client = boto3.client('cloudtrail', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
            if PolicyId == "CTMultiRegionTrail":
                responseCode,output = cloudtrail_enable_multi_region_trail.run_remediation(cloudtrail_client,Trail)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate Cloudtrail: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate Cloudtrail: " + str(e)

        try:
            if PolicyId == "CTLogFileValidation":
                responseCode,output = cloudtrail_enable_log_file_validation.run_remediation(cloudtrail_client,Trail)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate Cloudtrail: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate Cloudtrail: " + str(e)
        
        try:
            if PolicyId == "CTIsLogging":
                responseCode,output = cloudtrail_enable_trail_logging.run_remediation(cloudtrail_client,Trail)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate Cloudtrail: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate Cloudtrail: " + str(e)

        # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }