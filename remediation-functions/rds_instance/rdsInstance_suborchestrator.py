'''
RDS-instance sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from rds_instance import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID, Region
    
    try:
        PolicyId = json.loads(event["body"])["PolicyId"]
    except:
        PolicyId = ''
        pass

    #region CW Call
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
            RDSInstanceName = event["RDSInstanceName"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            rds = boto3.client('rds',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)
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
        
        if "RDSInstanceDeleteProtection" in str(records):
            try:
                rdsInstance_delete_protection.run_remediation(rds,RDSInstanceName)
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
        
        if "RDSPrivateInstance" in str(records):
            try:
                rdsInstance_disable_public_access.run_remediation(rds,RDSInstanceName)
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
        
        if ("RDSBackupRetentionPolicy" in str(records) or "RDSBackupTerm" in str(records)):
            try:
                rdsInstance_backupretention.run_remediation(rds,RDSInstanceName)
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
        
        print('remediated-' + RDSInstanceName)
        #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps('remediated-' + RDSInstanceName)
        }
    #endregion

    #region Portal Call
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
            RDSInstanceName = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            rds = boto3.client('rds',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)
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
            if PolicyId == "RDSInstanceDeleteProtection":
                responseCode,output = rdsInstance_delete_protection.run_remediation(rds,RDSInstanceName)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate RDS Instance: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate RDS Instance: " + str(e)

            # returning the output Array in json format
        
        try:
            if PolicyId == "RDSPrivateInstance":
                responseCode,output = rdsInstance_disable_public_access.run_remediation(rds,RDSInstanceName)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate RDS Instance: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate RDS Instance: " + str(e)
        
        try:
            if PolicyId in ["RDSBackupTerm", "RDSBackupRetentionPolicy"]:
                responseCode,output = rdsInstance_backupretention.run_remediation(rds,RDSInstanceName)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate RDS Instance: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate RDS Instance: " + str(e)
        
        return {  
            'statusCode': responseCode,
            'body': output
        }
    #endregion