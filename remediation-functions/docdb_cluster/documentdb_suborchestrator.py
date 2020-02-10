'''
docdb cluster sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from docdb_cluster import *

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
            docdb_clustername = event["DocdbClusterName"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            docdb = boto3.client('docdb', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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

        if "DocdbStorageEncrypted" in str(records):
            try:
                documentdb_defaultencryption.run_remediation(docdb,docdb_clustername)
                print('remediated-' + docdb_clustername)
                #returning the output Array in json format
                return {  
                    'statusCode': 200,
                    'body': json.dumps('remediated-' + docdb_clustername)
                }
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
        
        if "BackupRetentionPeriod" in str(records):
            try:
                documentdb_backup_retention.run_remediation(docdb,docdb_clustername)
                print('remediated-' + docdb_clustername)
                #returning the output Array in json format
                return {  
                    'statusCode': 200,
                    'body': json.dumps('remediated-' + docdb_clustername)
                }
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
        
        if "DocdbCloudWatchLogsEnabled" in str(records):    
            try:
                documentdb_logexport.run_remediation(docdb,docdb_clustername)
                print('remediated-' + docdb_clustername)
                #returning the output Array in json format
                return {  
                    'statusCode': 200,
                    'body': json.dumps('remediated-' + docdb_clustername)
                }
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
            docdb_clustername = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            docdb = boto3.client('docdb', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
            if PolicyId == "DocdbStorageEncrypted":  
                responseCode,output = documentdb_defaultencryption.run_remediation(docdb,docdb_clustername)
            
            if PolicyId == "BackupRetentionPeriod":  
                responseCode,output = documentdb_backup_retention.run_remediation(docdb,docdb_clustername)
            
            if PolicyId == "DocdbCloudWatchLogsEnabled":  
                responseCode,output = documentdb_logexport.run_remediation(docdb,docdb_clustername)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate docdb cluster: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate docdb cluster: " + str(e)

        # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }