'''
RDS-snapshot sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from rds_snapshots import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID, Region
    snapshot_access=["RDSSnapshotNoPublicAccess"]
    
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
            print("assume-role"+str(e))
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
            RDSSnapshotName = event["RDSSnapshotName"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            rds = boto3.client('rds',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)
        except ClientError as e:
            print("rds-client"+str(e))
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

        if set(snapshot_access).intersection(set(records)):
            try:
                rdssnapshot_access.run_remediation(rds,RDSSnapshotName)
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
        
        print('remediated-' + RDSSnapshotName)
        #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps('remediated-' + RDSSnapshotName)
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
            RDSSnapshotName = json.loads(event["body"])["ResourceName"]
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
            if PolicyId in snapshot_access:
                responseCode,output = rdssnapshot_access.run_remediation(rds,RDSSnapshotName)
                
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate RDS cluster: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate RDS cluster: " + str(e)

            # returning the output Array in json format
        
        return {  
            'statusCode': responseCode,
            'body': output
        }
    #endregion