'''
RDS-cluster sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from rds_cluster import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID, Region
    auto_pause=["AuroraServerlessScalingAutoPause", "AuroraPostgresServerlessScalingAutoPause"]
    backup_retention=["AuroraBackup", "AuroraBackupTerm", "AuroraServerlessBackupTerm", "AuroraPostgresServerlessBackupTerm"]
    copytagstosnapshots=["AuroraCopyTagsToSnapshot", "AuroraServerlessCopyTagsToSnapshot", "AuroraPostgresServerlessCopyTagsToSnapshot"]
    deletion_protection=["AuroraDeleteProtection", "AuroraServerlessDeleteProtection", "AuroraPostgresServerlessDeleteProtection"]
    
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
            RDSClusterName = event["RDSClusterName"]
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

        if set(auto_pause).intersection(set(records)):
            try:
                rdscluster_autopause.run_remediation(rds,RDSClusterName)
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

        if set(backup_retention).intersection(set(records)):
            try:
                rdscluster_backupretention.run_remediation(rds,RDSClusterName)
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

        if set(copytagstosnapshots).intersection(set(records)):
            try:
                rdscluster_copytagstosnapshot.run_remediation(rds,RDSClusterName)
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
        
        if set(deletion_protection).intersection(set(records)):
            try:
                rdscluster_deletion_protection.run_remediation(rds,RDSClusterName)
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
        
        print('remediated-' + RDSClusterName)
        #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps('remediated-' + RDSClusterName)
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
            RDSClusterName = json.loads(event["body"])["ResourceName"]
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
            if PolicyId in auto_pause:
                responseCode,output = rdscluster_autopause.run_remediation(rds,RDSClusterName)

            if PolicyId in backup_retention:
                responseCode,output = rdscluster_backupretention.run_remediation(rds,RDSClusterName)
        
            if PolicyId in copytagstosnapshots:
                responseCode,output = rdscluster_copytagstosnapshot.run_remediation(rds,RDSClusterName)

            if PolicyId in deletion_protection:
                responseCode,output = rdscluster_deletion_protection.run_remediation(rds,RDSClusterName)
        
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