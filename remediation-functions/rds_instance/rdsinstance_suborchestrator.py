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
    backup_retention=["SQLBackup","SQLBackupTerm","MariadbBackup","MariadbBackupTerm","OracleBackup","OracleBackupTerm","SQLServerBackup","SQLServerBackupTerm"]
    copytagstosnapshot=["SQLCopyTagsToSnapshot","MariadbCopyTagsToSnapshot","OracleCopyTagsToSnapshot","SQLServerCopyTagsToSnapshot"]
    deletion_protection=["SQLDeletionProtection","MariadbDeletionProtection", "OracleDeletionProtection", "SQLServerDeletionProtection"]
    disable_public_access=["SQLPrivateInstance","MariadbPrivateInstance","OraclePrivateInstance","SQLServerPrivateInstance","AuroraInstancePrivateInstance"]
    minor_version=["SQLVersionUpgrade","MariadbVersionUpgrade","OracleVersionUpgrade","SQLServerVersionUpgrade","AuroraInstanceVersionUpgrade"]
    multiaz=["SQLMultiAZEnabled","MariadbMultiAZEnabled","OracleMultiAZEnabled","SQLServerMultiAZEnabled"]
    performance_insights=["SQLPerformanceInsights","MariadbPerformanceInsights","OraclePerformanceInsights","SQLServerPerformanceInsights","AuroraInstancePerformanceInsights"]
    
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

        if set(backup_retention).intersection(set(records)):
            try:
                rdsinstance_backupretention.run_remediation(rds,RDSInstanceName)
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

        if set(copytagstosnapshot).intersection(set(records)):
            try:
                rdsinstance_copytagstosnapshot.run_remediation(rds,RDSInstanceName)
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
                rdsinstance_deletion_protection.run_remediation(rds,RDSInstanceName)
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

        if set(disable_public_access).intersection(set(records)):
            try:
                rdsinstance_disable_public_access.run_remediation(rds,RDSInstanceName)
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

        if set(minor_version).intersection(set(records)):
            try:
                rdsinstance_minorversionupgrade.run_remediation(rds,RDSInstanceName)
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

        if set(multiaz).intersection(set(records)):
            try:
                rdsinstance_multizone.run_remediation(rds,RDSInstanceName)
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
        
        if set(performance_insights).intersection(set(records)):
            try:
                rdsinstance_performanceinsights.run_remediation(rds,RDSInstanceName)
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
            if PolicyId in backup_retention:
                responseCode,output = rdsinstance_backupretention.run_remediation(rds,RDSInstanceName)

            if PolicyId in copytagstosnapshot:
                responseCode,output = rdsinstance_copytagstosnapshot.run_remediation(rds,RDSInstanceName)

            if PolicyId in deletion_protection:
                responseCode,output = rdsinstance_deletion_protection.run_remediation(rds,RDSInstanceName)

            if PolicyId in disable_public_access:
                responseCode,output = rdsinstance_disable_public_access.run_remediation(rds,RDSInstanceName)

            if PolicyId in minor_version:
                responseCode,output = rdsinstance_minorversionupgrade.run_remediation(rds,RDSInstanceName)

            if PolicyId in multiaz:
                responseCode,output = rdsinstance_multizone.run_remediation(rds,RDSInstanceName)

            if PolicyId in performance_insights:
                responseCode,output = rdsinstance_performanceinsights.run_remediation(rds,RDSInstanceName)
        
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