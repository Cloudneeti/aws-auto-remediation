'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Remediation orchestrator function
'''

import json
import boto3
import common
import hashlib
from botocore.exceptions import ClientError
import gzip
import base64
import os

def lambda_handler(event, context):
    cloudtrail_list = ["CTMultiRegionTrail", "CTLogFileValidation","CTIsLogging"]
    elb_list = ["ClassicLBConnDraining"]
    elbv2_list = ["AppLBDeletionProtection", "NetworkLBDeletionProtection"]
    iam_list = ["IAMPasswordRequiredNumber", "IAMPasswordUpCaseLetter", "IAMPasswordRequiredSymbols", "IAMRequireLowercaseLetter", "IAMMinPasswordLength", "IAMExpirePasswords", "IAMPasswordReusePrevention"]
    kinesis_list = ["KinesisEnhancedMonitoring", "KinesisSSE"]
    kms_list = ["KMSKeyRotation"]
    rds_cluster_list = ["AuroraDeleteProtection", "AuroraServerlessDeleteProtection", "AuroraPostgresServerlessDeleteProtection", "AuroraBackup", "AuroraBackupTerm", "AuroraServerlessBackupTerm", "AuroraPostgresServerlessBackupTerm", "AuroraCopyTagsToSnapshot", "AuroraServerlessCopyTagsToSnapshot", "AuroraPostgresServerlessCopyTagsToSnapshot", "AuroraServerlessScalingAutoPause", "AuroraPostgresServerlessScalingAutoPause","AuroralogExport","CloudwatchLogsExports", "AuroraIAMAuthEnabled"]
    rds_instance_list = ["SQLBackup","SQLBackupTerm","MariadbBackup","MariadbBackupTerm","OracleBackup","OracleBackupTerm","SQLServerBackup","SQLServerBackupTerm","SQLCopyTagsToSnapshot","MariadbCopyTagsToSnapshot","OracleCopyTagsToSnapshot","SQLServerCopyTagsToSnapshot","SQLDeletionProtection", "MariadbDeletionProtection", "OracleDeletionProtection", "SQLServerDeletionProtection", "SQLPrivateInstance","MariadbPrivateInstance","OraclePrivateInstance","SQLServerPrivateInstance","AuroraInstancePrivateInstance","SQLVersionUpgrade","MariadbVersionUpgrade","OracleVersionUpgrade","SQLServerVersionUpgrade","AuroraInstanceVersionUpgrade", "SQLMultiAZEnabled","MariadbMultiAZEnabled","OracleMultiAZEnabled","SQLServerMultiAZEnabled","SQLPerformanceInsights","MariadbPerformanceInsights","OraclePerformanceInsights","SQLServerPerformanceInsights","AuroraInstancePerformanceInsights","MySQLVersionUpgrade","MySQLBackup","MySQLBackupTerm","MySQLCopyTagsToSnapshot","MySQLDeletionProtection","MySQLPerformanceInsights","MySQLPrivateInstance","MySQLMultiAZEnabled","MySQLlogExport","MariadblogExport","OraclelogExport", "SQLIAMAuthEnabled", "MySQLIAMAuthEnabled","MySQLBlockEncryption","MySQLEnableFIPS"]
    redshift_list = ["RedShiftNotPublic", "RedShiftVersionUpgrade", "RedShiftAutomatedSnapshot"]
    neptune_instance_list = ["NeptuneAutoMinorVersionUpgrade","NeptuneCpoyTagsToSnapshots","NeptunePrivateAccess"]
    neptune_cluster_list = ["NeptuneBackupRetention","NeptuneClusterCloudWatchLogsEnabled","NeptuneIAMDbAuthEnabled"]
    s3_list = ["S3VersioningEnabled", "S3EncryptionEnabled", "S3bucketNoPublicAAUFull", "S3bucketNoPublicAAURead", "S3bucketNoPublicAAUReadACP", "S3bucketNoPublicAAUWrite", "S3bucketNoPublicAAUWriteACP", "S3notPublictoInternet", "S3notPublicRead", "S3notPublicReadACP", "S3notPublicWrite", "S3notPublicWriteACP","S3TransferAccelerateConfig","S3busketpublicaccess"]
    dynamodb_list = ["DynamoDbContinuousBackup"]
    ec2instance_list = ["EC2MonitoringState", "EC2TerminationProtection"]
    cloudformation_list = ["StackTermination"]
    asg_list = ["ASGCooldown"]
    sqs_list = ["SQSSSEEnabled"]
    rds_snapshot_list = ["RDSSnapshotNoPublicAccess"]
    docdb_cluster_list = ["DocDBBackupRetentionPeriod","DocDBCloudWatchLogsEnabled","DocDBDeletionProtection"]
    docdb_instance_list = ["DocDBInstanceAutoMinorVersionUpgrade"]
    fsx_windows_list = ["AWSFSxBackupRetentionPeriod","AWSFSxBackupRetentionDays"]
    kinesis_firehose_list = ["KinesisFirehoseEncryption"]
    
    try:
        runtime_region = os.environ['AWS_REGION']
    except:
        runtime_region = 'us-east-1'

    try:
        policy_list = json.loads(event['body'])['RemediationPolicies']
        policy_flag = 1
    except:
        policy_flag = 0
        pass

    try:
        PolicyId = json.loads(event["body"])["PolicyId"]
    except:
        PolicyId = ''
        pass

    try:
        cw_event_data = event['detail']
    except:
        cw_event_data = ''

    try:
        VerifyAccess = json.loads(event['body'])['VerifyAccess']
    except:
        VerifyAccess = ''
    
    #region Policy Discovery    
    if policy_flag:   
        try:  
            RemediationAWSAccountId = json.loads(event['body'])['RemediationAWSAccountId']
            RemAccHash = hashlib.md5(str(RemediationAWSAccountId).encode('utf-8')).hexdigest()
            s3Client = boto3.client('s3')
            buckets = s3Client.list_buckets()['Buckets']
            for i in range(len(buckets)):
                if RemAccHash in str(buckets[i]['Name']):
                    rem_bucket = buckets[i]['Name']
                    try:
                        s3Client.get_bucket_versioning(Bucket=rem_bucket)
                        break
                    except:
                        pass
        except ClientError as e: 
            print(e)
            return {
                'statusCode': 401,
                'body': json.dumps(str(e))
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 401,
                'body': json.dumps(str(e))
            }  
        # rem_bucket = 'zcspm-rem-cust-rem-acc'
        available_list = cloudtrail_list + elb_list + elbv2_list + iam_list + kinesis_list + kms_list + rds_cluster_list + rds_instance_list + redshift_list + s3_list + dynamodb_list + ec2instance_list + cloudformation_list + asg_list + sqs_list + neptune_instance_list + neptune_cluster_list + rds_snapshot_list + docdb_cluster_list + docdb_instance_list + fsx_windows_list + kinesis_firehose_list
            
        try:
            if set(policy_list) <= set(available_list): 
                RemediationData = json.loads(event['body'])
                AWSAccountId = json.loads(event['body'])["AWSAccountId"]

                hash_object = hashlib.sha256('{AWSAccountId}'.format(AWSAccountId = AWSAccountId).encode())
                hash_key = hash_object.hexdigest() 
                hash_key = 'policy_config/' + hash_key

                s3Client.put_object(Bucket=rem_bucket, Key=hash_key, Body=(bytes(json.dumps(RemediationData, indent=2).encode('UTF-8'))))
                return {
                    'statusCode': 200,
                    'body': json.dumps("Policies configured")
                }
    
            else:
                return {
                    'statusCode': 403,
                    'body': json.dumps("Update Remediation Framework")
                } #update remediation framework  

        except ClientError as e: 
            print(e)
            return {
                'statusCode': 401,
                'body': json.dumps(str(e))
            } 
        except Exception as e:
            print(e)
            return {
                'statusCode': 401,
                'body': json.dumps(str(e))
            } 
    #endregion    

    #region Auto-remediation
    elif cw_event_data:
        try:
            records = ""
            AWSAccId = cw_event_data["userIdentity"]["accountId"]
            EventName = cw_event_data["eventName"]
            EventSource = cw_event_data["userIdentity"]["arn"]
        except ClientError as e: 
            print(e)
            return {
                'statusCode': 401,
                'body': json.dumps(str(e))
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 401,
                'body': json.dumps(str(e))
            }
            
        try:
            sts = boto3.client('sts')
            RemediationAWSAccountId = sts.get_caller_identity()['Account']
        except:
            RemediationAWSAccountId = AWSAccId
        
        if "assumed-role/ZCSPM-Auto-Remediation-Role" not in str(EventSource):    
            try:
                hash_object = hashlib.sha256('{AWSAccId}'.format(AWSAccId = AWSAccId).encode())
                hash_key = hash_object.hexdigest()
                hash_key = 'policy_config/' + hash_key
            except ClientError as e:
                print(e)
                return {
                    'statusCode': 401,
                    'body': json.dumps(str(e))
                }
            except Exception as e:
                print(e)
                return {
                    'statusCode': 401,
                    'body': json.dumps(str(e))
                }
    
            try:
                s3Client = boto3.client('s3')
                buckets = s3Client.list_buckets()['Buckets']
                RemAccHash = hashlib.md5(str(RemediationAWSAccountId).encode('utf-8')).hexdigest()
                for i in range(len(buckets)):
                    if RemAccHash in str(buckets[i]['Name']):
                        rem_bucket = buckets[i]['Name']
                        try:
                            s3Client.get_bucket_versioning(Bucket=rem_bucket)
                            break
                        except:
                            pass                
                # SQL="select s.RemediationPolicies from s3object s where s.AWSAccountId = '" + cust_acc + "'"
                SQL="select s.RemediationPolicies from s3object s"
                data = s3Client.select_object_content(
                Bucket=rem_bucket,
                Key=hash_key,
                ExpressionType='SQL',
                Expression=SQL,
                InputSerialization = { 'CompressionType': 'NONE','JSON': {'Type': 'DOCUMENT'}},
                OutputSerialization = {'JSON': { 'RecordDelimiter': '\n',}}
                )
                
                for event in data['Payload']:
                    if 'Records' in event:
                        records = event['Records']['Payload'].decode('utf-8')
            except ClientError as e:
                print(e)            
                return {
                    'statusCode': 400,
                    'body': json.dumps(str(e))
                }
            except Exception as e:
                print(e)
                return {
                    'statusCode': 400,
                    'body': json.dumps(str(e))
                }
            
            if records:
                try:
                    invokeLambda = boto3.client('lambda', region_name=runtime_region)
    
                except ClientError as e: 
                    print(e)
                    return {
                        'statusCode': 401,
                        'body': json.dumps('Error during remediation, error:' + str(e))
                    } 
                except Exception as e:
                    print(e)
                    return {
                        'statusCode': 401,
                        'body': json.dumps('Error during remediation, error:' + str(e))
                    }

                #region cloudtrail sub-orchestrator call
                if EventName in ["CreateTrail", "UpdateTrail", "StopLogging"]:
                    try:
                        if EventName == "StopLogging":
                            TrailARN = cw_event_data["requestParameters"]["name"] #ARN captured as name in this event
                            Trail = TrailARN.split('/')[1]
                        else:
                            Trail = cw_event_data["responseElements"]["name"]
                        Region = cw_event_data["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "Trail": Trail,
                            "Region" : Region,
                            "policies": records
                        }
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-cloudtrail', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #region load-balancer sub-orchestrator call
                if EventName in ["CreateLoadBalancer", "ModifyLoadBalancerAttributes"]:
                    if EventName == "CreateLoadBalancer":
                        try:
                            lb_detail=cw_event_data["requestParameters"]["type"]
                            if lb_detail in ["application", "network"]:
                                lb_type='elbv2'
                            else:
                                lb_type='elb'
                        except:
                            lb_type='elb'
                    else:
                        try:
                            lb_attributes=cw_event_data["requestParameters"]["attributes"]
                            lb_type='elbv2'
                        except:
                            lb_type='elb'

                    if lb_type == 'elbv2':
                        try:
                            if EventName == "CreateLoadBalancer":
                                LoadBalancerArn = cw_event_data["responseElements"]["loadBalancers"][0]["loadBalancerArn"]
                            else:
                                LoadBalancerArn = cw_event_data["requestParameters"]["loadBalancerArn"]
                                
                            Region = cw_event_data["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "LoadBalancerArn": LoadBalancerArn,
                                "Region" : Region,
                                "policies": records
                            }
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-elbv2', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))

                    else:
                        try:
                            LoadBalancerName = cw_event_data["requestParameters"]["loadBalancerName"]
                            Region = cw_event_data["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "LoadBalancerName": LoadBalancerName,
                                "Region" : Region,
                                "policies": records
                            }
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-elb', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))
                #endregion

                #region IAM sub-orchestrator call
                if EventName in ["UpdateAccountPasswordPolicy", "DeleteAccountPasswordPolicy"]:
                    try:
                        remediationObj = {
                            "accountId": AWSAccId,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-iam', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #region Kinesis sub-orchestrator call
                if EventName in ["CreateStream", "StopStreamEncryption", "DisableEnhancedMonitoring"]:
                    try:
                        kinesis_stream = cw_event_data["requestParameters"]["streamName"]
                        Region = cw_event_data["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "kinesis_stream": kinesis_stream,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-kinesis', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #region kms suborchestrator invocation
                if EventName in ["CreateKey", "DisableKeyRotation"]:
                    try:
                        KeyId = cw_event_data["responseElements"]["keyMetadata"]["keyId"]
                        Region = cw_event_data["awsRegion"]
                    except:
                        KeyId = cw_event_data["requestParameters"]["keyId"]
                        Region = cw_event_data["awsRegion"]

                    try: 
                        remediationObj = {
                            "accountId": AWSAccId,
                            "KeyId": KeyId,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-kms', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #region redshift sub-orchestrator call
                if EventName in ["CreateCluster", "ModifyCluster"]:
                    try:
                        redshift = cw_event_data["requestParameters"]["clusterIdentifier"]
                        Region = cw_event_data["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "redshift": redshift,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-redshift', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #region S3 sub-orchestrator call
                if EventName in ["CreateBucket", "PutBucketAcl", "DeleteBucketEncryption", "PutBucketVersioning", "PutBucketPublicAccessBlock", "PutAccelerateConfiguration","PutBucketLogging"]:
                    try:
                        bucket = cw_event_data["requestParameters"]["bucketName"]
                        Region = cw_event_data["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "bucket": bucket,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-s3-bucket', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion
                
                #region neptune cluster suborchestrator call
                if EventName in ["CreateDBCluster", "ModifyDBCluster"]:
                    try:
                        DBEngine=cw_event_data["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'neptune' in str(DBEngine):
                        try:
                            NeptuneClusterName = cw_event_data["responseElements"]["dBClusterIdentifier"]
                            Region = cw_event_data["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "NeptuneClusterName": NeptuneClusterName,
                                "Region" : Region,
                                "policies": records
                            }
                            
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-neptune-cluster', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))
                #endregion

                #region Neptune instance suborchestrator call
                if EventName in ["CreateDBInstance", "ModifyDBInstance"]:
                    try:
                        DBEngine=cw_event_data["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'neptune' in str(DBEngine):
                        try:
                            NeptuneInstanceName = cw_event_data["responseElements"]["dBInstanceIdentifier"]
                            Region = cw_event_data["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "NeptuneInstanceName": NeptuneInstanceName,
                                "Region" : Region,
                                "policies": records
                            }
                            
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-neptune-instance', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))
                #endregion
                
                #region dynamodb suborchestrator call
                if EventName in ["CreateTable", "CreateTableReplica", "RestoreTableFromBackup", "UpdateTable", "UpdateContinuousBackups"]:
                    try:
                        DynamodbTableName = cw_event_data["requestParameters"]["tableName"]
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "DynamodbTableName": DynamodbTableName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-dynamodb', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #region asg suborchestrator call
                if EventName in ["UpdateAutoScalingGroup","CreateAutoScalingGroup"]:
                    try:
                        AutoScalingGroupName = cw_event_data["requestParameters"]["autoScalingGroupName"]
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "AutoScalingGroupName": AutoScalingGroupName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-asg', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion
                
                #region cloudformation suborchestrator call
                if EventName in ["CreateStack","UpdateStack","UpdateTerminationProtection"]:
                    try:
                        try:
                            StackName = cw_event_data["requestParameters"]["stackName"]
                        except:
                            StackName = ''
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "StackName": StackName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-cloudformation', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion
                
                #region ec2 instance suborchestrator call
                if EventName in ["RunInstances", "StartInstances", "ModifyInstanceAttribute","UnmonitorInstances"]:
                    try:
                        if EventName == "ModifyInstanceAttribute":
                            InstanceID = cw_event_data["requestParameters"]["instanceId"]
                        else:
                            InstanceID = cw_event_data["responseElements"]["instancesSet"]["items"][0]["instanceId"]
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "InstanceID": InstanceID,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-ec2-instance', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #sqs sub-orchestrator call
                if EventName in ["CreateQueue", "SetQueueAttributes"]:
                    try:
                        Queue_Url = cw_event_data["requestParameters"]["queueUrl"]
                        Region = cw_event_data["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "QueueUrl": Queue_Url,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-sqs', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion

                #rds-snapshot sub-orchestrator call
                if EventName in ["ModifyDBClusterSnapshotAttribute", "ModifyDBSnapshotAttribute"]:
                    try:
                        if EventName == "ModifyDBClusterSnapshotAttribute":
                            RDSSnapshotName = cw_event_data["responseElements"]["dBClusterSnapshotIdentifier"]
                        else:
                            RDSSnapshotName = cw_event_data["responseElements"]["dBSnapshotIdentifier"]
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "RDSSnapshotName": RDSSnapshotName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-rdssnapshot', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion
                
                #region documentdb cluster suborchestrator call
                if EventName in ["CreateDBCluster", "ModifyDBCluster"]:
                    try:
                        DBEngine=cw_event_data["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'docdb' in str(DBEngine):
                        return {
                                'statusCode': 200,
                                'body': json.dumps("Documentdb policies are not fully supported yet")
                            }
                        '''
                        try:
                            DocdbClusterName = cw_event_data["responseElements"]["dBClusterIdentifier"]
                            Region = cw_event_data["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "DocdbClusterName": DocdbClusterName,
                                "Region" : Region,
                                "policies": records
                            }
                            
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-documentdb-cluster', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))
                        '''
                #endregion
                
                #region documentdb instance suborchestrator call
                if EventName in ["CreateDBInstance","ModifyDBInstance"]:
                    try:
                        DBEngine=cw_event_data["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'docdb' in str(DBEngine):
                        return {
                                'statusCode': 200,
                                'body': json.dumps("Documentdb policies are not fully supported yet")
                            }
                        '''
                        try:
                            DocdbInstanceName = cw_event_data["responseElements"]["dBInstanceIdentifier"]
                            Region = cw_event_data["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "DocdbInstanceName": DocdbInstanceName,
                                "Region" : Region,
                                "policies": records
                            }
                            
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-documentdb-instance', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))
                        '''
                #endregion
                
                #region rds cluster suborchestrator call
                if EventName in ["CreateDBCluster", "ModifyDBCluster", "CreateDBInstance"]:
                    try:
                        DBEngine=cw_event_data["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'aurora' in str(DBEngine):
                        try:
                            print("started rds cluster lambda invocation")
                            RDSClusterName = cw_event_data["responseElements"]["dBClusterIdentifier"]
                            Region = cw_event_data["awsRegion"]
                            remediationObj = {
                                "accountId": AWSAccId,
                                "RDSClusterName": RDSClusterName,
                                "Region" : Region,
                                "policies": records
                            }
                            
                            response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-rdscluster', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                            response = json.loads(response['Payload'].read())
                            print(response)
                            return {
                                'statusCode': 200,
                                'body': json.dumps(response)
                            }
                        except ClientError as e:
                            print('Error during remediation, error:' + str(e))
                        except Exception as e:
                            print('Error during remediation, error:' + str(e))
                #endregion

                #region rds instance suborchestrator call
                if EventName in ["CreateDBInstance", "ModifyDBInstance", "ModifyDBParameterGroup"]:
                    try:
                        print("started rds instance lambda invocation")
                        RDSInstanceName = cw_event_data["responseElements"]["dBInstanceIdentifier"]
                        Region = cw_event_data["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "RDSInstanceName": RDSInstanceName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-rdsinstance', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion
                
                #region fsx windows suborchestrator call
                if EventName in ["UpdateFilesystem"]:
                    try:
                        FilesystemID = cw_event_data["requestParameters"]["fileSystemId"]
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "FilesystemID": FilesystemID,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-fsx-windows', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion
                
                #region kinesis firehose suborchestrator call
                if EventName in ["StopDeliveryStreamEncryption"]:
                    try:
                        StreamName = cw_event_data["requestParameters"]["deliveryStreamName"]
                        Region = cw_event_data["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "StreamName": StreamName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-kinesis-firehose', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
                        response = json.loads(response['Payload'].read())
                        print(response)
                        return {
                            'statusCode': 200,
                            'body': json.dumps(response)
                        }
                    except ClientError as e:
                        print('Error during remediation, error:' + str(e))
                    except Exception as e:
                        print('Error during remediation, error:' + str(e))
                #endregion            
                
            else:
                print("Policies not configured for remediation")
                return {
                    'statusCode': 200,
                    'body': json.dumps("Policies not configured for remediation")
                }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps("Resource already remediated!")
            }
    #endregion
            
    #region Verify-Access
    elif VerifyAccess:       
        OrchestartorAccess, RelayAccess = (True,)*2

        try:
            AWSAccId = json.loads(event['body'])['AWSAccountId']
            RemAccId = json.loads(event['body'])['RemediationAWSAccountId']
        except:
            pass
            
        if RemAccId != AWSAccId:            
        
            try:
                cust_accid, remdiationfunc_rolearn = common.getRoleArn(event)      
                aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(remdiationfunc_rolearn)
            except:
                OrchestartorAccess = False
            
            try:
                invokeLambda = boto3.client('lambda',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name=runtime_region)
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-auto-remediate-invoker', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                RelayAccess = json.loads(response['Payload'].read())
            except:
                RelayAccess = False                
        
        else:   
            try: 
                cust_accid, remdiatoracc_rolearn = common.getRoleArn(event)      
                common.getCredentials(remdiatoracc_rolearn)
            except:
                OrchestartorAccess = False
                
        return [RelayAccess, OrchestartorAccess]
    #endregion

    #region ZCSPM Portal Triggered remediation
    else:  
        try:  
            invokeLambda = boto3.client('lambda', region_name=runtime_region)
        except ClientError as e:
            print(e)
            response = {
                        'statusCode' : 400,
                        'body' : str(e)
                    }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': json.dumps(str(e))
            }

        #region cloudtrail suborchestrator call
        if PolicyId in (cloudtrail_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-cloudtrail', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region elb suborchestrator call
        if PolicyId in (elb_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-elb', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region elb suborchestrator call
        if PolicyId in (elbv2_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-elbv2', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region IAM sub-orchestrator call
        if PolicyId in (iam_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-iam', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
                response = {
                            'statusCode' : 401,
                            'body' : str(e)
                        }
            except Exception as e:
                print('Error during remediation, error:' + str(e))
                return {
                    'statusCode': 401,
                    'body': str(e)
                }
        #endregion

        #region Kinesis sub-orchestrator call
        if PolicyId in (kinesis_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-kinesis', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
                response = {
                            'statusCode' : 401,
                            'body' : str(e)
                        }
            except Exception as e:
                print('Error during remediation, error:' + str(e))
                return {
                    'statusCode': 401,
                    'body': str(e)
                }
        #endregion

        #region kms suborchestrator call
        if PolicyId in (kms_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-kms', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region rds cluster suborchestrator call
        if PolicyId in (rds_cluster_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-rdscluster', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region rds instance suborchestrator call
        if PolicyId in (rds_instance_list):
            try:        
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-rdsinstance', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region Redshift sub-orchestrator call
        if PolicyId in (redshift_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-redshift', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
                response = {
                            'statusCode' : 401,
                            'body' : str(e)
                        }
            except Exception as e:
                print('Error during remediation, error:' + str(e))
                return {
                    'statusCode': 401,
                    'body': str(e)
                }
        #endregion

        #region S3 sub-orchestrator call
        if PolicyId in str(s3_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-s3-bucket', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
                response = {
                            'statusCode' : 401,
                            'body' : str(e)
                        }
            except Exception as e:
                print(e)
                return {
                    'statusCode': 401,
                    'body': str(e)
                }
        #endregion
        
        #region rds cluster suborchestrator call
        if PolicyId in (dynamodb_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-dynamodb', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
        
        #region ec2 suborchestrator call
        if PolicyId in (ec2instance_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-ec2-instance', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
        
        #region cloudformation suborchestrator call
        if PolicyId in (cloudformation_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-cloudformation', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
        
        #region asg suborchestrator call
        if PolicyId in (asg_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-asg', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
        
        #region sqs suborchestrator call
        if PolicyId in (sqs_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-sqs', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
        
        #region neptune cluster suborchestrator call
        if PolicyId in (neptune_instance_list):
            try:            
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-neptune-instance', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion

        #region neptune instance suborchestrator call
        if PolicyId in (neptune_cluster_list):
            try:        
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-neptune-cluster', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
        
        #region neptune instance suborchestrator call
        if PolicyId in (rds_snapshot_list):
            try:        
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-remediate-rdssnapshot', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                response = json.loads(response['Payload'].read())
                print(response)
            except ClientError as e:
                print('Error during remediation, error:' + str(e))
            except Exception as e:
                print('Error during remediation, error:' + str(e))
        #endregion
                            
        return {
            'statusCode': response['statusCode'],
            'body': response['body']
        }
        