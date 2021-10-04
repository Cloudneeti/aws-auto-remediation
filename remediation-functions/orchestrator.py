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

def resource_exclusion(excludedResource_hashkey, resourceId ):
    try:        
        envPrefix = os.environ['envPrefix']
    except:
        envPrefix = ''
        pass
    
    try:
        rem_bucket = 'zcspm-rem-'+envPrefix              
        s3Client = boto3.client('s3')
    except Exception as e:
        return {
            'statusCode': 401,
            'body': json.dumps(str(e))
        }
    
    try:
        SQL="select * from s3object"
        data = s3Client.select_object_content(
        Bucket=rem_bucket,
        Key=excludedResource_hashkey,
        ExpressionType='SQL',
        Expression=SQL,
        InputSerialization = { 'CompressionType': 'NONE','JSON': {'Type': 'DOCUMENT'}},
        OutputSerialization = {'JSON': { 'RecordDelimiter': '\n',}}
        )
        
        for event in data['Payload']:
            if 'Records' in event:
                resourceData = event['Records']['Payload'].decode('utf-8')

        excludedResourceList = json.loads(resourceData)
    except:
        excludedResourceList = ''
        pass

    try:
        resourceTypeExclusion = excludedResourceList['all']
    except:
        resourceTypeExclusion = False

    try:
        isExcluded = excludedResourceList[resourceId]
    except:
        isExcluded = False

    if resourceTypeExclusion or isExcluded:
        return True
    else:
        return False

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
        primary_region = os.environ['AWS_REGION']
    except:
        primary_region = 'us-east-1'

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

    try:
        excludedResourceList = json.loads(event['body'])['excludedResourceList']
    except:
        excludedResourceList = ''

    try:        
        envPrefix = os.environ['envPrefix']
    except:
        envPrefix = ''
        pass
    
    #region Policy Discovery    
    if policy_flag and envPrefix:
        try:
            rem_bucket = 'zcspm-rem-'+envPrefix              
            s3Client = boto3.client('s3')
            s3Client.get_bucket_versioning(Bucket=rem_bucket)
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

    #region Resource Exclusion    
    if excludedResourceList and envPrefix:
        try:
            rem_bucket = 'zcspm-rem-'+envPrefix              
            s3Client = boto3.client('s3')
            s3Client.get_bucket_versioning(Bucket=rem_bucket)
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
            AWSAccountId = json.loads(event['body'])["AWSAccountId"]

            hash_object = hashlib.sha256('{AWSAccountId}'.format(AWSAccountId = AWSAccountId).encode())
            hash_key = hash_object.hexdigest() 
            hash_key = 'excludedResourceConfig/' + hash_key + '/'  + list(excludedResourceList.keys())[0]

            s3Client.put_object(Bucket=rem_bucket, Key=hash_key, Body=(bytes(json.dumps(excludedResourceList[list(excludedResourceList.keys())[0]], indent=2).encode('UTF-8'))))
            return {
                'statusCode': 200,
                'body': json.dumps("Updated Resource Exclusion data")
            }

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
    elif cw_event_data and envPrefix:
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
        
        if "assumed-role/ZCSPM-Auto-Remediation-Role" not in str(EventSource):    
            try:
                hash_object = hashlib.sha256('{AWSAccId}'.format(AWSAccId = AWSAccId).encode())
                hash_key = hash_object.hexdigest()
                policyconfig_hashkey = 'policy_config/' + hash_key
            except Exception as e:
                print(e)
                return {
                    'statusCode': 401,
                    'body': json.dumps(str(e))
                }
    
            try:
                rem_bucket = 'zcspm-rem-'+envPrefix              
                s3Client = boto3.client('s3')
                s3Client.get_bucket_versioning(Bucket=rem_bucket)

                SQL="select s.RemediationPolicies from s3object s"
                data = s3Client.select_object_content(
                Bucket=rem_bucket,
                Key=policyconfig_hashkey,
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
                    invokeLambda = boto3.client('lambda', region_name=primary_region)
    
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::CloudTrail::Trail'
                            isExcluded = resource_exclusion(excludedResource_hashkey, Trail)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(Trail) + ' is excluded from auto-remediation.')
                        else:
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
                            cw_event_data["requestParameters"]["attributes"]
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

                            try:                            
                                excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::ElasticLoadBalancingV2::LoadBalancer'
                                isExcluded = resource_exclusion(excludedResource_hashkey, LoadBalancerArn)
                            except:
                                isExcluded = ''

                            if isExcluded:
                                print('Resource: ' + str(LoadBalancerArn) + ' is excluded from auto-remediation.')
                            else:
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

                            try:                            
                                excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::ElasticLoadBalancing::LoadBalancer'
                                isExcluded = resource_exclusion(excludedResource_hashkey, LoadBalancerName)
                            except:
                                isExcluded = ''

                            if isExcluded:
                                print('Resource: ' + str(LoadBalancerName) + ' is excluded from auto-remediation.')
                            else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::Kinesis::Stream'
                            isExcluded = resource_exclusion(excludedResource_hashkey, kinesis_stream)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(kinesis_stream) + ' is excluded from auto-remediation.')
                        else:
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
                        excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::KMS::Key'
                        isExcluded = resource_exclusion(excludedResource_hashkey, KeyId)
                    except:
                        isExcluded = ''

                    if isExcluded:
                        print('Resource: ' + str(KeyId) + ' is excluded from auto-remediation.')
                    else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::Redshift::Cluster'
                            isExcluded = resource_exclusion(excludedResource_hashkey, redshift)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(redshift) + ' is excluded from auto-remediation.')
                        else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::S3::Bucket'
                            isExcluded = resource_exclusion(excludedResource_hashkey, bucket)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(bucket) + ' is excluded from auto-remediation.')
                        else:
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

                            try:                            
                                excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::Neptune::DBCluster'
                                isExcluded = resource_exclusion(excludedResource_hashkey, NeptuneClusterName)
                            except:
                                isExcluded = ''

                            if isExcluded:
                                print('Resource: ' + str(NeptuneClusterName) + ' is excluded from auto-remediation.')
                            else:
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

                            try:                            
                                excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::Neptune::DBInstance'
                                isExcluded = resource_exclusion(excludedResource_hashkey, NeptuneInstanceName)
                            except:
                                isExcluded = ''

                            if isExcluded:
                                print('Resource: ' + str(NeptuneInstanceName) + ' is excluded from auto-remediation.')
                            else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::DynamoDB::Table'
                            isExcluded = resource_exclusion(excludedResource_hashkey, DynamodbTableName)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(DynamodbTableName) + ' is excluded from auto-remediation.')
                        else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::AutoScaling::AutoScalingGroup'
                            isExcluded = resource_exclusion(excludedResource_hashkey, AutoScalingGroupName)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(AutoScalingGroupName) + ' is excluded from auto-remediation.')
                        else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::CloudFormation::Stack'
                            isExcluded = resource_exclusion(excludedResource_hashkey, StackName)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(StackName) + ' is excluded from auto-remediation.')
                        else:
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
                        try:
                            if EventName == "ModifyInstanceAttribute":
                                InstanceID = cw_event_data["requestParameters"]["instanceId"]
                            else:
                                InstanceID = cw_event_data["responseElements"]["instancesSet"]["items"][0]["instanceId"]
                        except:
                            return {
                                'statusCode': 400,
                                'body': json.dumps("EC2 Event: "+EventName+" not supported due to lack of data")
                            }

                        Region = cw_event_data["awsRegion"]

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::EC2::Instance'
                            isExcluded = resource_exclusion(excludedResource_hashkey, InstanceID)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(InstanceID) + ' is excluded from auto-remediation.')
                        else:
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
                    except:
                        Queue_Url = cw_event_data["responseElements"]["queueUrl"]
                    
                    Region = cw_event_data["awsRegion"]

                    try:                            
                        excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::SQS::Queue'
                        isExcluded = resource_exclusion(excludedResource_hashkey, Queue_Url)
                    except:
                        isExcluded = ''

                    if isExcluded:
                        print('Resource: ' + str(Queue_Url) + ' is excluded from auto-remediation.')
                    else:
                        remediationObj = {
                            "accountId": AWSAccId,
                            "QueueUrl": Queue_Url,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        try:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::RDS::Snapshot'
                            isExcluded = resource_exclusion(excludedResource_hashkey, RDSSnapshotName)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(RDSSnapshotName) + ' is excluded from auto-remediation.')
                        else:
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
                if EventName in ["CreateDBCluster", "ModifyDBCluster"]:
                    try:
                        DBEngine=cw_event_data["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'aurora' in str(DBEngine):
                        try:
                            RDSClusterName = cw_event_data["responseElements"]["dBClusterIdentifier"]
                            Region = cw_event_data["awsRegion"]

                            try:                            
                                excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::RDS::DBCluster::Aurora'
                                isExcluded = resource_exclusion(excludedResource_hashkey, RDSClusterName)
                            except:
                                isExcluded = ''

                            if isExcluded:
                                print('Resource: ' + str(RDSClusterName) + ' is excluded from auto-remediation.')
                            else:
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

                        try:
                            DBEngine=cw_event_data["responseElements"]["engine"]
                        except:
                            DBEngine=''

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::RDS::DBInstance'
                            isExcluded = resource_exclusion(excludedResource_hashkey, RDSInstanceName)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(RDSInstanceName) + ' is excluded from auto-remediation.')
                        else:
                            remediationObj = {
                                "accountId": AWSAccId,
                                "RDSInstanceName": RDSInstanceName,
                                "Region" : Region,
                                "policies": records,
                                "Engine":DBEngine
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::FSx::FileSystem'
                            isExcluded = resource_exclusion(excludedResource_hashkey, FilesystemID)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(FilesystemID) + ' is excluded from auto-remediation.')
                        else:
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

                        try:                            
                            excludedResource_hashkey = 'excludedResourceConfig/' + hash_key + '/AWS::KinesisFirehose::DeliveryStream'
                            isExcluded = resource_exclusion(excludedResource_hashkey, StreamName)
                        except:
                            isExcluded = ''

                        if isExcluded:
                            print('Resource: ' + str(StreamName) + ' is excluded from auto-remediation.')
                        else:
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
    elif VerifyAccess and envPrefix:       
        OrchestartorAccess, RelayAccess = (True,)*2
        cloudtrailStatus, frameworkStackStatus = (False,)*2

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

            invokerAccountVariable = 'invoker_region_' + str(cust_accid) 
            try:
                invoker_region=os.environ[invokerAccountVariable]
            except:
                invoker_region=''
                
            if not invoker_region:
                regions=[]
                enabled_regions = []
                session = boto3.session.Session()
                
                regions = session.get_available_regions('lambda')
                
                for region in regions:
                    sts_client = session.client('sts', region_name=region)
                    try:
                        sts_client.get_caller_identity()
                        enabled_regions.append(region)
                    except:
                        pass
                
                for region in enabled_regions:           
                    invoker_client = boto3.client('cloudtrail', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name=region)
                    try:
                        cloudtrailStatus = invoker_client.get_trail_status(Name='zcspm-remediation-trail')['IsLogging']
                        if cloudtrailStatus:
                            invoker_region=region
                            break
                    except:
                        cloudtrailStatus = False
                        pass

                try:
                    lambda_client = boto3.client('lambda')
                    env_variables=lambda_client.get_function_configuration(FunctionName='zcspm-aws-remediate-orchestrator')['Environment']['Variables']
                    env_variables[invokerAccountVariable]=invoker_region
                    lambda_client.update_function_configuration(FunctionName='zcspm-aws-remediate-orchestrator', Environment={'Variables': env_variables})                
                except Exception as e:
                    return {'statusCode': 400,'body': json.dumps(str(e))}

            try:
                invokeLambda = boto3.client('lambda',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name=invoker_region)
                response = invokeLambda.invoke(FunctionName = 'zcspm-aws-auto-remediate-invoker', InvocationType = 'RequestResponse', Payload = json.dumps(event))
                RelayAccess = json.loads(response['Payload'].read())
            except:
                RelayAccess = False
                
            try:
                ct_client = boto3.client('cloudtrail', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name=invoker_region)
                cloudtrailStatus = ct_client.get_trail_status(Name='zcspm-remediation-trail')['IsLogging']
            except:
                cloudtrailStatus = False
        
        else:   
            try: 
                cust_accid, remdiatoracc_rolearn = common.getRoleArn(event)      
                common.getCredentials(remdiatoracc_rolearn)
            except:
                OrchestartorAccess = False
                
            try:
                cloudtrail_client = boto3.client('cloudtrail', region_name=primary_region)
                cloudtrailStatus = cloudtrail_client.get_trail_status(Name='zcspm-remediation-trail')['IsLogging']
            except:
                cloudtrailStatus = False
                pass

        try:
            frameworkVersion = os.environ['Version']
        except:
            frameworkVersion = '2.3'

        try:
            StackName = 'zcspm-rem-functions-' + envPrefix
            stack_client = boto3.client('cloudformation', region_name=primary_region)
            StackStatus=stack_client.describe_stacks(StackName=StackName)['Stacks'][0]['StackStatus']
            if StackStatus in ['CREATE_COMPLETE','UPDATE_COMPLETE']:
                frameworkStackStatus = True
        except:
            frameworkStackStatus = False
            pass
                
        return [RelayAccess, OrchestartorAccess, frameworkVersion, frameworkStackStatus, cloudtrailStatus]
    #endregion

    #region ZCSPM Portal Triggered remediation
    else:  
        try:  
            invokeLambda = boto3.client('lambda', region_name=primary_region)
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
