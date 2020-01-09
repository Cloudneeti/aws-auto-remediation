'''
Remediation orchestrator function
'''

import json
import boto3
import common
import hashlib
from botocore.exceptions import ClientError
import gzip
import base64

def lambda_handler(event, context):
    cloudtrail_list = ["CTMultiRegionTrail", "CTLogFileValidation"]
    elb_list = ["ClassicLBConnDraining"]
    elbv2_list = ["AppLBDeletionProtection", "NetworkLBDeletionProtection"]
    iam_list = ["IAMPasswordRequiredNumber", "IAMPasswordUpCaseLetter", "IAMPasswordRequiredSymbols", "IAMRequireLowercaseLetter", "IAMMinPasswordLength", "IAMExpirePasswords", "IAMPasswordReusePrevention"]
    kinesis_list = ["KinesisEnhancedMonitoring", "KinesisSSE"]
    kms_list = ["KMSKeyRotation"]
    rds_cluster_list = ["AuroraDeleteProtection", "AuroraServerlessDeleteProtection", "AuroraPostgresServerlessDeleteProtection", "AuroraBackup", "AuroraBackupTerm", "AuroraServerlessBackupTerm", "AuroraPostgresServerlessBackupTerm", "AuroraCopyTagsToSnapshot", "AuroraServerlessCopyTagsToSnapshot", "AuroraPostgresServerlessCopyTagsToSnapshot", "AuroraServerlessScalingAutoPause", "AuroraPostgresServerlessScalingAutoPause"]
    rds_instance_list = ["SQLBackup","SQLBackupTerm","MariadbBackup","MariadbBackupTerm","OracleBackup","OracleBackupTerm","SQLServerBackup","SQLServerBackupTerm","SQLCopyTagsToSnapshot","MariadbCopyTagsToSnapshot","OracleCopyTagsToSnapshot","SQLServerCopyTagsToSnapshot","SQLDeletionProtection", "MariadbDeletionProtection", "OracleDeletionProtection", "SQLServerDeletionProtection", "SQLPrivateInstance","MariadbPrivateInstance","OraclePrivateInstance","SQLServerPrivateInstance","AuroraInstancePrivateInstance","SQLVersionUpgrade","MariadbVersionUpgrade","OracleVersionUpgrade","SQLServerVersionUpgrade","AuroraInstanceVersionUpgrade", "SQLMultiAZEnabled","MariadbMultiAZEnabled","OracleMultiAZEnabled","SQLServerMultiAZEnabled","SQLPerformanceInsights","MariadbPerformanceInsights","OraclePerformanceInsights","SQLServerPerformanceInsights","AuroraInstancePerformanceInsights"]
    redshift_list = ["RedShiftNotPublic", "RedShiftVersionUpgrade", "RedShiftAutomatedSnapshot"]
    s3_list = ["S3VersioningEnabled", "S3EncryptionEnabled", "S3bucketNoPublicAAUFull", "S3bucketNoPublicAAURead", "S3bucketNoPublicAAUReadACP", "S3bucketNoPublicAAUWrite", "S3bucketNoPublicAAUWriteACP", "S3notPublictoInternet", "S3notPublicRead", "S3notPublicReadACP", "S3notPublicWrite", "S3notPublicWriteACP"]

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
        cw_data = event['awslogs']['data']
    except:
        cw_data = ''

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
            Region = "us-east-1"
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
        # rem_bucket = 'cn-rem-cust-rem-acc'
        available_list = cloudtrail_list + elb_list + elbv2_list + iam_list + kinesis_list + kms_list + rds_cluster_list + rds_instance_list + redshift_list + s3_list
            
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
    elif cw_data:
        try:
            records = ""
            compressed_payload = base64.b64decode(cw_data)
            uncompressed_payload = gzip.decompress(compressed_payload)
            payload = json.loads(uncompressed_payload)
        
            log_events = payload['logEvents']
            log_event = json.loads(log_events[0]['message'])
            AWSAccId = log_event["userIdentity"]["accountId"]
            EventName = log_event["eventName"]
            EventSource = log_event["userIdentity"]["arn"]
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
        
        if "assumed-role/CN-Auto-Remediation-Role" not in str(EventSource):    
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
                Region = "us-east-1"
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
                    invokeLambda = boto3.client('lambda', region_name='us-east-1')
    
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
                if EventName in ["CreateTrail", "UpdateTrail"]:
                    try:
                        Trail = log_event["responseElements"]["name"]
                        Region = log_event["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "Trail": Trail,
                            "Region" : Region,
                            "policies": records
                        }
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-cloudtrail', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                            lb_detail=log_event["requestParameters"]["type"]
                            if lb_detail in ["application", "network"]:
                                lb_type='elbv2'
                            else:
                                lb_type='elb'
                        except:
                            lb_type='elb'
                    else:
                        try:
                            lb_attributes=log_event["requestParameters"]["attributes"]
                            lb_type='elbv2'
                        except:
                            lb_type='elb'

                    if lb_type == 'elbv2':
                        try:
                            if EventName == "CreateLoadBalancer":
                                LoadBalancerArn = log_event["responseElements"]["loadBalancers"][0]["loadBalancerArn"]
                            else:
                                LoadBalancerArn = log_event["requestParameters"]["loadBalancerArn"]
                                
                            Region = log_event["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "LoadBalancerArn": LoadBalancerArn,
                                "Region" : Region,
                                "policies": records
                            }
                            response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-elbv2', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                            LoadBalancerName = log_event["requestParameters"]["loadBalancerName"]
                            Region = log_event["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "LoadBalancerName": LoadBalancerName,
                                "Region" : Region,
                                "policies": records
                            }
                            response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-elb', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                        
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-iam', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                        kinesis_stream = log_event["requestParameters"]["streamName"]
                        Region = log_event["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "kinesis_stream": kinesis_stream,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-kinesis', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                        KeyId = log_event["responseElements"]["keyMetadata"]["keyId"]
                        Region = log_event["awsRegion"]
                    except:
                        KeyId = log_event["requestParameters"]["keyId"]
                        Region = log_event["awsRegion"]

                    try: 
                        remediationObj = {
                            "accountId": AWSAccId,
                            "KeyId": KeyId,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-kms', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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


                #region rds cluster suborchestrator call
                if EventName in ["CreateDBCluster", "ModifyDBCluster", "CreateDBInstance"]:
                    try:
                        DBEngine=log_event["responseElements"]["engine"]
                    except:
                        DBEngine=''

                    if 'aurora' in str(DBEngine):
                        try:
                            RDSClusterName = log_event["responseElements"]["dBClusterIdentifier"]
                            Region = log_event["awsRegion"]

                            remediationObj = {
                                "accountId": AWSAccId,
                                "RDSClusterName": RDSClusterName,
                                "Region" : Region,
                                "policies": records
                            }
                            
                            response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-rdscluster', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                if EventName in ["CreateDBInstance", "ModifyDBInstance"]:
                    try:
                        RDSInstanceName = log_event["responseElements"]["dBInstanceIdentifier"]
                        Region = log_event["awsRegion"]

                        remediationObj = {
                            "accountId": AWSAccId,
                            "RDSInstanceName": RDSInstanceName,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-rdsinstance', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                        redshift = log_event["requestParameters"]["clusterIdentifier"]
                        Region = log_event["awsRegion"]
                        remediationObj = {
                            "accountId": AWSAccId,
                            "redshift": redshift,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-redshift', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                if EventName in ["CreateBucket", "PutBucketAcl", "DeleteBucketEncryption", "PutBucketVersioning"]:
                    try:
                        bucket = log_event["requestParameters"]["bucketName"]
                        Region = log_event["awsRegion"]
                        
                        remediationObj = {
                            "accountId": AWSAccId,
                            "bucket": bucket,
                            "Region" : Region,
                            "policies": records
                        }
                        
                        response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-s3-bucket', InvocationType = 'RequestResponse', Payload = json.dumps(remediationObj))
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
                invokeLambda = boto3.client('lambda',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name='us-east-1')
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-relayfunction', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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

    #region CN Portal Triggered remediation
    else:  
        try:  
            invokeLambda = boto3.client('lambda', region_name='us-east-1')
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-cloudtrail', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-elb', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-elbv2', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-iam', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-kinesis', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-kms', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-rdscluster', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-rdsinstance', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-redshift', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-s3-bucket', InvocationType = 'RequestResponse', Payload = json.dumps(event))
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
                                
        return {
            'statusCode': response['statusCode'],
            'body': response['body']
        }