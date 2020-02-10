'''
S3 sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from s3 import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID, Region
    common_policies = ["S3bucketNoPublicAAUFull", "S3bucketNoPublicAAURead", "S3bucketNoPublicAAUReadACP", "S3bucketNoPublicAAUWrite", "S3bucketNoPublicAAUWriteACP", "S3notPublictoInternet", "S3notPublicRead", "S3notPublicReadACP", "S3notPublicWrite", "S3notPublicWriteACP"]
    
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
            bucket_name = event["bucket"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token)  
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
        
        if "S3EncryptionEnabled" in str(records):
            try:
                s3_put_bucket_encryption.run_remediation(s3_client,bucket_name)
                print('remediated-' + bucket_name)
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

        if "S3VersioningEnabled" in str(records):  
            try: 
                s3_put_bucket_versioning.run_remediation(s3_client,bucket_name)
                print('remediated-' + bucket_name)
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

        if set(common_policies).intersection(set(records)): 
            try:
                s3_put_bucket_acl.run_remediation(s3_client,bucket_name)
                print('remediated-' + bucket_name)
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

        #enable Transfer Acceleration feature
        if "S3TransferAccelerateConfig" in set(records): 
            try:
                s3_transfer_accelaration.run_remediation(s3_client,bucket_name)
                print('remediated-' + bucket_name)
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
            'body': json.dumps('remediated-' + bucket_name)
        }
        #enable block public access feature
        if "S3busketpublicaccess" in set(records): 
            try:
                s3_restrict_public_access.run_remediation(s3_client,bucket_name)
                print('remediated-' + bucket_name)
                #returning the output Array in json format
                return {  
                    'statusCode': 200,
                    'body': json.dumps('remediated-' + bucket_name)
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
            bucket_name = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token)  
        except ClientError as e:
            print("Error:" + str(e))
            return {  
                'statusCode': 400,
                'body': ("Error:" + str(e))
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': ("Error:" + str(e))
            }

        try:
            if PolicyId == "S3EncryptionEnabled":  
                responseCode,output = s3_put_bucket_encryption.run_remediation(s3_client,bucket_name)

            if PolicyId == "S3VersioningEnabled":
                responseCode,output = s3_put_bucket_versioning.run_remediation(s3_client,bucket_name)

            if PolicyId in str(common_policies):              
                responseCode,output = s3_put_bucket_acl.run_remediation(s3_client,bucket_name)
            
            #enable Transfer Acceleration feature
            if PolicyId == "S3TransferAccelerateConfig":              
                responseCode,output = s3_transfer_accelaration.run_remediation(s3_client,bucket_name)
        
            if PolicyId == "S3busketpublicaccess":  
                responseCode,output = s3_restrict_public_access.run_remediation(s3_client,bucket_name)
                    
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate bucket: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate bucket: " + str(e)

            # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }
