'''
sqs sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from sqs import *

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
            queue_url = event["QueueUrl"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            sqs = boto3.client('sqs', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
            # Create KMS client
            kms = boto3.client('kms', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
        
        if "SQSSSEEnabled" in str(records):
            try:
                sqs_enable_sse.run_remediation(sqs, queue_url)
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
                
        if '_DeadLetter_Queue' not in Queue_Url:
            if "SQSDeadLetterQueue" in str(records):
                try:
                    sqs_deadletter_queue.run_remediation(sqs, queue_url)
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
                
        if "SQSEncryptedKMS" in str(records):
            try:
                sqs_encryption_cmk.run_remediation(sqs, kms, queue_url, CustAccID)
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
        
        print('remediated-' + queue_url)
        #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps('remediated-' + queue_url)
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
            queue_name = json.loads(event["body"])["ResourceName"]
            queue_url = "https://sqs." + Region_name + ".amazonaws.com/" + CustAccID + "/" + queue_name
        except:
            Region = ""

        try:
            # Establish a session with the portal
            sqs = boto3.client('sqs', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
            # Create KMS client
            kms = boto3.client('kms', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
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
            if PolicyId == "SQSSSEEnabled":  
                responseCode,output = sqs_enable_sse.run_remediation(sqs, queue_url)
            
            if '_DeadLetter_Queue' not in queue_url:
                if PolicyId == "SQSDeadLetterQueue":  
                    responseCode,output = sqs_deadletter_queue.run_remediation(sqs, queue_url)
            
            if PolicyId == "SQSEncryptedKMS":  
                responseCode,output = sqs_encryption_cmk.run_remediation(sqs, kms, queue_url, CustAccID)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate sqs queue : " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate sqs queue : " + str(e)

            # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }