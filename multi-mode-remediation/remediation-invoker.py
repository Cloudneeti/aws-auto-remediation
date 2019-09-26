'''
Remediation invoker function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
import gzip
import base64

def lambda_handler(event, context):
    #multi-event customer account CW event
    try:
        cw_data = event['awslogs']['data']
    except:
        cw_data = ''

    #multi-account verify access
    try:
        VerifyAccess = json.loads(event['body'])['VerifyAccess']
        print(VerifyAccess)
    except:
        VerifyAccess = '' 

    #trigger by cw logs
    if cw_data:
        try:
            compressed_payload = base64.b64decode(cw_data)
            uncompressed_payload = gzip.decompress(compressed_payload)
            payload = json.loads(uncompressed_payload)
        
            log_events = payload['logEvents']
            log_event = json.loads(log_events[0]['message'])
            AWSAccId = log_event["userIdentity"]["accountId"]
        except ClientError as e:
            print(e)
        except Exception as e: 
            print(e)

        try:
            iam = boto3.client("iam")
            role_det = iam.get_role(RoleName='CN-Auto-Remediation-Role')['Role']['AssumeRolePolicyDocument']['Statement']
            for i in range(len(role_det)):
                if AWSAccId not in str(role_det[i]['Principal']):
                    RemAccDet = role_det[i]['Principal']['AWS']
                    RemAccId = (RemAccDet.split('arn:aws:iam::')[1]).split(':root')[0]
                    break
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
                
        try:  # common code
            remdiationfunc_rolearn = 'arn:aws:iam::' + RemAccId + ':role/CN-Remediation-Invocation-Role'
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(remdiationfunc_rolearn)
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

        try:
            invokeLambda = boto3.client('lambda',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name='us-east-1')
            response = invokeLambda.invoke(FunctionName = 'cn-aws-remediate-orchestrator', InvocationType = 'RequestResponse', Payload = json.dumps(event))
            t = json.loads(response['Payload'].read())
            print(t['body'])
            return {
                'statusCode': 200,
                'body': json.dumps(t)
            }
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

    elif VerifyAccess:       
        IsVerified = True 
        try:  # common code 
            cust_accid, remdiationacc_rolearn = common.getRemRoleArn(event)       
            common.getCredentials(remdiationacc_rolearn)
        except:
            IsVerified = False
        return IsVerified