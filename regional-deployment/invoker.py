'''
Remediation invoker function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    #regional-event customer account CW event
    
    try:
        cw_event_data = event['detail']
    except:
        cw_event_data = ''

    #trigger by cw logs
    if cw_event_data:
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

        # Invoke remediation orchestrator
        if "assumed-role/CN-Auto-Remediation-Role" not in str(EventSource):        
            try:  # common code
                remdiationfunc_rolearn = 'arn:aws:iam::' + AWSAccId + ':role/CN-Remediation-Invocation-Role'
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
                invokeLambda = boto3.client('lambda',aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token, region_name='us-east-2')
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
        #endregion
        
        #No Events
        else:
            print("Policies not configured for remediation")
            return {
                'statusCode': 200,
                'body': json.dumps("Policies not configured for remediation")
            }
        #endregion
    
    else:
        return {
            'statusCode': 200,
            'body': json.dumps("Invalid event source!")
        }