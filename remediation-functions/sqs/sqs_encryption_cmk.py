'''
Enable sqs queue Server-Side Encryption
'''
import json
import time
from botocore.exceptions import ClientError

def run_remediation(sqs,kms, queue_url, CustAccID):
    print("Executing sqs queue remediation")
    queue_not_encrypted = True
    try:
        response = sqs.get_queue_attributes(QueueUrl = queue_url, AttributeNames = ['All'])['Attributes']
        if response['KmsMasterKeyId'] and response['KmsMasterKeyId'] != 'alias/aws/sqs':
            queue_not_encrypted = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if queue_not_encrypted:
        try:
            kms_policy = {'Version': '2012-10-17', 'Statement': [ { 'Sid': 'CN-kmsiampolicy', 'Effect': 'Allow', 'Principal': { 'AWS': 'arn:aws:iam::'+CustAccID+':root' }, 'Action': 'kms:*', 'Resource': '*' }, { 'Sid': 'CN-kmspolicy', 'Effect': 'Allow', 'Principal': { 'Service': ['cloudtrail.amazonaws.com', 'dynamodb.amazonaws.com', 'sqs.amazonaws.com'] }, 'Action': 'kms:*', 'Resource': '*' } ] }
            create_cmk = kms.create_key(Policy=json.dumps(kms_policy))
            time.sleep(5)
            create_key_alias = kms.create_alias(
                                AliasName='alias/CN-Remediation-key-'+queue_url.split('/')[4],
                                TargetKeyId=create_cmk['KeyMetadata']['KeyId']
                            )
            kms.enable_key_rotation(KeyId=create_cmk['KeyMetadata']['KeyId'])
            kms.tag_resource(
                            KeyId=create_cmk['KeyMetadata']['KeyId'],
                            Tags=[
                                {
                                    'TagKey': 'Description',
                                    'TagValue': 'Cloudneeti remediation key for queue encrytion '+queue_url.split('/')[4]
                                },
                                {
                                    'TagKey': 'CreatedBy',
                                    'TagValue': 'Cloudneeti'
                                }
                            ]
                        )
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        
        if create_cmk['ResponseMetadata']['HTTPStatusCode'] == 200:     
            try:
                result = sqs.set_queue_attributes(QueueUrl=queue_url,Attributes={"KmsMasterKeyId": create_cmk['KeyMetadata']['KeyId'],"KmsDataKeyReusePeriodSeconds": "300"})
                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "Enabled Server-Side Encryption for SQS : %s \n" % queue_url
                        
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
        else:
            output = "Unable to create CMK for queue " + queue_url
    else:
        responseCode=200
        output='Server-Side Encryption with CMK already enabled for queue : '+queue_url
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output