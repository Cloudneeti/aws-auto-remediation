'''
Dead Letter Queue configured for each Amazon SQS queue
'''

from botocore.exceptions import ClientError

def run_remediation(sqs, queue_url):
    print("Executing sqs queue remediation")
    enabled_deadletter_queue = False
    try:
        response = sqs.get_queue_attributes(QueueUrl = queue_url, AttributeNames = ['All'])['Attributes']
        if response['RedrivePolicy']:
            enabled_deadletter_queue = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if not enabled_deadletter_queue:   
        try:
            QueueName = queue_url.split('/')[4]
            create_deadletter_queue = sqs.create_queue(
                                                    QueueName=QueueName+'_DeadLetter_Queue',
                                                    Attributes={"KmsMasterKeyId": "alias/aws/sqs","KmsDataKeyReusePeriodSeconds": "300"},
                                                    tags={
                                                        'Description' : 'Cloudneeti remediation queue for compliant '+QueueName,
                                                        'ProjectName' : 'Cloudneeti Remediation bots',
                                                        'Department': 'DevSecOps',
                                                        'CreatedBy': 'Cloudneeti'
                                                    }
                                                )
            arn_deadletter_queue = response['QueueArn'] + '_DeadLetter_Queue'
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
            
        if arn_deadletter_queue:
            try:
                RedrivePolicy = {"deadLetterTargetArn":arn_deadletter_queue,"maxReceiveCount":5}   
                result = sqs.set_queue_attributes(QueueUrl=queue_url,Attributes={"RedrivePolicy": json.dumps(RedrivePolicy)})
                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "Enabled Redrive Policy for SQS queue : %s \n" % queue_url
                    
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
        else:
            output = "Unable to create queue for setting up redrive policy"
    else:
        responseCode=200
        output='Queue '+queue_url+' already have redrive policy set with deadletter queue'
        print(output)
        
    print(str(responseCode)+'-'+output)
    return responseCode,output