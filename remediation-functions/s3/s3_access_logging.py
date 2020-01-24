'''
Enable Access logging for bucket
'''

from botocore.exceptions import ClientError

def run_remediation(s3_client, bucket_name):
    print("Executing remediation")            
    bucket_logging = False        
    try:
        result = s3_client.get_bucket_logging(Bucket=bucket_name)
        if result['LoggingEnabled']['TargetPrefix']:
            bucket_logging = True
                      
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if not bucket_logging:
        try:
            bucket_region = s3_client.head_bucket(Bucket=bucket_name)['ResponseMetadata']['HTTPHeaders']['x-amz-bucket-region']
            if bucket_region not in ['EU','eu-west-1','us-west-1','us-west-2','ap-south-1','ap-southeast-1','ap-southeast-2','ap-northeast-1','sa-east-1','cn-north-1','eu-central-1']:
                try:
                    create_bucket = s3_client.create_bucket(
                                                ACL='log-delivery-write',
                                                Bucket='cn-s3-log-bucket-'+bucket_name,
                                                ObjectLockEnabledForBucket=True)
                except Exception as e:
                    print('Unable to create bucket: '+ str(e))   
            else:
                try:
                    create_bucket = s3_client.create_bucket(
                                                ACL='log-delivery-write',
                                                Bucket='cn-s3-log-bucket-'+bucket_name,
                                                CreateBucketConfiguration={'LocationConstraint':bucket_region},
                                                ObjectLockEnabledForBucket=True)
                except Exception as e:
                    print('Unable to create bucket: '+ str(e))
            if create_bucket['ResponseMetadata']['HTTPStatusCode'] == 200:
                try:
                    result = s3.put_bucket_logging(
                                                Bucket=bucket_name,
                                                BucketLoggingStatus={
                                                    'LoggingEnabled': {
                                                        'TargetBucket': bucket_name,
                                                        'TargetPrefix': 's3'
                                                    }
                                                }
                                            )
                    responseCode = result['ResponseMetadata']['HTTPStatusCode']
                    if responseCode >= 400:
                        output = "Unexpected error: %s \n" % str(result)
                    else:
                        output = "Access logging  enabled for bucket: %s \n" % bucket_name
                            
                except ClientError as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                    print(output)
                except Exception as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                    print(output)
            else:
                responseCode = 400
                output = "Unable to create bucket to store log for : " + bucket_name
                print(output)
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    else:
        responseCode = 200
        output = "Access logging already enabled for : " + bucket_name
        print(output)
                
    print(str(responseCode)+'-'+output)
    return responseCode,output

