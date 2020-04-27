'''
Kinesis firhose default encryption
'''
import time
from botocore.exceptions import ClientError

def run_remediation(kinesis_firehose,delivery_stream_name):
    print("Executing remediation")            
    firhose_encryption = False
    #Verify current Encryption for delivery stream 
    try:
        response = kinesis_firehose.describe_delivery_stream(DeliveryStreamName=delivery_stream_name)['DeliveryStreamDescription']
        if responseresponse['DeliveryStreamEncryptionConfiguration'] == {'Status': 'ENABLED'}:
            firhose_encryption = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not firhose_encryption:
        #Apply Encryption to delivery stream                  
        try:
            result = kinesis_firehose.start_delivery_stream_encryption(
                        DeliveryStreamName = delivery_stream_name,
                        DeliveryStreamEncryptionConfigurationInput = {'KeyType': 'AWS_OWNED_CMK'}
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Encryption with aws kms will be enabled within 30-seconds for delivery stream : %s \n" % delivery_stream_name
                    
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
        output='Encryption with aws kms is already enabled for delivery stream : '+ delivery_stream_name
        print(output)
        
    print(str(responseCode)+'-'+output)
    return responseCode,output

