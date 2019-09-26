'''
Enable KMS Key Rotation
'''

from botocore.exceptions import ClientError

def run_remediation(kms_client, KeyId):
    print("Executing KMS remediation")            
            
    try:
        result = kms_client.enable_key_rotation(
            KeyId=KeyId
        )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Key Rotaion is enabled for: %s \n" % KeyId
                
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output