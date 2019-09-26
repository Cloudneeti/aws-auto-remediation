'''
Enable Cloudtrail in multi regions
'''

from botocore.exceptions import ClientError

def run_remediation(cloudtrail_client, Trail):
    print("Executing Cloudtrail remediation")  
            
    try:
        result = cloudtrail_client.update_trail(
            Name=Trail,
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=True
        )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Multi Region Enabled for: %s \n" % Trail
                
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