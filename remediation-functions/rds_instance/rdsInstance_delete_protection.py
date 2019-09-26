'''
Enable Deletion Protection feature for AWS RDS database instances
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print("Executing RDS Instance remediation")  
            
    try:
        result = rds.modify_db_instance(
            DBInstanceIdentifier=RDSIdentifier,
            DeletionProtection=True
        )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Delete Protection Enabled for: %s \n" % RDSIdentifier
                
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