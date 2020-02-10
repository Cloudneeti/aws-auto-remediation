'''
Enable Copy Tags to snapshot feature for AWS RDS database instance
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS instance remediation")  
    copytags = ''
    #Verify Current Copytag to snapshot configuration
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        copytags = response[0]['CopyTagsToSnapshot']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if not copytags:
        #Enable Copytag to Snapshot
        try:
            result = rds.modify_db_instance(
                DBInstanceIdentifier = RDSInstanceName,
                ApplyImmediately = False,
                CopyTagsToSnapshot = True
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Copy tags to snapshot enabled for rds-instance : %s \n" % RDSInstanceName
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)

        print(str(responseCode)+'-'+output)
    else:
        responseCode = 200
        output ='Copy tags to snapshot already enabled for rds-instance : '+ RDSInstanceName
        print(output)

    return responseCode,output