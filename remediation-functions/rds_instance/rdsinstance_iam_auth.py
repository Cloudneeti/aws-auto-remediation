'''
Enable IAM Authentication for RDS Instances
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")  
    iam_auth_value= False
    try:
        dbinstance_details = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances']
        if dbinstance_details[0]['IAMDatabaseAuthenticationEnabled']:
            iam_auth_value = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
            
    if not iam_auth_value:
        while dbinstance_details[0]['DBInstanceStatus'] not in ['available', 'stopped']:
            try:
                dbinstance_details = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances']
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)

        try:
            result = rds.modify_db_instance(
                DBInstanceIdentifier=RDSInstanceName,
                ApplyImmediately=True,
                EnableIAMDatabaseAuthentication=True
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "IAM Authentication enabled for rds-instance : %s \n" % RDSInstanceName
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)

    else:
        responseCode=200
        output='IAM Authentication already enabled for rds-instance : '+RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output