'''
Disable Amazon RDS Database Instances public access
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")
    public='' 
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances']
        public=response[0]['PubliclyAccessible']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if public:  
        while response[0]['DBInstanceStatus'] not in ['available', 'stopped']:
            try:
                response = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances']
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
                PubliclyAccessible=False
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Public Access Disabled for rds-instance: %s \n" % RDSInstanceName
                    
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
        output='Public Access already disabled for rds-instance : '+RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output