'''
Enable MultiAZ for Amazon RDS Database Instances
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")
    multiaz='' 
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances']
        multiaz=response[0]['MultiAZ']
        current_retention=response[0]['BackupRetentionPeriod']
        if not current_retention:
            current_retention=7
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not multiaz:
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
                BackupRetentionPeriod=current_retention,
                ApplyImmediately=False,
                MultiAZ=True
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "MultiAZ enabled for rds-instance : %s \n" % RDSInstanceName
                    
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
        output='MultiAZ already enabled for rds-instance : '+RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output