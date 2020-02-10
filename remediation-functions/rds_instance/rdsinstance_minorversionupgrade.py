'''
Enable Amazon RDS Database Instances Auto Minor Version Upgrade
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")
    autoversion=''
    #Verify current value for auto minor version upgrade config. 
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        autoversion = response[0]['AutoMinorVersionUpgrade']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not autoversion:
        #Apply Auto-minor version upgrade to db-instance
        try:
            result = rds.modify_db_instance(
                DBInstanceIdentifier = RDSInstanceName,
                BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                ApplyImmediately = False,
                AutoMinorVersionUpgrade = True
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Auto Minor Version Upgrade enabled for rds-instance : %s \n" % RDSInstanceName
                    
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
        output='Auto Minor Version Upgrade already enabled for rds-instance : '+ RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output