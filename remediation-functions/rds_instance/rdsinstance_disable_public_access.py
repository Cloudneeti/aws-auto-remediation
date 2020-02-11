'''
Disable Amazon RDS Database Instances public access
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")
    public = True
    #Verify Current public access settings for db-instance 
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        public=response[0]['PubliclyAccessible']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if public:
        #Apply public access as false for db-instance
        try:
            result = rds.modify_db_instance(
                DBInstanceIdentifier = RDSInstanceName,
                BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                ApplyImmediately = False,
                PubliclyAccessible = False
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
        responseCode = 200
        output='Public Access already disabled for rds-instance : '+ RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output