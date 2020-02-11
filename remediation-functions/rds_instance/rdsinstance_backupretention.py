'''
RDS Instance Backup Retention Period
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS instance remediation")
    response = ''
    current_retention = 0
    #Verify Current Backup retention
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        current_retention = response[0]['BackupRetentionPeriod']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if current_retention < 7:
        #verify instance state  
        while response[0]['DBInstanceStatus'] not in ['available', 'stopped']:
            try:
                response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                
        #Enabling Backup retention
        try:
            result = rds.modify_db_instance(
                DBInstanceIdentifier = RDSInstanceName,
                ApplyImmediately = True,
                BackupRetentionPeriod = 7
            )
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Backup retention set to 7 days for rds-instance : %s \n" % RDSInstanceName
                    
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
        output = "RDS-instance already compliant"

    print(str(responseCode)+'-'+output)
    return responseCode,output