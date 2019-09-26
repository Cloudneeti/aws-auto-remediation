'''
RDS Instance Backup Retention Period
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS remediation")

    current_retention = 0

    try:
        current_retention = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances'][0]['BackupRetentionPeriod']
    except:
        current_retention = 0   

    if not current_retention:       
        try:
            result = rds.modify_db_instance(
                DBInstanceIdentifier=RDSInstanceName,
                BackupRetentionPeriod=7
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Performance Insights Enabled for: %s \n" % RDSInstanceName
                    
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
        output = "RDS already remediated"

    print(str(responseCode)+'-'+output)
    return responseCode,output