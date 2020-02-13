'''
Enable Amazon RDS Log Exports feature[MySQL,MariaDB,Oracle]
'''
import time
from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")
    RDSlogs=''
    #Verify current logs config. for db-instance 
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        RDSlogs = response[0]['EnabledCloudwatchLogsExports']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if response[0]['Engine'] not in ['aurora-postgresql','aurora','postgres','sqlserver-ex','sqlserver-se','sqlserver-web','sqlserver-ee']:
        if len(RDSlogs) < 2:
            #verify instance state  
            while response[0]['DBInstanceStatus'] not in ['available', 'stopped']:
                try:
                    response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
                    time.sleep(10)
                except ClientError as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                except Exception as e:
                    responseCode = 400
                output = "Unexpected error: " + str(e)
                
            #Apply all logs for db-instance        
            try:
                if response[0]['Engine'] in ['mysql','mariadb']:
                    result = rds.modify_db_instance(
                        DBInstanceIdentifier = RDSInstanceName,
                        BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                        ApplyImmediately = False,
                        CloudwatchLogsExportConfiguration = {
                            'EnableLogTypes': ['audit', 'error', 'general', 'slowquery']
                        }
                    )

                    responseCode = result['ResponseMetadata']['HTTPStatusCode']
                    if responseCode >= 400:
                        output = "Unexpected error: %s \n" % str(result)
                    else:
                        output = "Log Export Enabled for rds-instance: %s \n" % RDSInstanceName
                
                elif response[0]['Engine'] in ['oracle-se', 'oracle-ee', 'oracle-se1', 'oracle-se2']:
                    result = rds.modify_db_instance(
                        DBInstanceIdentifier = RDSInstanceName,
                        BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                        ApplyImmediately = False,
                        CloudwatchLogsExportConfiguration = {
                            'EnableLogTypes': ['alert','audit','listener','trace']
                        }
                    )

                    responseCode = result['ResponseMetadata']['HTTPStatusCode']
                    if responseCode >= 400:
                        output = "Unexpected error: %s \n" % str(result)
                    else:
                        output = "Log Export Enabled for rds-instance: %s \n" % RDSInstanceName
                            
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
            output='Log Export already Enabled for rds-instance : '+ RDSInstanceName
            print(output)
    
    else:
        responseCode = 200
        output='Log Export is not supported for rds-instance engine : '+ response[0]['Engine']
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output