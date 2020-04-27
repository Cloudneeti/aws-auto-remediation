'''
neptune auto version upgrade
'''

from botocore.exceptions import ClientError
import time

def run_remediation(neptune, cluster_name):
    print("Executing remediation")            
    backup = True
    
    #verify value for current backup retention 
    try:
        response = neptune.describe_db_clusters(DBClusterIdentifier = cluster_name)['DBClusters']
        backupretention = response[0]['BackupRetentionPeriod']
        if backupretention < 7:
            backup = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not backup:
        #verify instance state  
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = neptune.describe_db_clusters(DBClusterIdentifier = cluster_name)['DBClusters']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
        #Update current backup retention          
        try:
            result = neptune.modify_db_cluster(
                        DBClusterIdentifier = cluster_name,
                        BackupRetentionPeriod = 7,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "backup retention is now enabled for neptune cluster : %s \n" % cluster_name
                    
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
        output='Backup retention is already enabled for neptune-instance : '+ cluster_name
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

