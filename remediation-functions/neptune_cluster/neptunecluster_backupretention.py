'''
neptune auto version upgrade
'''

from botocore.exceptions import ClientError

def run_remediation(neptune, cluster_name):
    print("Executing remediation")            
    backup='' 
    try:
        response = neptune.describe_db_clusters(DBClusterIdentifier=cluster_name)['DBClusters']
        backupretention=response[0]['BackupRetentionPeriod']
        if backupretention < 7:
            backup = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not backup:          
        try:
            result = neptune.modify_db_cluster(
                        DBClusterIdentifier=cluster_name,
                        BackupRetentionPeriod=7,
                        ApplyImmediately=True
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

    print(str(responseCode)+'-'+output)
    return responseCode,output

