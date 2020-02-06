'''
docdb backup retention
'''

from botocore.exceptions import ClientError

def run_remediation(docdb,docdb_clustername):
    print("Executing remediation")            
    backup = False
    try:
        response = docdb.describe_db_clusters(DBClusterIdentifier=docdb_clustername)['DBClusters']
        backupretention=response[0]['BackupRetentionPeriod']
        if backupretention >= 7:
            backup = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not backup:          
        try:
            result = docdb.modify_db_cluster(
                        DBClusterIdentifier=docdb_clustername,
                        BackupRetentionPeriod=8,
                        ApplyImmediately=True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "backup retention is now enabled for docdb cluster : %s \n" % docdb_clustername
                    
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

