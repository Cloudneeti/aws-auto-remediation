'''
docdb deletion protection
'''
import time
from botocore.exceptions import ClientError

def run_remediation(docdb,docdb_clustername):
    print("Executing remediation")            
    deletionprotection = False
    
    #Verify current deletion protection for cluster
    try:
        response = docdb.describe_db_clusters(DBClusterIdentifier = docdb_clustername)['DBClusters']
        deletionprotection = response[0]['DeletionProtection']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not deletionprotection:
        #verify cluster state  
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = docdb.describe_db_clusters(DBClusterIdentifier = docdb_clustername)['DBClusters']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
        
        #Apply deletion protection to cluster                  
        try:
            result = docdb.modify_db_cluster(
                        DBClusterIdentifier = docdb_clustername,
                        DeletionProtection = True,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Deletion protection is now enabled for docdb cluster : %s \n" % docdb_clustername
                    
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
        output='Deletion protection is already enabled for docdb cluster : '+ docdb_clustername
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

