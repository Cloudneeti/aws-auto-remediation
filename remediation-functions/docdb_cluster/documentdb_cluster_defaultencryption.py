'''
Enable encryption for documntdb cluster
'''
import time
from botocore.exceptions import ClientError

def run_remediation(docdb,docdb_clustername):
    print("Executing remediation")            
    docdb_encryption_enabled = False
    #Verify encryption for cluster 
    try:
        response = docdb.describe_db_clusters(DBClusterIdentifier = docdb_clustername)['DBClusters']
        docdb_encryption = response[0]['StorageEncrypted']
        if docdb_encryption:
            docdb_encryption_enabled = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not docdb_encryption_enabled:          
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
                
        try:    
            #Apply cluster encryption
            result = docdb.modify_db_cluster(
                        DBClusterIdentifier = docdb_clustername,
                        StorageEncrypted = True,
                        KmsKeyId = 'alias/aws/rds',
                        ApplyImmediately=True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Encryption now enabled for docdb cluster : %s \n" % docdb_clustername
                    
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
        output='Encryption with AWS KMS is already enabled for docdb cluster : '+ docdb_clustername
        print(output)
        
    print(str(responseCode)+'-'+output)
    return responseCode,output

