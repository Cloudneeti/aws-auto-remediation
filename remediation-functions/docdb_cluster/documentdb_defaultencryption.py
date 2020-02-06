'''
Enable encryption for documntdb cluster
'''

from botocore.exceptions import ClientError

def run_remediation(docdb,docdb_clustername):
    print("Executing remediation")            
    docdb_encryption_enabled = False
    try:
        response = docdb.describe_db_clusters(DBClusterIdentifier=docdb_clustername)['DBClusters']
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
        try:
            result = docdb.modify_db_cluster(
                        DBClusterIdentifier=docdb_clustername,
                        StorageEncrypted = True,
                        KmsKeyId = 'alias/aws/rds'
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

    print(str(responseCode)+'-'+output)
    return responseCode,output

