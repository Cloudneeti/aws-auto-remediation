'''
Enable Deletion Protection feature for AWS RDS database clusters
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print("Executing RDS Cluster remediation")  

    try:
        response = rds.describe_db_clusters(DBClusterIdentifier=RDSIdentifier)['DBClusters']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if not response[0]['DeletionProtection']:            
        try:
            result = rds.modify_db_cluster(
                DBClusterIdentifier=RDSIdentifier,
                ApplyImmediately=True,
                DeletionProtection=True
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Delete Protection Enabled for cluster : %s \n" % RDSIdentifier
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)

        print(str(responseCode)+'-'+output)
    else:
        responseCode=200
        output='Deletion protection already enabled for cluster : '+RDSIdentifier
        print(output)

    return responseCode,output