'''
Enable Copy Tags to snapshot feature for AWS RDS database clusters
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print("Executing RDS Cluster remediation")  
    response=''
    try:
        response = rds.describe_db_clusters(DBClusterIdentifier=RDSIdentifier)['DBClusters'][0]['CopyTagsToSnapshot']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if not response:            
        try:
            result = rds.modify_db_cluster(
                DBClusterIdentifier=RDSIdentifier,
                ApplyImmediately=True,
                CopyTagsToSnapshot=True
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Copy tags to snapshot enabled for cluster : %s \n" % RDSIdentifier
                    
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
        output='Copy tags to snapshot already enabled for cluster : '+RDSIdentifier
        print(output)

    return responseCode,output