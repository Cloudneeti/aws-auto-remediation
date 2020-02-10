'''
Enable IAM Authentication for RDS Cluster
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print("Executing RDS Cluster remediation")
    iam_auth_value = False
    #Verify for iam authentication value for db-instance
    try:
        dbcluster_detail = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
        DBenginemode = dbcluster_detail[0]['EngineMode']
        if dbcluster_detail[0]['IAMDatabaseAuthenticationEnabled']:
            iam_auth_value = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if DBenginemode != 'serverless':
        if not iam_auth_value:
            #Updating iam authentication for db-cluster                        
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier = RDSIdentifier,
                    BackupRetentionPeriod = dbcluster_detail[0]['BackupRetentionPeriod'],
                    ApplyImmediately = False,
                    EnableIAMDatabaseAuthentication = True
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "IAM Authentication enabled for RDS Cluster : %s \n" % RDSIdentifier
                        
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
            responseCode = 200
            output = 'IAM Authentication already enabled for RDS Cluster : '+ RDSIdentifier
            print(output)
    else:
        responseCode = 200
        output = 'IAM Authentication not supported for RDS Serverless Cluster : '+ RDSIdentifier
        print(output)

    return responseCode,output