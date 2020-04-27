'''
Backup retention for AWS RDS database clusters
'''
import time
from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print("Executing RDS Cluster remediation")  
    #Verify backup retention for rds-cluster
    try:
        response = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if response[0]['BackupRetentionPeriod'] < 7:
        #verify cluster state
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            
        #Update Backup retention period for db-cluster                      
        try:
            result = rds.modify_db_cluster(
                DBClusterIdentifier = RDSIdentifier,
                ApplyImmediately = True,
                BackupRetentionPeriod=8
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Backup retention set to 7 days for cluster : %s \n" % RDSIdentifier
                    
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
        output = 'Backup retention value is already >=7 days for cluster : '+ RDSIdentifier
        print(output)

    return responseCode,output