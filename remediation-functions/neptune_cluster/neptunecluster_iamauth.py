'''
neptune iam authentication
'''

from botocore.exceptions import ClientError
import time

def run_remediation(neptune, cluster_name):
    print("Executing remediation")            
    iamauth_enabled = True
    
    #verify value for current backup retention 
    try:
        response = neptune.describe_db_clusters(DBClusterIdentifier = cluster_name)['DBClusters']
        iamauth_enabled = response[0]['IAMDatabaseAuthenticationEnabled']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not iamauth_enabled:
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
        #Update current Iam authentication          
        try:
            result = neptune.modify_db_cluster(
                        DBClusterIdentifier = cluster_name,
                        EnableIAMDatabaseAuthentication = True,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Iam authentication is now enabled for neptune cluster : %s \n" % cluster_name
                    
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
        output='Iam authentication is already enabled for neptune-instance : '+ cluster_name
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

