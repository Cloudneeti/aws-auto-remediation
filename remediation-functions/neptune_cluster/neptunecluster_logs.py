'''
neptune Cloudwatch logs
'''

from botocore.exceptions import ClientError
import time

def run_remediation(neptune, cluster_name):
    print("Executing remediation")            
    logs_enabled = False
    
    #verify value for Cloudwatch logs
    try:
        response = neptune.describe_db_clusters(DBClusterIdentifier = cluster_name)['DBClusters']
        if response[0]['EnabledCloudwatchLogsExports']:
            logs_enabled = True
        else:
            logs_enabled = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not logs_enabled:
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
        #Enable audit logs          
        try:
            result = neptune.modify_db_cluster(
                        DBClusterIdentifier = cluster_name,
                        CloudwatchLogsExportConfiguration={'EnableLogTypes':['audit']},
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Cloudwatch logs are now enabled for neptune cluster : %s \n" % cluster_name
                    
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
        output='Cloudwatch logs are already enabled for neptune-instance : '+ cluster_name
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

