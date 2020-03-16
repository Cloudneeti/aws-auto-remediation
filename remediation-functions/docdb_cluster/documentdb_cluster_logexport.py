'''
Enable cloudwatch logs for documntdb cluster
'''
import time
from botocore.exceptions import ClientError

def run_remediation(docdb,docdb_clustername):
    print("Executing remediation")            
    cloudwatch_log_enabled = False
    
    #verify current log configuration for db-cluster
    try:
        response = docdb.describe_db_clusters(DBClusterIdentifier = docdb_clustername)['DBClusters']
        cloudwatchlog_export = response[0]['EnabledCloudwatchLogsExports']
        if len(cloudwatchlog_export) >= 2:
            cloudwatch_log_enabled = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not cloudwatch_log_enabled:
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
            result = docdb.modify_db_cluster(
                        DBClusterIdentifier = docdb_clustername,
                        EnableCloudwatchLogsExports =  ['audit' , 'profiler'],
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Cloudwatch logs is now enabled for docdb cluster : %s \n" % docdb_clustername
                    
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
        output='Cloudwatch logs are already enabled for docdb cluster : '+ docdb_clustername
        print(output)
        
    print(str(responseCode)+'-'+output)
    return responseCode,output

