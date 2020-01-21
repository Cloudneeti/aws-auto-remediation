'''
Enable Log Exports feature for AWS RDS database clusters[AuroraMySQL,AuroraPostgresSQL,AuroraMySQL Serverless]
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print('Executing RDS Cluster remediation')  
    response=''
    DBenginemode=''
    DBengine=''
    RDSlogs=''
    try:
        response = rds.describe_db_clusters(DBClusterIdentifier=RDSIdentifier)['DBClusters']
        RDSlogs=response[0]['EnabledCloudwatchLogsExports']
        DBenginemode=response[0]['EngineMode']
        DBengine=response[0]['Engine']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if DBenginemode == 'serverless' and DBengine == 'aurora':
        if len(RDSlogs) <= 3:                  
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier=RDSIdentifier,
                    ApplyImmediately=True,
                    CloudwatchLogsExportConfiguration={
                        'EnableLogTypes': ['audit', 'error', 'general', 'slowquery']
                    }
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = 'Unexpected error: ' + str(result)
                else:
                    output = 'CloudWatch logs feature enabled for cluster : '+RDSIdentifier
                        
            except ClientError as e:
                responseCode = 400
                output = 'Unexpected error: ' + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = 'Unexpected error: ' + str(e)
                print(output)

            print(str(responseCode)+'-'+output)
        else:
            responseCode=200
            output='CloudWatch logs feature already enabled for cluster : '+RDSIdentifier
            print(output)
            
    else:
        if DBengine == 'aurora' and len(RDSlogs) <= 3:            
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier=RDSIdentifier,
                    ApplyImmediately=True,
                    CloudwatchLogsExportConfiguration={
                        'EnableLogTypes': ['audit', 'error', 'general', 'slowquery']
                    }
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "CloudWatch logs feature Enabled for cluster : %s \n" % RDSIdentifier
                        
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)

            print(str(responseCode)+'-'+output)
        
        elif DBengine == 'aurora-postgresql' and len(RDSlogs) == 0:
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier=RDSIdentifier,
                    ApplyImmediately=True,
                    CloudwatchLogsExportConfiguration={
                        'EnableLogTypes': ['postgresql']
                    }
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "CloudWatch logs feature Enabled for cluster : %s \n" % RDSIdentifier
                        
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
            output='CloudWatch logs feature already enabled for cluster : '+RDSIdentifier
            print(output)

        return responseCode,output

    return responseCode,output