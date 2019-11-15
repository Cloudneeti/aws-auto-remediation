'''
Enable autopause feature for AWS RDS database clusters
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print('Executing RDS Cluster remediation')  
    response=''
    DBenginemode=''
    autopause=''
    try:
        response = rds.describe_db_clusters(DBClusterIdentifier=RDSIdentifier)['DBClusters']
        autopause=response[0]['ScalingConfigurationInfo']['AutoPause']
        DBenginemode=response[0]['EngineMode']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if DBenginemode == 'serverless':
        if not autopause:                  
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier=RDSIdentifier,
                    ApplyImmediately=True,
                    ScalingConfiguration={'AutoPause':True}
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = 'Unexpected error: ' + str(result)
                else:
                    output = 'Autopause feature enabled for cluster : '+RDSIdentifier
                        
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
            output='Autopause feature already enabled for cluster : '+RDSIdentifier
            print(output)
    else:
        responseCode=200
        output='Autopause feature is not supported for cluster : '+RDSIdentifier
        print(output)

    return responseCode,output