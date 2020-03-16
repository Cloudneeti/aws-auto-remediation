'''
docdb AutoMinor VersionUpgrade
'''
from botocore.exceptions import ClientError

def run_remediation(eks,EKSClusterName):
    print("Executing remediation")            
    eks_logging = False
    
    #Verify current logging for eks cluster
    try:
        response = eks.describe_cluster(name=EKSClusterName)['cluster']
        if response['logging']['clusterLogging'][0]['enabled']:
            eks_logging = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not eks_logging:
        #verify cluster state  
        while response[0]['status'] not in ['ACTIVE']:
            try:
                response = eks.describe_cluster(name=EKSClusterName)['cluster']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
        #Apply control plane logging to cluster                  
        try:
            result = docdb.update_cluster_config(
                            name=EKSClusterName,
                            logging={
                                'clusterLogging': [
                                    {
                                        'types': ['api','audit','authenticator','controllerManager','scheduler'],
                                        'enabled': True
                                    }
                                ]
                            },
                            clientRequestToken=response['clientRequestToken']
                        )


            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Control plane logging is now enabled for eks cluster : %s \n" % EKSClusterName
                    
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
        output='Control plane logging is already enabled for eks cluster : '+ EKSClusterName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

