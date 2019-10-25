'''
Enable Load balancer connection draining
'''

from botocore.exceptions import ClientError

def run_remediation(elb, LoadBalancerName):
    print("Executing classic load balancer remediation")            

    connection_draining=False
    try:
        response=elb.describe_load_balancer_attributes(LoadBalancerName=LoadBalancerName)['LoadBalancerAttributes']
        connection_draining=response['ConnectionDraining']['Enabled']
    except:
        connection_draining=False

    if not connection_draining:   
        try:
            result = elb.modify_load_balancer_attributes(
                LoadBalancerName=LoadBalancerName,
                LoadBalancerAttributes={
                    'ConnectionDraining':{
                        'Enabled':True,
                        'Timeout':300
                    }
                }
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Connection draining is enabled for: %s \n" % LoadBalancerName
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    else:
        responseCode=200
        output="Connection draining is already enabled for: %s \n" % LoadBalancerName

    print(str(responseCode)+'-'+output)
    return responseCode,output