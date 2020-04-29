'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

EKS control plane logging
'''
import time
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
            result = eks.update_cluster_config(
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

