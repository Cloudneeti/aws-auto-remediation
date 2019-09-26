'''
Make redshift private
'''

from botocore.exceptions import ClientError

def run_remediation(redshift, cluster_name):
    print("Executing remediation")    

    public_access = True
    
    try:
        public_access = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters'][0]['PubliclyAccessible']
    except:
        public_access = False    

    if public_access:
        flag=1
        while flag:
            redshift_detail = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters']
            if redshift_detail[0]['ClusterStatus'] not in ['modifying', 'rebooting', 'creating']:        
            
                try:
                    result = redshift.modify_cluster(
                                ClusterIdentifier=cluster_name,
                                PubliclyAccessible=False
                            )

                    responseCode = result['ResponseMetadata']['HTTPStatusCode']
                    if responseCode >= 400:
                        output = "Unexpected error: %s \n" % str(result)
                    else:
                        output = "Redshift cluster is now private: %s \n" % cluster_name
                            
                except ClientError as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                    print(output)
                except Exception as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                    print(output)
                flag = 0
    else:
        responseCode = 200
        output = "Redshift already remediated"

    print(str(responseCode)+'-'+output)
    return responseCode,output

