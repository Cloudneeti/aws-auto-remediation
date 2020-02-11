'''
Redshift automated retention period
'''

from botocore.exceptions import ClientError

def run_remediation(redshift, cluster_name):
    print("Executing remediation")            

    current_retention = 0
    #Verify current backup retention value
    try:
        response = redshift.describe_clusters(ClusterIdentifier = cluster_name)['Clusters']
        current_retention = response[0]['AutomatedSnapshotRetentionPeriod']
    except:
        current_retention = 0    

    if not current_retention:
        flag=1
        while flag:
            redshift_detail = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters']
            if redshift_detail[0]['ClusterStatus'] not in ['modifying', 'rebooting', 'creating']:
                try:
                    result = redshift.modify_cluster(
                                ClusterIdentifier=cluster_name,
                                AutomatedSnapshotRetentionPeriod=7
                            )
    
                    responseCode = result['ResponseMetadata']['HTTPStatusCode']
                    if responseCode >= 400:
                        output = "Unexpected error: %s \n" % str(result)
                    else:
                        output = "Automatic retention is now set for: %s \n" % cluster_name
                            
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

