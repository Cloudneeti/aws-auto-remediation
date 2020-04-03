'''
Redshift automated retention period
'''

from botocore.exceptions import ClientError
import time

def run_remediation(redshift, cluster_name):
    print("Executing remediation")            

    current_retention = 0
    
    try:
        current_retention = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters'][0]['AutomatedSnapshotRetentionPeriod']
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
                                MaintenanceTrackName='trailing',
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
                time.sleep(10)

    else:
        responseCode = 200
        output = "Redshift already remediated"

    print(str(responseCode)+'-'+output)
    return responseCode,output

