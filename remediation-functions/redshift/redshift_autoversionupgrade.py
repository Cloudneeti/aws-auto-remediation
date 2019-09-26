'''
Allow redshift auto version upgrade
'''

from botocore.exceptions import ClientError

def run_remediation(redshift, cluster_name):
    print("Executing remediation")            
            
    try:
        result = redshift.modify_cluster(
                    ClusterIdentifier=cluster_name,
                    AllowVersionUpgrade=True
                )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Auto version upgrade is now enabled for: %s \n" % cluster_name
                
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

