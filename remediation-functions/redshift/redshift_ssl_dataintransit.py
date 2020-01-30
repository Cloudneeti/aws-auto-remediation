'''
Redshift non-default parameter groups require SSL to secure data in transit
'''

from botocore.exceptions import ClientError

def run_remediation(redshift, cluster_name):
    print("Executing remediation")            

    ssl_enabled = 1
    activity_logging = 2
    parametervalue = []
    try:
        Cluster_Det = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters']
        RedShiftParameterGroup = Cluster_Det[0]['ClusterParameterGroups'][0]['ParameterGroupName']
        ParameterGroupDet = redshift.describe_cluster_parameters(ParameterGroupName=RedShiftParameterGroup)['Parameters']
        for i in range(len(ParameterGroupDet)):
            if ParameterGroupDet[i]['ParameterName'] == 'require_ssl' and ParameterGroupDet[i]['ParameterValue'] == 'true':
                ssl_enabled = 0
                parametervalue.append(ssl_enabled)
            if ParameterGroupDet[i]['ParameterName'] == 'enable_user_activity_logging' and ParameterGroupDet[i]['ParameterValue'] == 'true':
                activity_logging = 0
                parametervalue.append(activity_logging)
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)   

    if 1 in parametervalue:
        flag=1
        while flag:
            redshift_detail = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters']
            if redshift_detail[0]['ClusterStatus'] not in ['modifying', 'rebooting', 'creating']:
                try:
                    result = redshift.modify_cluster_parameter_group(
                                            ParameterGroupName=RedShiftParameterGroup,
                                            Parameters=[
                                                {
                                                    'ParameterName': 'require_ssl',
                                                    'ParameterValue': 'true',
                                                    'Description': 'applying ssl for data in transit encryption',
                                                    'Source': 'user',
                                                    'DataType': 'boolean',
                                                    'IsModifiable': True,
                                                }
                                            ]
                                        )
                    reboot_response = redshift.reboot_cluster(ClusterIdentifier=cluster_name)
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
    elif 2 in parametervalue:
        flag=1
        while flag:
            redshift_detail = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters']
            if redshift_detail[0]['ClusterStatus'] not in ['modifying', 'rebooting', 'creating']:
                try:
                    result = redshift.modify_cluster_parameter_group(
                                            ParameterGroupName=RedShiftParameterGroup,
                                            Parameters=[
                                                {
                                                    'ParameterName': 'enable_user_activity_logging',
                                                    'ParameterValue': 'true',
                                                    'Description': 'applying user activity logging for cluster',
                                                    'Source': 'user',
                                                    'DataType': 'boolean',
                                                    'IsModifiable': True,
                                                }
                                            ]
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
                    
    else:
        responseCode = 200
        output = "Redshift already remediated"

    print(str(responseCode)+'-'+output)
    return responseCode,output

