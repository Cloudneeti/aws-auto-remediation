'''
Add data-tier security group tagging to RDS Cluster
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print("Executing RDS Cluster remediation")  
    tags = ['data tier','datatier','data-tier']
    data_tier_tag = False
    #Verify data-tier tags for security groups applied to db-cluster
    try:
        dbcluster_detail = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
        security_group_id = dbcluster_detail[0]['VpcSecurityGroups'][0]['VpcSecurityGroupId']
        try:
            response = rds.list_tags_for_resource(ResourceName = dbcluster_detail[0]['DBClusterArn'])['TagList']
            for tag in response:
                if response[tag]['Key'].lower() in tags and response[tag]['Value'] == security_group_id:
                    data_tier_tag = True
        except:
            data_tier_tag = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    if not data_tier_tag:
        #Add data-tier tags for security groups to db-cluster             
        try:
            result = rds.add_tags_to_resource(ResourceName = dbcluster_detail[0]['DBClusterArn'], Tags = [{'Key': 'data-tier','Value': security_group_id}])

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Data-tier security group are configured for RDS Cluster : %s \n" % RDSIdentifier
                    
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
        responseCode = 200
        output = 'Data-tier security group already configured for RDS Cluster : '+ RDSIdentifier
        print(output)

    return responseCode,output