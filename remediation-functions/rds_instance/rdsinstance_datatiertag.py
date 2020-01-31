'''
Add data-tier security group tagging to RDS Instances
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")  
    data_tier_tag= False
    tags = ['data tier','datatier','data-tier'] 
    try:
        dbinstance_details = rds.describe_db_instances(DBInstanceIdentifier=RDSInstanceName)['DBInstances']
        security_group_id = dbinstance_details[0]['VpcSecurityGroups'][0]['VpcSecurityGroupId']
        try:
            response = rds.list_tags_for_resource(ResourceName= dbinstance_details[0]['DBInstanceArn'])['TagList']
        except:
            data_tier_tag= False
        for tag in response:
            if response[tag]['Key'].lower() in tags and response[tag]['Value'] == security_group_id:
                data_tier_tag = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
            
    if not data_tier_tag:
        try:
            result = rds.add_tags_to_resource(ResourceName=dbinstance_details[0]['DBInstanceArn'],Tags=[{'Key': 'dat-tier','Value': security_group_id}])

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Data-tier security group are configured for RDS Instance : %s \n" % RDSInstanceName
                    
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
        output='Data-tier security group already configured for RDS Instance : '+RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output