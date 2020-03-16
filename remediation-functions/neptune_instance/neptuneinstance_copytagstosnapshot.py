'''
update neptune copytags to snapshot
'''

from botocore.exceptions import ClientError

def run_remediation(neptune, instance_name):
    print("Executing remediation")            
    applied_copy_tags_value = False
     
    #Verify current value for auto minor version upgrade 
    try:
        response = neptune.describe_db_instances(DBInstanceIdentifier = instance_name)['DBInstances']
        applied_copy_tags_value = response[0]['CopyTagsToSnapshot']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not applied_copy_tags_value:
        #verify instance state  
        while response[0]['DBInstanceStatus'] not in ['available', 'stopped']:
            try:
                response = neptune.describe_db_instances(DBInstanceIdentifier = instance_name)['DBInstances']
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                
        #Update copy tags to snapshot for neptune db-instance        
        try:
            result = neptune.modify_db_instance(
                        DBInstanceIdentifier = instance_name,
                        CopyTagsToSnapshot = True,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Copy tags to snapshot is now enabled for neptune instance : %s \n" % instance_name
                    
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
        output='Copy tags to snapshot is already enabled for neptune-instance : '+ instance_name
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

