'''
update public access parameter for instance
'''

from botocore.exceptions import ClientError
import time

def run_remediation(neptune, instance_name):
    print("Executing remediation")            
    applied_public_access = False
     
    #Verify current value for auto minor version upgrade 
    try:
        response = neptune.describe_db_instances(DBInstanceIdentifier = instance_name)['DBInstances']
        applied_public_access = response[0]['PubliclyAccessible']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not applied_public_access:
        #verify instance state  
        while response[0]['DBInstanceStatus'] not in ['available', 'stopped']:
            try:
                response = neptune.describe_db_instances(DBInstanceIdentifier = instance_name)['DBInstances']
                time.sleep(10)
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
                        PubliclyAccessible = False,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Public Access is disabled for neptune instance : %s \n" % instance_name
                    
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
        output='Public Access already disabled for neptune-instance : '+ instance_name
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

