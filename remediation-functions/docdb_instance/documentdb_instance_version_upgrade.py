'''
docdb AutoMinor VersionUpgrade
'''
import time
from botocore.exceptions import ClientError

def run_remediation(docdb,docdb_instancename):
    print("Executing remediation")            
    version_upgrade = False
    
    #Verify current AutoMinor VersionUpgrade for cluster
    try:
        response = docdb.describe_db_instances(DBInstanceIdentifier = docdb_instancename)['DBInstances']
        version_upgrade = response[0]['AutoMinorVersionUpgrade']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not version_upgrade:
        #verify cluster state  
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = docdb.describe_db_instances(DBInstanceIdentifier = docdb_instancename)['DBInstances']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
        #Apply AutoMinor VersionUpgrade to cluster                  
        try:
            result = docdb.modify_db_instance(
                        DBInstanceIdentifier = docdb_instancename,
                        AutoMinorVersionUpgrade = True,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "AutoMinor VersionUpgrade is now enabled for docdb cluster : %s \n" % docdb_instancename
                    
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
        output='AutoMinor VersionUpgrade is already enabled for docdb cluster : '+ docdb_instancename
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

