'''
Update backup retention for fsx
'''

from botocore.exceptions import ClientError

def run_remediation(fsx, FileSystemId):
    print("Executing Cloudtrail remediation")
    
    fsx_backup_retention = False
    
    #verify for current backup retention value
    try:
        response = fsx.describe_file_systems(FileSystemIds = [FileSystemId])['FileSystems']
        if response[0]['WindowsConfiguration'] ['AutomaticBackupRetentionDays'] >= 7:
            fsx_backup_retention = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if not fsx_backup_retention:    
        #Apply backup retention to file system        
        try:
            result = fsx.update_trail(
                Name = FileSystemId,
                WindowsConfiguration = {'AutomaticBackupRetentionDays': 8}
            )
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Backup retention is enabled for file system : %s \n" % FileSystemId
                    
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
        output='Backup retention is already enabled for file system: '+ FileSystemId
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output