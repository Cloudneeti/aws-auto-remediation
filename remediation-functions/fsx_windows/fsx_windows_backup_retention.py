'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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