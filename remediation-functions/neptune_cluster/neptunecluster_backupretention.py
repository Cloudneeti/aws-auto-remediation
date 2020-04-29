'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

neptune auto version upgrade
'''

from botocore.exceptions import ClientError
import time

def run_remediation(neptune, cluster_name):
    print("Executing remediation")            
    backup = True
    
    #verify value for current backup retention 
    try:
        response = neptune.describe_db_clusters(DBClusterIdentifier = cluster_name)['DBClusters']
        backupretention = response[0]['BackupRetentionPeriod']
        if backupretention < 7:
            backup = False
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if not backup:
        #verify instance state  
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = neptune.describe_db_clusters(DBClusterIdentifier = cluster_name)['DBClusters']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
        #Update current backup retention          
        try:
            result = neptune.modify_db_cluster(
                        DBClusterIdentifier = cluster_name,
                        BackupRetentionPeriod = 7,
                        ApplyImmediately = True
                    )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "backup retention is now enabled for neptune cluster : %s \n" % cluster_name
                    
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
        output='Backup retention is already enabled for neptune-instance : '+ cluster_name
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output

