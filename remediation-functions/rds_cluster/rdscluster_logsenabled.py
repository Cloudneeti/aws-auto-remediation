'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Enable Log Exports feature for AWS RDS database clusters[AuroraMySQL,AuroraPostgresSQL,AuroraMySQL Serverless]
'''
import time
from botocore.exceptions import ClientError

def run_remediation(rds, RDSIdentifier):
    print('Executing RDS Cluster remediation')
    RDSlogs = ''
    #Verify cloudwatch logs enabled for db-cluster
    try:
        response = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
        DBenginemode = response[0]['EngineMode']
        DBengine = response[0]['Engine']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    try:
        RDSlogs = response[0]['EnabledCloudwatchLogsExports']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if DBenginemode == 'serverless' and DBengine == 'aurora':
        #verify cluster state
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
                time.sleep(10)
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                
        #Enable cloudwatch logs for serverless db-cluster        
        if len(RDSlogs) <= 3:                  
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier = RDSIdentifier,
                    BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                    ApplyImmediately = False,
                    CloudwatchLogsExportConfiguration = {
                        'EnableLogTypes': ['audit', 'error', 'general', 'slowquery']
                    }
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = 'Unexpected error: ' + str(result)
                else:
                    output = 'CloudWatch logs feature enabled for cluster : '+ RDSIdentifier
                        
            except ClientError as e:
                responseCode = 400
                output = 'Unexpected error: ' + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = 'Unexpected error: ' + str(e)
                print(output)

            print(str(responseCode)+'-'+output)
        else:
            responseCode = 200
            output = 'CloudWatch logs feature already enabled for cluster : '+ RDSIdentifier
            print(output)
            
    else:
        #verify cluster state
        while response[0]['Status'] not in ['available', 'stopped']:
            try:
                response = rds.describe_db_clusters(DBClusterIdentifier = RDSIdentifier)['DBClusters']
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                
        #Enable cloudwatch logs for provisioned db-cluster 
        if DBengine == 'aurora' and len(RDSlogs) <= 3:            
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier = RDSIdentifier,
                    BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                    ApplyImmediately = False,
                    CloudwatchLogsExportConfiguration = {
                        'EnableLogTypes': ['audit', 'error', 'general', 'slowquery']
                    }
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "CloudWatch logs feature Enabled for cluster : %s \n" % RDSIdentifier
                        
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)

            print(str(responseCode)+'-'+output)
        
        elif DBengine == 'aurora-postgresql' and len(RDSlogs) == 0:
            try:
                result = rds.modify_db_cluster(
                    DBClusterIdentifier = RDSIdentifier,
                    BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                    ApplyImmediately = False,
                    CloudwatchLogsExportConfiguration = {
                        'EnableLogTypes': ['postgresql']
                    }
                )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "CloudWatch logs feature Enabled for cluster : %s \n" % RDSIdentifier
                        
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
            output = 'CloudWatch logs feature already enabled for cluster : '+ RDSIdentifier
            print(output)

        return responseCode,output

    return responseCode,output