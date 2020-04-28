'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Enable IAM Authentication for RDS Instances
'''
import time
from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")  
    iam_auth_value= False
    #Verify Current iam authentication configuration
    try:
        dbinstance_details = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        if dbinstance_details[0]['IAMDatabaseAuthenticationEnabled']:
            iam_auth_value = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if dbinstance_details[0]['Engine'] not in ['mariadb','oracle-se', 'oracle-ee', 'oracle-se1', 'oracle-se2','sqlserver-ex','sqlserver-se','sqlserver-web','sqlserver-ee','aurora-postgresql','aurora']:        
        if not iam_auth_value:
            #verify instance state  
            while dbinstance_details[0]['DBInstanceStatus'] not in ['available', 'stopped']:
                try:
                    dbinstance_details = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
                    time.sleep(10)
                except ClientError as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                except Exception as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                
            #Apply iam authentication for db-instance
            try:
                result = rds.modify_db_instance(
                    DBInstanceIdentifier = RDSInstanceName,
                    BackupRetentionPeriod = dbinstance_details[0]['BackupRetentionPeriod'],
                    ApplyImmediately = False,
                    EnableIAMDatabaseAuthentication = True
                )
                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "IAM Authentication enabled for rds-instance : %s \n" % RDSInstanceName
                        
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
            output='IAM Authentication already enabled for rds-instance : '+ RDSInstanceName
            print(output)
    else:
        responseCode=200
        output ='IAM Authentication is not supported for rds-instance engine: '+ dbinstance_details[0]['Engine']
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output