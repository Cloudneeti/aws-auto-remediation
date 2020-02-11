'''
RDS instance performance insights
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")
    performance_insights=''
    #Verify performance insights configuration for db-instance 
    try:
        response = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        DBInstanceClass = response[0]['DBInstanceClass']
        performance_insights = response[0]['PerformanceInsightsEnabled']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)

    if DBInstanceClass not in ['db.t2.micro', 'db.t2.small', 'db.t3.micro', 'db.t3.small']:
        if not performance_insights:
            #Apply performance insights for db-instance
            try:
                result = rds.modify_db_instance(
                    DBInstanceIdentifier = RDSInstanceName,
                    BackupRetentionPeriod = response[0]['BackupRetentionPeriod'],
                    ApplyImmediately = False,
                    EnablePerformanceInsights = True
                )
                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "Performance insights enabled for rds-instance : %s \n" % RDSInstanceName
                        
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
            output = 'Performance insights already enabled for rds-instance : '+ RDSInstanceName
            print(output)
    else:
        responseCode=200
        output = 'Performance insights is not supported for rds-instance : '+ RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output