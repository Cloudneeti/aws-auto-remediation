'''
Global resources are included into Amazon Config service
'''

from botocore.exceptions import ClientError

def run_remediation(config, table_name):
    print("Executing config table remediation")

    current_retention = ''

    try:
        response = config.describe_continuous_backups(TableName=table_name)['ContinuousBackupsDescription']
        current_retention=response[0]['ContinuousBackupsStatus']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not current_retention: 
        try:
            result = config.update_continuous_backups(
                                TableName=table_name,
                                PointInTimeRecoverySpecification={
                                    'PointInTimeRecoveryEnabled': True
                                })

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled continuous backups for : %s \n" % table_name
                    
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
        output = "config table is already compliant"

    print(str(responseCode)+'-'+output)
    return responseCode,output