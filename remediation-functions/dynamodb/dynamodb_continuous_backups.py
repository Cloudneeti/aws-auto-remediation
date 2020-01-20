'''
Enable DynamoDB table continuous backups
'''

from botocore.exceptions import ClientError

def run_remediation(dynamodb, DynamodbTableName):
    print("Executing DynamoDB table remediation")

    continuous_backup = ''

    try:
        response = dynamodb.describe_continuous_backups(TableName=DynamodbTableName)['ContinuousBackupsDescription']
        continuous_backup=response[0]['ContinuousBackupsStatus']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not continuous_backup: 
        try:
            result = dynamodb.update_continuous_backups(
                                TableName=DynamodbTableName,
                                PointInTimeRecoverySpecification={
                                    'PointInTimeRecoveryEnabled': True
                                })

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled continuous backups for : %s \n" % DynamodbTableName
                    
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
        output = "dynamodb table is already compliant"

    print(str(responseCode)+'-'+output)
    return responseCode,output