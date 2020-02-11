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
        print(continuous_backup)
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  
    
    try:
        table_details = dynamodb.describe_table(TableName=DynamodbTableName)['Table']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e) 

    if not continuous_backup:
        while table_details['TableStatus'] not in ['ACTIVE']:
            try:
                table_details = dynamodb.describe_table(TableName=DynamodbTableName)['Table']
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e) 
        try:
            result = dynamodb.update_continuous_backups(
                                TableName=DynamodbTableName,
                                PointInTimeRecoverySpecification={
                                    'PointInTimeRecoveryEnabled': True
                                })
            print("dynamodb contineous backup updated")
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