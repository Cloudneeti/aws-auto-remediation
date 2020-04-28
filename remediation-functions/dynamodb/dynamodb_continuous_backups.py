'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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