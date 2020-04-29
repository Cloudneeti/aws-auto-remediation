'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

cloudformation sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from cloudformation import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID, Region
    
    try:
        PolicyId = json.loads(event["body"])["PolicyId"]
    except:
        PolicyId = ''
        pass

    if not PolicyId:
        print("Executing auto-remediation")
        try:  # common code
            CustAccID, role_arn = common.getRoleArn_cwlogs(event)
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(role_arn)
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }

        try:
            Region = event["Region"]
            StackName = event["StackName"]
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            cloudformation = boto3.client('cloudformation', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }
        
        if "StackTermination" in str(records):
            try:
                cloudformation_termination_protection.run_remediation(cloudformation,StackName)
                print('remediated-' + StackName)
                #returning the output Array in json format
                return {  
                    'statusCode': 200,
                    'body': json.dumps('remediated-' + StackName)
                }
            except ClientError as e:
                print(e)
                return {  
                    'statusCode': 400,
                    'body': str(e)
                }
            except Exception as e:
                print(e)
                return {
                    'statusCode': 400,
                    'body': str(e)
                }   
        

    else:
        print("CN-portal triggered remediation")
        try:
            CustAccID, role_arn = common.getRoleArn(event)
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(role_arn)
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }

        try:
            Region_name = json.loads(event["body"])["Region"]
            Region = common.getRegionName(Region_name)
            StackName = json.loads(event["body"])["ResourceName"]
        except:
            Region = ""

        try:
            # Establish a session with the portal
            cloudformation = boto3.client('cloudformation', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token,region_name=Region)  
        except ClientError as e:
            print(e)
            return {  
                'statusCode': 400,
                'body': str(e)
            }
        except Exception as e:
            print(e)
            return {
                'statusCode': 400,
                'body': str(e)
            }

        try:
            if PolicyId == "StackTermination":  
                responseCode,output = cloudformation_termination_protection.run_remediation(cloudformation,StackName)
        
        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate Cloudformation stack: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate Cloudformation stack: " + str(e)

            # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }