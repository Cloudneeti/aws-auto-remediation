'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

IAM sub-orchestrator function
'''

import json
import boto3
import common
from botocore.exceptions import ClientError
from iam import *

def lambda_handler(event, context):
    global aws_access_key_id, aws_secret_access_key, aws_session_token, CustAccID
    
    try:
        PolicyId = json.loads(event["body"])["PolicyId"]
    except:
        PolicyId = ''
        pass

    if not PolicyId:
        print("Executing auto-remediation")
        params = {}
        try:  # common code
            CustAccID, role_arn = common.getRoleArn_cwlogs(event)
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(role_arn)
            params = {
                        "aws_access_key_id": aws_access_key_id,
                        "aws_secret_access_key": aws_secret_access_key,
                        "aws_session_token": aws_session_token
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

        try:
            records_json = json.loads(event["policies"])
            records = records_json["RemediationPolicies"]
        except:
            pass

        try:
            # Establish a session with the portal
            iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token)  
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
            
        
        if "IAMPasswordRequiredNumber" in str(records):
            try:       
                iam_require_numbers.run_remediation(iam_client, params)
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

        if "IAMPasswordUpCaseLetter" in str(records):
            try:
                iam_require_uppercaseletters.run_remediation(iam_client, params)    
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

        if "IAMPasswordRequiredSymbols" in str(records):  
            try: 
                iam_require_symbols.run_remediation(iam_client, params)
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
            
        if "IAMRequireLowercaseLetter" in str(records):  
            try:
                iam_require_lowercaseletters.run_remediation(iam_client, params) 
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

        if "IAMMinPasswordLength" in str(records):
            try:
                iam_minimum_passwordlength.run_remediation(iam_client, params) 
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

        if "IAMExpirePasswords" in str(records):
            try:
                iam_password_expiration.run_remediation(iam_client, params) 
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

        if "IAMPasswordReusePrevention" in str(records):
            try:
                iam_password_reuse.run_remediation(iam_client, params) 
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

        print("Remediated IAM policies")
            #returning the output Array in json format
        return {  
            'statusCode': 200,
            'body': json.dumps("Remediated IAM policies")
        }

    else:
        print("CN-portal triggered remediation")
        try:  # common code
            CustAccID, role_arn = common.getRoleArn(event)
            aws_access_key_id, aws_secret_access_key, aws_session_token = common.getCredentials(role_arn)
            params = {
                        "aws_access_key_id": aws_access_key_id,
                        "aws_secret_access_key": aws_secret_access_key,
                        "aws_session_token": aws_session_token
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

        try:
            # Establish a session with the portal
            iam_client = boto3.client('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token)  
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
            responseCode = 400
            output = "Policies not configured"
            
            if PolicyId == "IAMPasswordRequiredNumber":     
                responseCode,output = iam_require_numbers.run_remediation(iam_client, params)

            if PolicyId == "IAMPasswordUpCaseLetter":        
                responseCode,output = iam_require_uppercaseletters.run_remediation(iam_client, params)

            if PolicyId == "IAMPasswordRequiredSymbols":       
                responseCode,output = iam_require_symbols.run_remediation(iam_client, params)
                
            if PolicyId == "IAMRequireLowercaseLetter":       
                responseCode,output = iam_require_lowercaseletters.run_remediation(iam_client, params) 

            if PolicyId == "IAMMinPasswordLength":       
                responseCode,output = iam_minimum_passwordlength.run_remediation(iam_client, params)     

            if PolicyId == "IAMExpirePasswords":       
                responseCode,output = iam_password_expiration.run_remediation(iam_client, params) 

            if PolicyId == "IAMPasswordReusePrevention":       
                responseCode,output = iam_password_reuse.run_remediation(iam_client, params)               

        except ClientError as e:
            responseCode = 400
            output = "Unable to remediate IAM Policies: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unable to remediate IAM Policies: " + str(e)
            # returning the output Array in json format
        return {  
            'statusCode': responseCode,
            'body': output
        }
