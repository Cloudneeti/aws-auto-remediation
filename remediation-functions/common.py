'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

common code
'''

import boto3
import json

def customErrorResponse(statusCode=401, errorMessage="Custom Error Message"):
    headers = { "Content-Type" : "application/json" }
    return {
        'statusCode': statusCode,
        'headers': headers,
        'body': json.dumps(errorMessage)
    }

class customException(Exception):
    def __init__(self, errMsg="Custom Error Message"):
        self.errorMessage = errMsg

    def __str__(self):
        return self.errorMessage

def getCredentials(roleArn, roleSessionName='ZCSPM-RemSession'):
    sts_client = boto3.client('sts')
    try:
        response = sts_client.assume_role(RoleArn=roleArn,RoleSessionName=roleSessionName)
    except Exception as e:
        print(e)
        raise customException("Error while trying to AssumeRole")
    cred = response['Credentials']
    return cred['AccessKeyId'], cred['SecretAccessKey'], cred['SessionToken']

# Handles the body in the post message and returns the roleArn 
def getRoleArn(event):
    try:
        CustAccID = json.loads(event['body'])['AWSAccountId']
        if len(CustAccID) < 12:
            return "", customException("Error when parsing the Post message body")
    except:
        return "", customException("Error when parsing the Post message body")
    return CustAccID, 'arn:aws:iam::' + CustAccID + ':role/ZCSPM-Auto-Remediation-Role'

def getRoleArn_cwlogs(event):
    try:
        CustAccID = event["accountId"]
        if len(CustAccID) < 12:
            return "", customException("Error when parsing the Post message body")
    except:
        return "", customException("Error when parsing the Post message body")
    return CustAccID, 'arn:aws:iam::' + CustAccID + ':role/ZCSPM-Auto-Remediation-Role'
    
def getRegionName(Region):
    RegionDetail = {
                  "US East (N. Virginia)" : "us-east-1",
                  "US East (Ohio)" : "us-east-2",
                  "US West (N. California)" : "us-west-1",
                  "US West (Oregon)" : "us-west-2",
                  "Asia Pacific (Mumbai)" : "ap-south-1",
                  "Asia Pacific (Seoul)" : "ap-northeast-2",
                  "Asia Pacific (Singapore)" : "ap-southeast-1",
                  "Asia Pacific (Sydney)" : "ap-southeast-2",
                  "Asia Pacific (Tokyo)" : "ap-northeast-1",
                  "Canada (Central)" : "ca-central-1",
                  "EU (Frankfurt)" : "eu-central-1",
                  "EU (Ireland)" : "eu-west-1",
                  "EU (London)" : "eu-west-2",
                  "EU (Paris)" : "eu-west-3",
                  "EU (Stockholm)" : "eu-north-1",
                  "South America (São Paulo)" : "sa-east-1",
                  "Asia Pacific (Hong Kong)" :  "ap-east-1"
                }
    if RegionDetail[Region]:
        return RegionDetail[Region]
    else:
        return Region