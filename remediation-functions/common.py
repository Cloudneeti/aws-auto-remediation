'''
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

def getCredentials(roleArn, roleSessionName='CN-RemSession'):
    sts_client = boto3.client('sts')
    try:
        response = sts_client.assume_role(RoleArn=roleArn,RoleSessionName=roleSessionName)
    except Exception as e:
        print(e)
        raise customException("Error when getting AssumeRole")
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
    return CustAccID, 'arn:aws:iam::' + CustAccID + ':role/CN-Auto-Remediation-Role'

def getRoleArn_cwlogs(event):
    try:
        CustAccID = event["accountId"]
        if len(CustAccID) < 12:
            return "", customException("Error when parsing the Post message body")
    except:
        return "", customException("Error when parsing the Post message body")
    return CustAccID, 'arn:aws:iam::' + CustAccID + ':role/CN-Auto-Remediation-Role'
    
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