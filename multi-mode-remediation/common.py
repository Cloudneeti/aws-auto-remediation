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

def getRemRoleArn(event):
    try:
        CustAccID = json.loads(event['body'])['RemediationAWSAccountId']
        if len(CustAccID) < 12:
            return "", customException("Error when parsing the Post message body")
    except:
        return "", customException("Error when parsing the Post message body")
    return CustAccID, 'arn:aws:iam::' + CustAccID + ':role/CN-Remediation-Invocation-Role'
