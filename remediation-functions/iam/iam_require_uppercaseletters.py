'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Password policy uppercase
'''

from botocore.exceptions import ClientError
import boto3

def run_remediation(iam_client, params):
    print("Executing remediation")  
    
    try:
        # Get current policy details
        password_configuration = iam_client.get_account_password_policy()['PasswordPolicy']
    except:
        iam_resource = boto3.resource('iam', aws_access_key_id=params['aws_access_key_id'], aws_secret_access_key=params['aws_secret_access_key'],aws_session_token=params['aws_session_token'])
        account_password_policy = iam_resource.create_account_password_policy(
            MinimumPasswordLength=14,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True,
            AllowUsersToChangePassword=False,
            MaxPasswordAge=90,
            PasswordReusePrevention=24,
            HardExpiry=False
        )
        password_configuration = iam_client.get_account_password_policy()['PasswordPolicy']
    
    try:
        password_configuration["MaxPasswordAge"]
        password_configuration["PasswordReusePrevention"]
        password_configuration["HardExpiry"]
    except:
        password_configuration["MaxPasswordAge"] = 90
        password_configuration["PasswordReusePrevention"] = 24
        password_configuration["HardExpiry"] = False            
            
    try:
        result = iam_client.update_account_password_policy(
            MinimumPasswordLength=password_configuration["MinimumPasswordLength"],
            RequireSymbols=password_configuration["RequireSymbols"],
            RequireNumbers=password_configuration["RequireNumbers"],
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=password_configuration["RequireLowercaseCharacters"],
            AllowUsersToChangePassword=password_configuration["AllowUsersToChangePassword"],
            MaxPasswordAge=password_configuration["MaxPasswordAge"],
            PasswordReusePrevention=password_configuration["PasswordReusePrevention"],
            HardExpiry=password_configuration["HardExpiry"]
        )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error:" + str(result) + "\n"
        else:
            output = "Account Password Policy to require uppercase updated successfully \n" 
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output