'''
Password policy password length
'''

from botocore.exceptions import ClientError

def run_remediation(iam_client):
    print("Executing remediation")     
    
    try:
        # Get current policy details
        password_configuration = iam_client.get_account_password_policy()['PasswordPolicy']
    except:
        iam_resource = boto3.resource('iam', aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key,aws_session_token=aws_session_token)
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
    except:
        password_configuration["MaxPasswordAge"] = 90
        password_configuration["PasswordReusePrevention"] = 24

    if password_configuration["MinimumPasswordLength"] < 14:             
            
        try:
            result = iam_client.update_account_password_policy(
                MinimumPasswordLength=14,
                RequireSymbols=password_configuration["RequireSymbols"],
                RequireNumbers=password_configuration["RequireNumbers"],
                RequireUppercaseCharacters=password_configuration["RequireUppercaseCharacters"],
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
                output = "Account Password Policy for password length updated successfully \n" 
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
        output = "Account Password Policy already updated"

    print(str(responseCode)+'-'+output)
    return responseCode,output