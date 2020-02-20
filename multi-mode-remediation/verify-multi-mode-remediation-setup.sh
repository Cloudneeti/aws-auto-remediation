#!/bin/bash

: '
#SYNOPSIS
    Validate if Remediation is enabled or not.
.DESCRIPTION
    This script will check the deployment status of the critical components of the remediation framework.
.NOTES
    Version: 1.0

    # PREREQUISITE
      - Install aws cli
        Link : https://docs.aws.amazon.com/cli/latest/userguide/install-linux-al2017.html
      - Install json parser jq
        Installation command: sudo apt-get install jq
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
      - Configure your aws account using the below command:
        aws configure
        Enter the required inputs:
            AWS Access Key ID: Access key of any admin user of the account in consideration.
            AWS Secret Access Key: Secret Access Key of any admin user of the account in consideration
            Default region name: Programmatic region name where you want to deploy the framework (eg: us-east-1)
            Default output format: json  
      - Command to execute : bash verify-multi-mode-remediation-setup.sh [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-e <environment-prefix>]

.INPUTS
    (-a)New AWS Account Id: 12-digit AWS Account Id of the account which is newly added to use the remediation framework
    (-r)Remediation Account Id: 12-digit AWS account Id of the account where the remediation framework is deployed
    (-e)Environment prefix: Enter any suitable prefix for your deployment

.OUTPUTS
    None
'
usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-e <environment-prefix>] " 1>&2; exit 1; }

env="dev"
version="1.0"
while getopts "a:r:e:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        r)
            remawsaccountid=${OPTARG}
            ;;
        e)
            env=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [[ "$env" == "" ]] || [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]]; then
    usage
fi

aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-rem-$env-$acc_sha --region $aws_region 2>/dev/null)"
stack_status=$?

echo "Validating environment prefix..."
sleep 5

if [[ $stack_status -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
    exit 1
fi

echo "Verifying role deployment...."
relay_role_det="$(aws iam get-role --role-name CN-RelayFunctionRole 2>/dev/null)"
relay_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

echo "Verifying Cloudtrail deployment...."
CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region 2>/dev/null)"
CT_status=$?

CT_log="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region | jq -r '.IsLogging' 2>/dev/null)"

echo "Verifying Lambda deployment...."
Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-relayfunction --region $aws_region 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$relay_role" -ne 0 ]] && [[ "$Rem_role" -ne 0 ]] && [[ "$CT_status" -ne 0 ]] && [[ "$Lambda_status" -ne 0 ]] && [[ "$s3_status" -ne 0 ]]; then
   echo "Remediation framework is not deployed"
elif [[ "$relay_role" -ne 0 ]] || [[ "$Rem_role" -ne 0 ]];
then
   echo "Remediation framework roles are not deployed. Please delete and redploy the framework"
elif [[ "$Lambda_status" -ne 0 ]];
then
   echo "Remediation framework lambda functions are not deployed. Please delete and redploy the framework"
elif [[ "$CT_status" -ne 0 ]] || [[ "$CT_log" -ne true ]];
then
   echo "Remediation framework CLoudtrail is not deployed correctly. Please delete and redploy the framework"
elif [[ "$s3_status" -ne 0 ]];
then
   echo "Remediation framework s3-bucket is not deployed correctly or deleted. Please delete and redploy the framework"
elif [[ "$relay_role" -eq 0 ]] && [[ "$Rem_role" -eq 0 ]] && [[ "$CT_status" -eq 0 ]] && [[ "$Lambda_status" -eq 0 ]] && [[ "$s3_status" -eq 0 ]];
then
   echo "Remediation framework is correctly deployed"
else
   echo "Something went wrong!"
fi

echo "............."
echo "Verifying if role in the remediation framework is correctly deployed or not!"
rem_role="$(aws sts assume-role --role-arn arn:aws:iam::$remawsaccountid:role/CN-Remediation-Invocation-Role --role-session-name cn-session 2>/dev/null)"
rem_role_status=$?
if [[ $rem_role_status -ne 0 ]]; then
    echo "The role in the account with remediation framework is not updated with the current account details! Please run update-remediation-role.sh to update the role!"
else
    echo "Remediation account role is correctly updated!!"
fi