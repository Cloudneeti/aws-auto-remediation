#!/bin/bash

: '
#SYNOPSIS
    Validate Deployment of Remediation Framework.
.DESCRIPTION
    This script will check the deployment status of the critical components of the remediation framework.
.NOTES
    Version: 1.0

    # PREREQUISITE
      - Install aws cli
        Link : https://docs.aws.amazon.com/cli/latest/userguide/install-linux-al2017.html
      - Install json parser jq
        Installation command: sudo apt-get install jq
      - Configure your aws account using the below command:
        aws configure
        Enter the required inputs:
            AWS Access Key ID: Access key of any admin user of the account in consideration.
            AWS Secret Access Key: Secret Access Key of any admin user of the account in consideration
            Default region name: Programmatic region name where you want to deploy the framework (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash verify-remediation-setup.sh [-a <12-digit-account-id>] [-e <environment-prefix>]
.INPUTS
    (-a)Account Id: 12-digit AWS account Id of the account for which you want to verify if remediation framework is deployed or not.
    (-e)Environment prefix: Enter any suitable prefix for your deployment

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>]" 1>&2; exit 1; }

while getopts "a:e:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
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

if [[ "$env" == "" ]] || [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Verifying role deployment...."
orches_role_det="$(aws iam get-role --role-name CN-Remediation-Invocation-Role)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role)"
Rem_role=$?

echo "Verifying Cloudtrail deployment...."
CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail)"
CT_status=$?

CT_log="$(aws cloudtrail get-trail-status --name cn-remediation-trail | jq -r '.IsLogging')"

echo "Verifying Lambda deployment...."
Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$orches_role" -ne 0 ]] && [[ "$Rem_role" -ne 0 ]] && [[ "$CT_status" -ne 0 ]] && [[ "$Lambda_status" -ne 0 ]] && [[ "$s3_status" -ne 0 ]]; then
   echo "Remediation framework is not deployed"
elif [[ "$orches_role" -ne 0 ]] || [[ "$Rem_role" -ne 0 ]];
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
elif [[ "$orches_role" -eq 0 ]] && [[ "$Rem_role" -eq 0 ]] && [[ "$CT_status" -eq 0 ]] && [[ "$Lambda_status" -eq 0 ]] && [[ "$s3_status" -eq 0 ]];
then
   echo "Remediation framework is correctly deployed"
else
   echo "Something went wrong!"
fi