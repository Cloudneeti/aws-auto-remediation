#!/bin/bash

: '
#SYNOPSIS
    Disable Remediation.
.DESCRIPTION
    This script will remove all the services deployed for the remediation framework and disbale remediation for the account.
.NOTES
    Version: 1.0

    # PREREQUISITE
      - Install aws cli
        Link : https://docs.aws.amazon.com/cli/latest/userguide/install-linux-al2017.html
      - Before running this script, you need to delete the associated remediation s3-bucket
        Bucket name is as follows : cn-rem-{environment-prefix}-{account-id-hash}
      - Configure your aws account using the below command:
        aws configure
        Enter the required inputs:
            AWS Access Key ID: Access key of any admin user of the account in consideration.
            AWS Secret Access Key: Secret Access Key of any admin user of the account in consideration
            Default region name: Programmatic region name where you want to deploy the framework (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash decommission-multi-mode-remediation.sh [-a <12-digit-account-id>] [-e <environment-prefix>]

.INPUTS
    (-a)Account Id: 12-digit AWS account Id of the account for which you want to disbale remediation  
    (-e)Environment prefix: Enter any suitable prefix for your deployment

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>] " 1>&2; exit 1; }

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

if [[ "$env" == "" ]] ||  [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-aws-remediate-$env-$acc_sha 2>/dev/null)"
stack_staus=$?

if [[ $stack_staus -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
    exit 1
fi

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

echo "Checking if the deployment bucket was correctly deleted... "

if [[ $s3_status -eq 0 ]]; then
    echo "Deployment bucket is still not deleted. Please delete cn-rem-$env-$acc_sha and try to re-run the script again."
    exit 1
fi

echo "Deleting deployment stack..."
if ( test ! -z "$awsaccountid" && test ! -z "$env" )
then
    aws cloudformation delete-stack --stack-name cn-aws-remediate-$env-$acc_sha 2>/dev/null
    lambda_status=$?
	aws cloudformation delete-stack --stack-name $env-$acc_sha 2>/dev/null
    bucket_status=$?
else
    aws cloudformation delete-stack --stack-name cn-aws-remediate-multirem-acc-$acc_sha 2>/dev/null
    lambda_status=$?
	aws cloudformation delete-stack --stack-name multirem-acc-$acc_sha 2>/dev/null
    bucket_status=$?	
fi

if [[ $lambda_status -eq 0 ]] && [[ $bucket_status -eq 0 ]]; then
    echo "Successfully deleted deployment stack!"
else
    echo "Something went wrong! Please contact Cloudneeti support!"
fi