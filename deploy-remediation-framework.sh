#!/bin/bash

: '
#SYNOPSIS
    Deployment of Remediation Framework.
.DESCRIPTION
    This script will deploy all the services required for the remediation framework.
.NOTES
    Version: 1.0

    # PREREQUISITE
      - Install aws cli
        Link : https://docs.aws.amazon.com/cli/latest/userguide/install-linux-al2017.html
      - Install npm 
        Installation commands: 
            - sudo apt-get update
            - sudo apt-get install nodejs
            - sudo apt-get install npm
      - Install serverless
        Installation command:
            - sudo npm install -g serverless
      - Configure your aws account using the below command:
        aws configure
        Enter the required inputs:
            AWS Access Key ID: Access key of any admin user of the account in consideration.
            AWS Secret Access Key: Secret Access Key of any admin user of the account in consideration
            Default region name: Programmatic region name where you want to deploy the framework (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash deploy-remediation-framework.sh [-a <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>]

.INPUTS
    (-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by Cloudneeti)

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>]" 1>&2; exit 1; }

while getopts "a:e:v:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        e)
            env=${OPTARG}
            ;;
        v)
            version=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

cd remediation-functions/

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Checking if the remediation framework already exists in the configured account....."

orches_role_det="$(aws iam get-role --role-name CN-Remediation-Invocation-Role 2>/dev/null)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail 2>/dev/null)"
CT_status=$?

Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$orches_role" -eq 0 ]] || [[ "$Rem_role" -eq 0 ]] || [[ "$CT_status" -eq 0 ]] || [[ "$Lambda_status" -eq 0 ]] || [[ "$s3_status" -eq 0 ]]; then
	echo "Remediation components already exist. Attempting to redploy framework with latest updates !"

    if [[ "$s3_status" -eq 0 ]]; then
        echo "Redploying framework....."
        if ( test ! -z "$env" && test ! -z "$version" )
        then
            serverless deploy --env $env-$acc_sha --aws-account-id $awsaccountid --version $version
            lambda_status=$?
        else
            serverless deploy --env rem-acc-$acc_sha --aws-account-id $awsaccountid --version 1.0
            lambda_status=$?
        fi

        if [[ $lambda_status -eq 0 ]]; then
            echo "Successfully deployed remediation framework with latest updates!!"
        else
            echo "Something went wrong! Please contact Cloudneeti support for more details"
        fi
        exit 1
    else
        echo "Remediation components already exist with a different environment prefix. Please run verify-multi-acc-remediation-setup.py for more details !"
        exit 1
    fi
fi

echo "Deploying remediation framework...."
if ( test ! -z "$env" && test ! -z "$version" )
then
	aws cloudformation deploy --template-file deployment-bucket.yml --stack-name $env-$acc_sha --parameter-overrides Stack=$env-$acc_sha awsaccountid=$awsaccountid --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    bucket_status=$?
    if [[ "$bucket_status" -eq 0 ]]; then
	    serverless deploy --env $env-$acc_sha --aws-account-id $awsaccountid --version $version
        lambda_status=$?
    else
        echo "Something went wrong! Please contact Cloudneeti support for more details"
        exit 1
    fi
else
	aws cloudformation deploy --template-file deployment-bucket.yml --stack-name rem-acc-$acc_sha --parameter-overrides Stack=rem-acc-$acc_sha awsaccountid=$awsaccountid --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    bucket_status=$?
    if [[ "$bucket_status" -eq 0 ]]; then
	    serverless deploy --env rem-acc-$acc_sha --aws-account-id $awsaccountid --version 1.0
        lambda_status=$?
    else
        echo "Something went wrong! Please contact Cloudneeti support for more details"
        exit 1
    fi
fi

if [[ $lambda_status -eq 0 ]]; then
    echo "Successfully deployed remediation framework!!"
else
    echo "Something went wrong! Please contact Cloudneeti support for more details"
fi