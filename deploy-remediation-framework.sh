#!/bin/bash

: '
#SYNOPSIS
    Deployment of Remediation Framework.
.DESCRIPTION
    This script will deploy all the services required for the remediation framework.
.NOTES
    Version: 2.0
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
            Default region name: AWS region name (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)
.EXAMPLE
    Command to execute : bash deploy-remediation-framework.sh [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v <2.0>] [-s <list of regions where auto-remediation is to enabled>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    **Mandatory(-p)AWS Region: Region where you want to deploy all major components of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by Cloudneeti)
    (-s)Region list: Comma seperated list(with no spaces) of the regions where the auto-remediation is to be enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you want to enable auto-remediation in all other available regions
        **Pass "na" if you do not want to enable auto-remediation in any other region
.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v <2.0>] [-s <list of regions where auto-remediation is to enabled>]" 1>&2; exit 1; }
env="dev"
version="2.0"
secondaryregions=('na')
while getopts "a:p:e:v:s:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        p)
            primaryregion=${OPTARG}
            ;;
        e)
            env=${OPTARG}
            ;;
        v)
            version=${OPTARG}
            ;;
        s) secondaryregions=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))
valid_values=( "na" "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

#Verify input for regional deployment
if [[ $secondaryregions == "na" ]]; then
    valid_regions=${valid_values[0]}
elif [[ $secondaryregions == "all" ]]; then
    valid_regions=("${valid_values[@]:1:15}")
else
    valid_regions="${secondaryregions[@]}"
fi

IFS=, read -a valid_regions <<<"${valid_regions[@]}"
printf -v ips ',"%s"' "${valid_regions[@]}"
ips="${ips:1}"
valid_regions=($(echo "${valid_regions[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

#Validating user input for custom regions  
secondary_regions=()
for valid_val in "${valid_values[@]}"; do
    for valid_reg in "${valid_regions[@]}"; do
        if [[ $valid_val == $valid_reg ]]; then
            secondary_regions+=("$valid_val")
        fi
    done
    if [[ $valid_val != "na" ]] && [[ $primaryregion == $valid_val ]]; then
        primary_deployment=$primaryregion
    fi
done


#validate aws account-id and region
if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ $primary_deployment == "" ]]; then
    usage
fi

#Verify deployment of remediation framework
cd remediation-functions/

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Checking if the remediation framework already exists in the configured account....."

orches_role_det="$(aws iam get-role --role-name CN-Remediation-Invocation-Role 2>/dev/null)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

invoker_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Invoker 2>/dev/null)"
invoker_role=$?

CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $primary_deployment 2>/dev/null)"
CT_status=$?

Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator --region $primary_deployment 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

#Update existing remediation framework
if [[ "$orches_role" -eq 0 ]] || [[ "$Rem_role" -eq 0 ]] || [[ "$CT_status" -eq 0 ]] || [[ "$Lambda_status" -eq 0 ]] || [[ "$s3_status" -eq 0 ]] || [[ "$invoker_role" -eq 0 ]]; then
	echo "Remediation components already exist. Attempting to redploy framework with latest updates !"

    if [[ "$s3_status" -eq 0 ]]; then
        echo "Redploying framework....."
        serverless deploy --env $env-$acc_sha --aws-account-id $awsaccountid --region $primary_deployment --remediationversion $version
        lambda_status=$?

        if [[ $lambda_status -eq 0 ]]; then
            echo "Successfully deployed remediation framework with latest updates!!"
        else
            echo "Something went wrong! Please contact Cloudneeti support for more details"
        fi
    else
        echo "Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !"
        exit 1
    fi
else
    #Deploy framework from scratch
    echo "Deploying remediation framework...."
    aws cloudformation deploy --template-file deployment-bucket.yml --stack-name cn-rem-$env-$acc_sha --parameter-overrides Stack=cn-rem-$env-$acc_sha awsaccountid=$awsaccountid region=$primary_deployment --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    s3_status=$?
    if [[ "$s3_status" -eq 0 ]]; then
        serverless deploy --env $env-$acc_sha --aws-account-id $awsaccountid --region $primary_deployment --remediationversion $version
        lambda_status=$?
    else
        echo "Something went wrong! Please contact Cloudneeti support for more details"
        exit 1
    fi
fi

#Regional deployments for framework
cd ..
cd regional-deployment/
echo "Configure Regional Deployments...."

if [[ "$secondary_regions" -ne "na" ]] & [[ "$s3_status" -eq 0 ]]; then
    #Deploy Regional Stack
    for region in "${secondary_regions[@]}"; do
        if [[ "$region" != "$primary_deployment" ]]; then
            Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $region 2>/dev/null)"
            Lambda_status=$?

            Regional_stack="$(aws cloudformation describe-stacks --stack-name cn-rem-$env-$region-$acc_sha --region $region 2>/dev/null)"
            Regional_stack_status=$?
            
            if [[ "$Regional_stack_status" -ne 0 ]] & [[ "$Lambda_status" -eq 0 ]]; then
                echo "Region $region is not configured because of existing resources, please delete them and redeploy framework to configure this region"
            else
                aws cloudformation deploy --template-file region-function-deployment-singleacc.yml --stack-name cn-rem-$env-$region-$acc_sha --parameter-overrides Stack=cn-rem-$env-$region-$acc_sha awsaccountid=$awsaccountid region=$region remediationregion=$primary_deployment --region $region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                Regional_stack_status=$?

                if [[ "$Regional_stack_status" -eq 0 ]]; then
                    echo "Successfully configured region $region in remediation framework"
                else
                    echo "Failed to configure region $region in remediation framework"
                fi
            fi
        fi
    done
else
    echo "Regional Deployments skipped with input na!.."
fi

if [[ $lambda_status -eq 0 ]]; then
    echo "Successfully deployed remediation framework!!"
else
    echo "Something went wrong! Please contact Cloudneeti support for more details"
fi