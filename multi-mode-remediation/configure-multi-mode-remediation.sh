#!/bin/bash

: '
#SYNOPSIS
    Enable Remediation.
.DESCRIPTION
    This script will deploy all the services required for the remediation framework and enable remediation for this account.
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
    Command to execute : bash deploy-remediation-framework.sh [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>] [-m <list of regions where remediation is to enabled>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account for which you want to enable the remediation
    **Mandatory(-r)Remediation Account Id: 12-digit AWS account Id of the account where the remediation framework is deployed
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by Cloudneeti)
    (-m)Region list: Comma seperated list(with no spaces) of the regions where the remediation is to be enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you want to enable remediation in all other available regions
        **Pass "na" if you do not want to enable remediation in any other region
.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>] [-m <list of regions where remediation is to enabled>]" 1>&2; exit 1; }

env="dev"
version="1.0"
regionlist=('all')
while getopts "a:e:v:m:" o; do
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
        v)
            version=${OPTARG}
            ;;
		m) regionlist=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))
Valid_values=( "na" "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

#Verify input for regional deployment
if [[ $regionlist == "na" ]]; then
    input_regions=${Valid_values[0]}
else
    input_regions="${regionlist[@]}"
fi

IFS=, read -a input_regions <<<"${regionlist}"
printf -v ips ',"%s"' "${input_regions[@]}"
ips="${ips:1}"

input_regions=($(echo "${input_regions[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

if [[ $regionlist == "all" ]]; then
    input_regions=("${Valid_values[@]:1:15}")
fi

#Validating user input for custom regions  
validated_regions=()
for i in "${Valid_values[@]}"; do
    for j in "${input_regions[@]}"; do
        if [[ $i == $j ]]; then
            validated_regions+=("$i")
        fi
    done
done

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]]; then
    usage
fi

aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"

env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Checking if the remediation is already enabled for the account....."

invoker_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Invoker 2>/dev/null)"
invoker_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region 2>/dev/null)"
CT_status=$?

Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $aws_region 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-multirem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$invoker_role" -eq 0 ]] || [[ "$Rem_role" -eq 0 ]] || [[ "$CT_status" -eq 0 ]] || [[ "$Lambda_status" -eq 0 ]] || [[ "$s3_status" -eq 0 ]]; then
	echo "Remediation components already exist. Attempting to redploy framework with latest updates !"
    #Redeploy framework
    if [[ "$s3_status" -eq 0 ]]; then
        echo "Redploying framework....."
        aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name cn-multirem-$env-$acc_sha --parameter-overrides Stack=cn-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$remawsaccountid region=$aws_region remediationregion=$aws_region --region $aws_region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
        Lambda_status=$?

        if [[ $Lambda_status -eq 0 ]]; then
            echo "Successfully deployed remediation framework with latest updates!!"
        else
            echo "Something went wrong! Please contact Cloudneeti support for more details"
            exit 1
        fi
    else
        echo "Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !"
        exit 1
    fi
else
    #Deploy framework from scrach
    echo "Deploying remediation framework...."
    aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name cn-multirem-$env-$acc_sha --parameter-overrides Stack=cn-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$remawsaccountid region=$i remediationregion=$aws_region --region $aws_region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    Lambda_status=$?

    if [[ $lambda_status -eq 0 ]]; then
        echo "Successfully deployed remediation framework with latest updates!!"
    else
        echo "Something went wrong! Please contact Cloudneeti support for more details"
        exit 1
    fi
fi

#Regional deployments for framework
cd ..
cd regional-deployment/
echo "Configure Regional Deployments...."

if [[ "$validated_regions" -ne "na" ]]; then
    if [[ "$bucket_status" -eq 0 ]]; then
    #Deploy Regional Stack
        for i in "${validated_regions[@]}"; do
            if [[ "$i" != "$aws_region" ]]; then
                aws cloudformation deploy --template-file region-deployment-multiacc.yml --stack-name cn-multirem-$env-$i-$acc_sha --parameter-overrides Stack=cn-rem-$env-$i-$acc_sha awsaccountid=$awsaccountid region=$i remediationregion=$aws_region --region $i --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $i 2>/dev/null)"
                Lambda_status=$?
                if [[ "$Lambda_status" -eq 0 ]]; then
                    echo "Successfully configured region $i in remediation framework"
                else
                    echo "Failed to configure region $i in remediation framework"
                fi
            fi
        done
    else
        echo "Bucket not found Something went wrong! Please contact Cloudneeti support for more details"
        exit 1
    fi
else
    echo "Regional Deployments skipped with input na!.."
fi

if [[ $lambda_status -eq 0 ]]; then
    echo "Successfully deployed remediation framework!!"
else
    echo "Something went wrong! Please contact Cloudneeti support for more details"
fi