#!/bin/bash

: '

#SYNOPSIS
    Validate Deployment of Remediation Framework.
.DESCRIPTION
    This script will check the deployment status of the critical components of the remediation framework.

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 2.1
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
            Default region name: AWS region name (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)
.EXAMPLE
    Command to execute : bash verify-remediation-setup.sh [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions where auto-remediation is to be verified>]
.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    **Mandatory(-p)AWS Region: Region where you want to deploy all major components of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-s)Region list: Comma seperated list(with no spaces) of the regions where the auto-remediation is to be verified(eg: us-east-1,us-east-2)
        **Pass "all" if you want to verify auto-remediation in all other available regions
        **Pass "na" if you do not want to verify auto-remediation in any other region
.OUTPUTS
    None
'
usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions where auto-remediation is to be verified>]" 1>&2; exit 1; }
env="dev"
version="2.1"
secondaryregions=('na')
while getopts "a:p:e:s:" o; do
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
        s) secondaryregions=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))
valid_values=( "na" "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

echo "Verifying if pre-requisites are set-up.."
sleep 5
if [[ "$(which serverless)" != "" ]] && [[ "$(which aws)" != "" ]] && [[ "$(which jq)" != "" ]];then
    echo "All pre-requisite packages are installed!!"
else
    echo "Package(s)/tool(s) mentioned as pre-requisites have not been correctly installed. Please verify the installation and try re-running the script."
    exit 1
fi

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
if [[ "$env" == "" ]] || [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ $primary_deployment == "" ]]; then
    usage
fi

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name zcspm-rem-$env-$acc_sha --region $primary_deployment 2>/dev/null)"
stack_status=$?

echo "Validating environment prefix..."

if [[ $stack_status -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
    exit 1
fi

echo "Verifying role deployment...."
orches_role_det="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Role)"
Rem_role=$?

echo "Verifying Cloudtrail deployment...."
CT_det="$(aws cloudtrail get-trail-status --name zcspm-remediation-trail --region $primary_deployment)"
CT_status=$?

CT_log="$(aws cloudtrail get-trail-status --name zcspm-remediation-trail --region $primary_deployment | jq -r '.IsLogging')"

echo "Verifying Lambda deployment...."
Lambda_det="$(aws lambda get-function --function-name zcspm-aws-remediate-orchestrator --region $primary_deployment)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket zcspm-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$orches_role" -ne 0 ]] && [[ "$Rem_role" -ne 0 ]] && [[ "$CT_status" -ne 0 ]] && [[ "$Lambda_status" -ne 0 ]] && [[ "$s3_status" -ne 0 ]]; then
   echo "Remediation framework is not deployed"
elif [[ "$orches_role" -ne 0 ]] || [[ "$Rem_role" -ne 0 ]];
then
   echo "Required roles not found. Please delete and redeploy the framework"
elif [[ "$Lambda_status" -ne 0 ]];
then
   echo "Remediation functions not found. Please delete and redeploy the framework"
elif [[ "$CT_status" -ne 0 ]] || [[ "$CT_log" -ne true ]];
then
   echo "Remediation framework cloudtrail trail is not deployed correctly. Please delete and redeploy the framework"
elif [[ "$s3_status" -ne 0 ]];
then
   echo "Remediation framework s3-bucket is not deployed correctly or deleted. Please delete and redeploy the framework"
elif [[ "$orches_role" -eq 0 ]] && [[ "$Rem_role" -eq 0 ]] && [[ "$CT_status" -eq 0 ]] && [[ "$Lambda_status" -eq 0 ]] && [[ "$s3_status" -eq 0 ]];
then
   echo "Remediation framework is correctly deployed"
else
   echo "Something went wrong!"
fi

echo "Verifying Regional Configuration...."

Invoker_rem_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Invoker)"
Invoker_Rem_role=$?

if [[ "$secondary_regions" -ne "na" ]] && [[ "$s3_status" -eq 0 ]]; then
    #Deploy Regional Stack
    for region in "${secondary_regions[@]}"; do
        if [[ "$region" != "$primary_deployment" ]]; then
            regional_stack_detail="$(aws cloudformation describe-stacks --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null)"
            regional_stack_status=$?

            Invoker_Lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $region 2>/dev/null)"
            Invoker_Lambda_status=$?

            if [[ "$regional_stack_status" -ne 0 ]] && [[ "$Invoker_Lambda_status" -ne 0 ]];
            then
                echo "Remediation framework is not configured in region $region. Please redploy the framework with region $region as input"
            elif [[ "$Invoker_Lambda_status" -ne 0 ]];
            then
                echo "Remediation framework is not configured in region $region. Please redploy the framework with region $region as input"
            elif [[ "$regional_stack_status" -ne 0 ]];
            then
                echo "Remediation framework is not configured in region $region. Please redploy the framework with region $region as input"
            elif [[ "$regional_stack_status" -eq 0 ]] && [[ "$Invoker_Lambda_status" -eq 0 ]] && [[ "$Invoker_Rem_role" -eq 0 ]];
            then
                echo "Remediation framework is correctly deployed in region $region"
            else
                echo "Something went wrong!"
            fi
        else
            echo "Region $primary_deployment is configured as primary region."
        fi
    done
else
    echo "Regional Deployments verification skipped with input na!.."
fi

echo "Verifying Global Services Integration...."
global_stack="$(aws cloudformation describe-stacks --stack-name zcspm-rem-global-resources-$env-$acc_sha --region "us-east-1" 2>/dev/null)"
global_stack_detail=$?

if [[ "$global_stack_detail" -eq 0 ]]; then
    echo "Global Services Auto Remediation is enabled"
else
    echo "Global Services Auto Remediation is disabled"
fi