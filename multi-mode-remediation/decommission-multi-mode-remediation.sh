#!/bin/bash

: '
#SYNOPSIS
    Disable Remediation.
.DESCRIPTION
    This script will remove all the services deployed for the remediation framework and disbale remediation for the account.
.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 2.0

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
            Default region name: AWS region name (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash decommission-multi-mode-remediation.sh [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions from where the auto-remediation is to be decommissioned>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account for which you want to disbale remediation  
    **Mandatory(-p)AWS Region: Region where you have deployed all major resources of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-s)Region list: Comma seperated list(with no spaces) of the regions from where the auto-remediation is to be decommissioned(eg: us-east-1,us-east-2)
        **Pass "all" if you want to decommission auto-remediation frpm all other available regions
        **Pass "na" if you do not want to decommission auto-remediation from any other region
.OUTPUTS
    None
'
usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions from where the auto-remediation is to be decommissioned>]" 1>&2; exit 1; }

env="dev"
version="2.0"
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

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Validating environment prefix..."
sleep 5

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-multirem-$env-$acc_sha --region $primary_deployment 2>/dev/null)"
stack_status=$?

if [[ $stack_status -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."#
    exit 1
fi

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-multirem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

echo "Checking if the deployment bucket was correctly deleted... "

if [[ $s3_status -eq 0 ]]; then
    echo "Deployment bucket is still not deleted. Please delete cn-multirem-$env-$acc_sha and try to re-run the script again."
    exit 1
fi

echo "Deleting deployment stack..."
#remove termination protection from stack
aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name cn-multirem-$env-$acc_sha --region $primary_deployment 2>/dev/null

#delete main stack
aws cloudformation delete-stack --stack-name cn-multirem-$env-$acc_sha --region $primary_deployment 2>/dev/null
Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
Lambda_status=$?

echo "Deleting Regional Deployments...."

if [[ "$secondary_regions" -ne "na" ]]; then
    #Delete Regional Stack
    for region in "${secondary_regions[@]}"; do
        if [[ "$region" != "$primary_deployment" ]]; then
            stack_detail="$(aws cloudformation describe-stacks --stack-name cn-multirem-$env-$region-$acc_sha --region $region 2>/dev/null)"
            stack_status=$?

            if [[ $stack_status -eq 0 ]]; then
                #remove termination protection
                aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name cn-multirem-$env-$region-$acc_sha --region $region 2>/dev/null
                #delete stack from other regions
                aws cloudformation delete-stack --stack-name cn-multirem-$env-$region-$acc_sha --region $region
            else
                echo "Region $region is not configured in remediation framework"
            fi
        fi
    done
else
    echo "Regional Stack deletion skipped with input na!.."
fi

if [[ $Lambda_status -eq 0 ]] && [[ $bucket_status -eq 0 ]]; then
    echo "Successfully deleted deployment stack!"
else
    echo "Something went wrong! Please contact Cloudneeti support!"
fi