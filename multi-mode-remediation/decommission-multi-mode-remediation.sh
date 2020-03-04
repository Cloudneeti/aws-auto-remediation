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
    Command to execute : bash decommission-multi-mode-remediation.sh [-a <12-digit-account-id>] [-e <environment-prefix>] [-m <list of regions where remediation is enabled>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account for which you want to disbale remediation  
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-m)Region list: Comma seperated list(with no spaces) of the regions where the remediation is enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you have enabled remediation in all other available regions
        **Pass "na" if you do not have enabled remediation in any other region

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>] [-m <list of regions where remediation is enabled>]" 1>&2; exit 1; }

env="dev"
version="1.0"
while getopts "a:e:m:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        e)
            env=${OPTARG}
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

IFS=, read -a input_regions <<<"${regionlist}"
printf -v ips ',"%s"' "${input_regions[@]}"
ips="${ips:1}"

input_regions=($(echo "${input_regions[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

#Verify input for regional deployment
if [[ $regionlist == "na" ]]; then
    input_regions=${Valid_values[0]}
else
    input_regions="${regionlist[@]}"
fi



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

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Validating environment prefix..."
sleep 5

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-multirem-$env-$acc_sha --region $aws_region 2>/dev/null)"
stack_status=$?

#if [[ $stack_status -ne 0 ]]; then
#    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
#    exit 1
#fi

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-multirem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

echo "Checking if the deployment bucket was correctly deleted... "

if [[ $s3_status -eq 0 ]]; then
    echo "Deployment bucket is still not deleted. Please delete cn-multirem-$env-$acc_sha and try to re-run the script again."
    exit 1
fi

echo "Deleting deployment stack..."
#remove termination protection from stack
aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name cn-multirem-$env-$acc_sha --region $aws_region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null

#delete main stack
aws cloudformation delete-stack --stack-name cn-multirem-$env-$acc_sha --region $aws_region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $aws_region 2>/dev/null)"
Lambda_status=$?

echo "Deleting Regional Deployments...."

if [[ "$validated_regions" -ne "na" ]]; then
    #Deploy Regional Stack
    for i in "${validated_regions[@]}"; do
        if [[ "$i" != "$aws_region" ]]; then
            stack_detail="$(aws cloudformation describe-stacks --stack-name cn-multirem-$env-$i-$acc_sha --region $i 2>/dev/null)"
            stack_status=$?
            #remove termination protection
            aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name cn-multirem-$env-$i-$acc_sha --region $i --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
            #delete stack from other regions
            aws cloudformation delete-stack --stack-name cn-multirem-$env-$i-$acc_sha --region $i
        fi
    done
else
    echo "Regional Deployments deletion skipped with input na!.."
fi


if [[ $Lambda_status -eq 0 ]] && [[ $bucket_status -eq 0 ]]; then
    echo "Successfully deleted deployment stack!"
else
    echo "Something went wrong! Please contact Cloudneeti support!"
fi