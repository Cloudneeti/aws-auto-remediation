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
      - Command to execute : bash verify-multi-mode-remediation-setup.sh [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-e <environment-prefix>] [-m <list of regions where remediation is enabled>]

.INPUTS
    **Mandatory(-a)New AWS Account Id: 12-digit AWS Account Id of the account which is newly added to use the remediation framework
    **Mandatory(-r)Remediation Account Id: 12-digit AWS account Id of the account where the remediation framework is deployed
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-m)Region list: Comma seperated list(with no spaces) of the regions where the remediation enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you have enabled remediation in all other available regions
        **Pass "na" if you do not have enabled remediation in any other region

.OUTPUTS
    None
'
usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-e <environment-prefix>] [-m <list of regions where remediation is enabled>]" 1>&2; exit 1; }

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

if [[ "$env" == "" ]] || [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]]; then
    usage
fi

aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-multirem-$env-$acc_sha --region $aws_region 2>/dev/null)"
stack_status=$?

echo "Validating environment prefix..."
sleep 5

if [[ $stack_status -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
    exit 1
fi

echo "Verifying role deployment...."
invoker_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Invoker 2>/dev/null)"
invoker_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

echo "Verifying Cloudtrail deployment...."
CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region 2>/dev/null)"
CT_status=$?

CT_log="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region | jq -r '.IsLogging' 2>/dev/null)"

echo "Verifying Lambda deployment...."
Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $aws_region 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-multirem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$invoker_role" -ne 0 ]] && [[ "$Rem_role" -ne 0 ]] && [[ "$CT_status" -ne 0 ]] && [[ "$Lambda_status" -ne 0 ]] && [[ "$s3_status" -ne 0 ]]; then
   echo "Remediation framework is not deployed"
elif [[ "$invoker_role" -ne 0 ]] || [[ "$Rem_role" -ne 0 ]];
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
elif [[ "$invoker_role" -eq 0 ]] && [[ "$Rem_role" -eq 0 ]] && [[ "$CT_status" -eq 0 ]] && [[ "$Lambda_status" -eq 0 ]] && [[ "$s3_status" -eq 0 ]];
then
   echo "Remediation framework is correctly deployed"
else
   echo "Something went wrong!"
fi

echo "Verifying Regional Configuration...."

if [[ "$validated_regions" -ne "na" ]]; then
    #Verify Regional Stack
    if [[ "$i" != "$aws_region" ]]; then
        for i in "${validated_regions[@]}";
        do
            regional_stack_detail="$(aws cloudformation describe-stacks --stack-name cn-multirem-$env-$i-$acc_sha --region $i 2>/dev/null)"
            regional_stack_status=$?

            Invoker_Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $i 2>/dev/null)"
            Invoker_Lambda_status=$?

            if [[ "$regional_stack_status" -ne 0 ]] && [[ "$Invoker_Lambda_status" -ne 0 ]];
            then
                echo "Remediation framework is not configured. Please redploy the framework with region $i as input"
            elif [[ "$Invoker_Lambda_status" -ne 0 ]];
            then
                echo "Remediation framework Invoker lambda function is not deployed. Please redploy the framework with region $i as input"
            elif [[ "$regional_stack_status" -ne 0 ]];
            then
                echo "Remediation framework stack is not deployed. Please redploy the framework with region $i as input"
            elif [[ "$regional_stack_status" -eq 0 ]] && [[ "$Invoker_Lambda_status" -eq 0 ]] && [[ "$invoker_role" -eq 0 ]];
            then
                echo "Remediation framework is correctly deployed in region $i"
            else
                echo "Something went wrong!"
            fi
        done
    fi
else
    echo "Regional Deployments deletion skipped with input na!.."
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