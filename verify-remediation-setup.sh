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
    Command to execute : bash verify-remediation-setup.sh [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions where remediation is enabled>]
.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    **Mandatory(-p)AWS Region: Region where you want to deploy all major components of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-s)Region list: Comma seperated list(with no spaces) of the regions where the remediation is to be verified(eg: us-east-1,us-east-2)
        **Pass "all" if you want to verify remediation in all other available regions
        **Pass "na" if you do not want to verify remediation in any other region
.OUTPUTS
    None
'
usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions where remediation is enabled>]" 1>&2; exit 1; }
env="dev"
version="1.0"
secondaryregions=('all')
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
for i in "${valid_values[@]}"; do
    for j in "${valid_regions[@]}"; do
        if [[ $i == $j ]]; then
            secondary_regions+=("$i")
        fi
    done
    if [[ $i != "na" ]] && [[ $primaryregion == $i ]]; then
        primary_deployment=$primaryregion
    fi
done


#validate aws account-id and region
if [[ "$env" == "" ]] || [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ $primary_deployment == "" ]]; then
    usage
fi

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-rem-$env-$acc_sha --region $primary_deployment 2>/dev/null)"
stack_status=$?

echo "Validating environment prefix..."

if [[ $stack_status -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
    exit 1
fi

echo "Verifying role deployment...."
orches_role_det="$(aws iam get-role --role-name CN-Remediation-Invocation-Role)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role)"
Rem_role=$?

echo "Verifying Cloudtrail deployment...."
CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $primary_deployment)"
CT_status=$?

CT_log="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $primary_deployment | jq -r '.IsLogging')"

echo "Verifying Lambda deployment...."
Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator --region $primary_deployment)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$orches_role" -ne 0 ]] && [[ "$Rem_role" -ne 0 ]] && [[ "$CT_status" -ne 0 ]] && [[ "$Lambda_status" -ne 0 ]] && [[ "$s3_status" -ne 0 ]]; then
   echo "Remediation framework is not deployed"
elif [[ "$orches_role" -ne 0 ]] || [[ "$Rem_role" -ne 0 ]];
then
   echo "Required roles not found. Please delete and redploy the framework"
elif [[ "$Lambda_status" -ne 0 ]];
then
   echo "Remediation functions not found. Please delete and redploy the framework"
elif [[ "$CT_status" -ne 0 ]] || [[ "$CT_log" -ne true ]];
then
   echo "Remediation framework cloudtrail trail is not deployed correctly. Please delete and redploy the framework"
elif [[ "$s3_status" -ne 0 ]];
then
   echo "Remediation framework s3-bucket is not deployed correctly or deleted. Please delete and redploy the framework"
elif [[ "$orches_role" -eq 0 ]] && [[ "$Rem_role" -eq 0 ]] && [[ "$CT_status" -eq 0 ]] && [[ "$Lambda_status" -eq 0 ]] && [[ "$s3_status" -eq 0 ]];
then
   echo "Remediation framework is correctly deployed"
else
   echo "Something went wrong!"
fi

echo "Verifying Regional Configuration...."

Invoker_rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Invoker)"
Invoker_Rem_role=$?

if [[ "$secondary_regions" -ne "na" ]]; then
    if [[ "$s3_status" -eq 0 ]]; then
        #Deploy Regional Stack
        for i in "${secondary_regions[@]}";
        do
            if [[ "$i" != "$primary_deployment" ]]; then
                regional_stack_detail="$(aws cloudformation describe-stacks --stack-name cn-rem-$env-$i-$acc_sha --region $i 2>/dev/null)"
                regional_stack_status=$?

                Invoker_Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $i 2>/dev/null)"
                Invoker_Lambda_status=$?

                if [[ "$regional_stack_status" -ne 0 ]] && [[ "$Invoker_Lambda_status" -ne 0 ]];
                then
                    echo "Remediation framework is not configured in region $i. Please redploy the framework with region $i as input"
                elif [[ "$Invoker_Lambda_status" -ne 0 ]];
                then
                    echo "Remediation framework is not configured in region $i. Please redploy the framework with region $i as input"
                elif [[ "$regional_stack_status" -ne 0 ]];
                then
                    echo "Remediation framework is not configured in region $i. Please redploy the framework with region $i as input"
                elif [[ "$regional_stack_status" -eq 0 ]] && [[ "$Invoker_Lambda_status" -eq 0 ]] && [[ "$Invoker_Rem_role" -eq 0 ]];
                then
                    echo "Remediation framework is correctly deployed in region $i"
                else
                    echo "Something went wrong!"
                fi
            else
                echo "Region $primary_deployment is configured as primary region."
            fi
        done
    else
        echo "Bucket not found Something went wrong! Please contact Cloudneeti support for more details"
        exit 1
    fi
else
    echo "Regional Deployments verification skipped with input na!.."
fi