#!/bin/bash

: '

#SYNOPSIS
    Decommissioning Remediation Framework.
.DESCRIPTION
    This script will remove all the services deployed for the remediation framework.

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 2.2

    # PREREQUISITE
      - Install aws cli
        Link : https://docs.aws.amazon.com/cli/latest/userguide/install-linux-al2017.html
      - Before running this script, you need to delete the associated remediation s3-bucket
        Bucket name is as follows : zcspm-rem-{environment-prefix}-{account-id-hash}
      - Configure your aws account using the below command:
        aws configure
        Enter the required inputs:
            AWS Access Key ID: Access key of any admin user of the account in consideration.
            AWS Secret Access Key: Secret Access Key of any admin user of the account in consideration
            Default region name: AWS region name (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash decommission-remediation-framework.sh [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions from where the auto-remediation is to be decommissioned>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    **Mandatory(-p)AWS Region: Region where you want to deploy all major resources of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-s)Region list: Comma seperated list(with no spaces) of the regions from where the auto-remediation is to be decommissioned(eg: us-east-1,us-east-2)
        **Pass "all" if you want to decommission auto-remediation from all other available regions
        **Pass "na" if you do not want to decommission auto-remediation from any other region

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-s <list of regions from where the auto-remediation is to be decommissioned>]" 1>&2; exit 1; }
env="dev"
version="2.2"
secondaryregions=('na')
while getopts "a:p:e:s:m:" o; do
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
        s) 
            secondaryregions=${OPTARG}
            ;;
        m) 
            memberaccounts=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))
valid_values=( "na" "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

echo
echo "Validating input parameters..."

echo
echo "Validating if AWS CLI is configured for the master Organization account.."

org_detail=""

org_detail="$(aws organizations list-accounts --output json 2>/dev/null)"

if [[ $org_detail == "" ]]; then
    echo "AWS CLI is not configured for master Organization account. Please verify the credentials and try again"
    exit 1
fi
echo "AWS CLI is configured for master organization account: $awsaccountid"

echo
echo "Verifying entered AWS Account Id(s) and region(s)..."

configure_account="$(aws sts get-caller-identity)"

if [[ "$configure_account" != *"$awsaccountid"* ]];then
    echo "AWS CLI configuration AWS account Id and entered AWS account Id does not match. Please try again with correct AWS Account Id."
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
if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ $primary_deployment == "" ]]; then
    usage
fi

organization_accounts=()

for i in $(jq '.Accounts | keys | .[]' <<< "$org_detail"); do
    account_detail=$(jq -r ".Accounts[$i]" <<< "$org_detail")
    memberaccountid=$(jq -r '.Id' <<< "$account_detail")
    if ! [[ "$memberaccountid" =~ "$awsaccountid" ]]; then
        organization_accounts+=("$memberaccountid")
    fi
done

if [[ $memberaccounts == "na" ]]; then
    multimode_deployment="no"
elif [[ $memberaccounts == "all" ]]; then
    multimode_deployment="yes"
    org_memberaccounts=("${organization_accounts[@]}")
else
    multimode_deployment="yes"
    org_memberaccounts="${memberaccounts[@]}"
fi

IFS=, read -a org_memberaccounts <<<"${org_memberaccounts[@]}"
printf -v ips ',"%s"' "${org_memberaccounts[@]}"
ips="${ips:1}"
org_memberaccounts=($(echo "${org_memberaccounts[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

valid_memberaccounts=()
for account in "${org_memberaccounts[@]}"; do
    if [[ ${#account} != 12 ]] || ! [[ "$account" =~ ^[0-9]+$ ]]; then
        echo "Incorrect member account id(s) provided. Expected values are: ${organization_accounts[@]}"
        exit 1
    fi
    for memberaccount in "${organization_accounts[@]}"; do
        if [[ "$account" == "$memberaccount" ]]; then
            valid_memberaccounts+=("$account")
        fi
    done
done

echo "Account and region validations complete. Entered AWS Account Id(s) and region(s) are in correct format."

masterawsaccountid=$awsaccountid

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name zcspm-rem-functions-$env-$acc_sha --region $primary_deployment 2>/dev/null)"
stack_status=$?

echo
echo "Validating environment prefix..."
sleep 5

if [[ $stack_status -ne 0 ]]; then
    echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."
    exit 1
fi


echo "Remediation framework stack exists with enetered prefix. Initiating cleanup of remediation framework."

s3_detail="$(aws s3api get-bucket-versioning --bucket zcspm-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

echo "Checking if the deployment bucket was correctly deleted..."
sleep 5

if [[ $s3_status -eq 0 ]]; then
    echo "Deployment bucket is still not deleted. Please delete bucket zcspm-rem-$env-$acc_sha and try to re-run the script again."
    exit 1
fi

echo
echo "Deleting deployment stack..."
#remove termination protection from stack
aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name zcspm-rem-functions-$env-$acc_sha --region $primary_deployment 2>/dev/null
aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name zcspm-rem-$env-$acc_sha --region $primary_deployment 2>/dev/null

#Delete remediation framework stack
aws cloudformation delete-stack --stack-name zcspm-rem-functions-$env-$acc_sha --region $primary_deployment 2>/dev/null
lambda_status=$?

aws cloudformation delete-stack --stack-name zcspm-rem-$env-$acc_sha --region $primary_deployment 2>/dev/null
bucket_status=$?

echo "Successfully completed the cleanup of master remediation framework"

echo
echo "Deleting Regional Deployments...."

if [[ "$secondary_regions" -ne "na" ]]; then
    #Delete Regional Stack
    for region in "${secondary_regions[@]}"; do
        if [[ "$region" != "$primary_deployment" ]]; then
            stack_detail="$(aws cloudformation describe-stacks --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null)"
            stack_status=$?
            
            if [[ $stack_status -eq 0 ]]; then
                echo
                echo "Initiating cleanup of remediation framework components in region: $region"
                #remove termination protection
                aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null
                #delete stack from other regions
                aws cloudformation delete-stack --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null
                echo "Successfully completed the cleanup of remediation framework component in region: $region"
            else
                echo "Region $region is not configured in remediation framework"
            fi
        fi
    done
else
    echo "Regional Stack deletion skipped with input na!.."
fi

if [[ $lambda_status -eq 0 ]]  && [[ $bucket_status -eq 0 ]]; then
    echo "Successfully deleted deployment stack!"
else
    echo "Something went wrong! Please contact ZCSPM support!"
fi

if [[ $org_detail ]] && [[ "$multimode_deployment" -eq "yes" ]]; then
    echo    
    echo "Initiating framework cleanup in member accounts of the organization..."
    
    cd ./multi-mode-remediation/

    for awsaccountid in "${valid_memberaccounts[@]}"; do
        roleName='OrganizationAccountAccessRole'

        if [[ "$awsaccountid" -ne "$masterawsaccountid" ]]; then
            echo
            echo "Decommissioning framework from member account: $awsaccountid"
            roleArn='arn:aws:iam::'$awsaccountid':role/'$roleName

            credentials="$(aws sts assume-role --role-arn $roleArn --role-session-name zcspm-session --output json | jq .Credentials 2>/dev/null)"
            AccessKey="$(echo $credentials | jq -r .AccessKeyId)"
            SecretAccessKey="$(echo $credentials | jq -r .SecretAccessKey)"
            SessionToken="$(echo $credentials | jq -r .SessionToken)"
            
            export AWS_ACCESS_KEY_ID=$AccessKey
            export AWS_SECRET_ACCESS_KEY=$SecretAccessKey
            export AWS_SESSION_TOKEN=$SessionToken

            acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
            echo
            echo "Validating environment prefix..."
            sleep 5

            stack_detail="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-$env-$acc_sha --region $primary_deployment 2>/dev/null)"
            stack_status=$?

            if [[ $stack_status -ne 0 ]]; then
                echo "Invaild environment prefix. No relevant stack found. Please enter current environment prefix and try to re-run the script again."#
                exit 1
            fi

            echo "Remediation framework stack exists with enetered prefix. Initiating cleanup of remediation framework."
            s3_detail="$(aws s3api get-bucket-versioning --bucket zcspm-multirem-$env-$acc_sha 2>/dev/null)"
            s3_status=$?

            echo "Checking if the deployment bucket was correctly deleted... "

            if [[ $s3_status -eq 0 ]]; then
                echo "Deployment bucket is still not deleted. Please delete zcspm-multirem-$env-$acc_sha and try to re-run the script again."
                exit 1
            fi

            echo "Deleting deployment stack..."
            #remove termination protection from stack
            aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name zcspm-multirem-$env-$acc_sha --region $primary_deployment 2>/dev/null

            #delete main stack
            aws cloudformation delete-stack --stack-name zcspm-multirem-$env-$acc_sha --region $primary_deployment 2>/dev/null
            Lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
            Lambda_status=$?

            echo "Deleting Regional Deployments...."

            if [[ "$secondary_regions" -ne "na" ]]; then
                #Delete Regional Stack
                for region in "${secondary_regions[@]}"; do
                    if [[ "$region" != "$primary_deployment" ]]; then
                        stack_detail="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                        stack_status=$?

                        if [[ $stack_status -eq 0 ]]; then
                            echo
                            echo "Initiating cleanup of remediation framework components in region: $region"
                            #remove termination protection
                            aws cloudformation update-termination-protection --no-enable-termination-protection --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region 2>/dev/null
                            #delete stack from other regions
                            aws cloudformation delete-stack --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region
                            echo "Successfully completed the cleanup of remediation framework component in region: $region"
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
                echo "Something went wrong! Please contact ZCSPM support!"
            fi

            #reset environment variables
            export AWS_ACCESS_KEY_ID=""
            export AWS_SECRET_ACCESS_KEY=""
            export AWS_SESSION_TOKEN=""

        fi
    done
fi

echo
echo "Remediation framework and its components have been successfully deleted from the mentioned AWS account(s) and region(s)"