#!/bin/bash

: '

#SYNOPSIS
    Deployment of Remediation Framework.
.DESCRIPTION
    This script will deploy all the services required for the remediation framework.

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 2.2
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
    Command to execute : bash deploy-remediation-framework.sh [-a <12-digit-account-id>] [-z <12-digit-zcspm-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v version] [-s <list of regions where auto-remediation is to enabled>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    **Optional(-z)ZCSPM Account Id : Enter 12-digit account Id of ZCSPM AWS Account, only if you wish to integrate the remediation framework with ZCSPM
    **Mandatory(-p)AWS Region: Region where you want to deploy all major components of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by ZCSPM)
    (-s)Region list: Comma seperated list(with no spaces) of the regions where the auto-remediation is to be enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you want to enable auto-remediation in all other available regions
        **Pass "na" if you do not want to enable auto-remediation in any other region
.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-z <12-digit-zcspm-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v version] [-s <list of regions where auto-remediation is to enabled>]" 1>&2; exit 1; }
env="dev"
version="2.2"
secondaryregions=('na')
while getopts "a:z:p:e:v:s:m:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        z)
            zcspmawsaccountid=${OPTARG}
            ;;
        p)
            primaryregion=${OPTARG}
            ;;
        e)
            env=${OPTARG}
            ;;
        v)
            inputversion=${OPTARG}
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

echo "Verifying if pre-requisites are set-up.."
sleep 5
if [[ "$(which serverless)" != "" ]] && [[ "$(which aws)" != "" ]];then
    echo "All pre-requisite packages are installed!!"
else
    echo "Package(s)/tool(s) mentioned as pre-requisites have not been correctly installed. Please verify the installation and try re-running the script."
    exit 1
fi

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
echo "Validating framework version"

if [[ "$inputversion" != "$version" ]]; then
    echo "Incorrect framework version provided. Current framework version is: $version"
    exit 1
fi

echo "Framework version that will be deployed is: $version"

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
    echo "Entered AWS Account Id or the primary deployment region are invalid!!"
    usage
fi

if [[ "$zcspmawsaccountid" == "" ]] || [[ "$zcspmawsaccountid" == "na" ]]; then
    read -p "The ZCSPM Account Id parameter (-z) was not passed as an input. This signifies that the remediation framework cannot be integrated with ZCSPM portal. Do you still want to continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    zcspmawsaccountid=$awsaccountid
else
    if [[ ${#zcspmawsaccountid} != 12 ]] || ! [[ "$zcspmawsaccountid" =~ ^[0-9]+$ ]]; then
    echo "Entered ZCSPM AWS Account Id is invalid!!"
    usage
    fi
fi

organization_accounts=()

for i in $(jq '.Accounts | keys | .[]' <<< "$org_detail"); do
    account_detail=$(jq -r ".Accounts[$i]" <<< "$org_detail")
    memberaccountid=$(jq -r '.Id' <<< "$account_detail")
    if ! [[ "$memberaccountid" =~ "$awsaccountid" ]]; then
        organization_accounts+=("$memberaccountid")
    fi
done

valid_memberaccounts=()
for account in "${memberaccounts[@]}"; do
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

if [[ $memberaccounts == "na" ]]; then
    multimode_deployment="no"
elif [[ $memberaccounts == "all" ]]; then
    multimode_deployment="yes"
    valid_memberaccounts=("${organization_accounts[@]}")
else
    multimode_deployment="yes"
fi

echo "Account and region validations complete. Enter Account Id(s) and region(s) are in correct format."

masterawsaccountid=$awsaccountid

#Verify deployment of remediation framework
cd remediation-functions/

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo
echo "Checking if the remediation framework already exists in the configured account....."

orches_role_det="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role 2>/dev/null)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

invoker_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Invoker 2>/dev/null)"
invoker_role=$?

CT_det="$(aws cloudtrail get-trail-status --name zcspm-remediation-trail --region $primary_deployment 2>/dev/null)"
CT_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket zcspm-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

rem_location="$(aws s3api get-bucket-location --bucket zcspm-rem-$env-$acc_sha --query 'LocationConstraint' 2>/dev/null)"
primary_location="$(eval echo $rem_location)"

#Update existing remediation framework
if [[ "$orches_role" -eq 0 ]] || [[ "$Rem_role" -eq 0 ]] || [[ "$CT_status" -eq 0 ]] || [[ "$s3_status" -eq 0 ]] || [[ "$invoker_role" -eq 0 ]]; then
	echo "Remediation components already exist. Attempting to redeploy framework with latest updates !"
    if [[ "$s3_status" -eq 0 ]]; then
        if [[ $primary_location == $primary_deployment ]]; then
            echo "Redeploying framework....."
            serverless deploy --env $env --accounthash $env-$acc_sha --aws-account-id $awsaccountid --zcspm-aws-account-id $zcspmawsaccountid --region $primary_deployment --remediationversion $version
            Lambda_det="$(aws lambda get-function --function-name zcspm-aws-remediate-orchestrator --region $primary_deployment 2>/dev/null)"
            Lambda_status=$?

            if [[ $lambda_status -eq 0 ]]; then
                echo "Successfully deployed remediation framework with latest updates!!"
            else
                echo "Something went wrong! Please contact ZCSPM support for more details"
            fi
        else
            echo "Remediation components already exist in $primary_location region. Please run deploy-remediation-framework.sh with primary region as $primary_location !"
            exit 1
        fi
    else
        echo "Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !"
        exit 1
    fi
else
    #Deploy framework from scratch
    echo "Existing remediation setup not found. Deploying new setup for remediation framework...."
    aws cloudformation deploy --template-file deployment-bucket.yml --stack-name zcspm-rem-$env-$acc_sha --parameter-overrides Stack=zcspm-rem-$env-$acc_sha awsaccountid=$awsaccountid region=$primary_deployment --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    s3_status=$?
    if [[ "$s3_status" -eq 0 ]]; then
        serverless deploy --env $env --accounthash $env-$acc_sha --aws-account-id $awsaccountid --zcspm-aws-account-id $zcspmawsaccountid --region $primary_deployment --remediationversion $version
        lambda_status=$?

        #Enabling termination protection for stack(s)
        aws cloudformation update-termination-protection --enable-termination-protection --stack-name zcspm-rem-$env-$acc_sha --region $primary_deployment 2>/dev/null
        aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-rem-functions-$env-$acc_sha" --region $primary_deployment 2>/dev/null
    else
        echo "Something went wrong! Please contact ZCSPM support for more details"
        exit 1
    fi
    echo "Successfully deployed master remediation setup in region $primary_deployment of AWS account: $awsaccountid"
fi

if [[ $org_detail ]]; then
    org_account_count="$(aws organizations list-accounts --output json | jq '.Accounts' | jq length 2>/dev/null)"

    if [[ $org_account_count -ne 0 ]]; then

        echo
        echo "Updating invocation role with the specified member Account(s) in the AWS Organization...."

        role_detail="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role --output json 2>/dev/null)"
        role_status=$?
        if [[ $role_status -ne 0 ]]; then
            echo "Remediation role does not exist!! Please verify if the remediation framework is correctly deployed or not."
            exit 1
        fi

        Assume_role_policy="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role --output json | jq '.Role.AssumeRolePolicyDocument' 2>/dev/null )"
        role_status=$?

        if [[ $role_status -ne 0 ]]; then
            echo "Unable to get role details. Please contact ZCSPM support!"
            exit 1
        fi

        echo "Updating existing role..."
        Updated_Assume_role_policy=""
        for awsaccountid in "${valid_memberaccounts[@]}"; do

            if [[ $Assume_role_policy =~ "$awsaccountid" ]]; then
                continue
            else
                Updated_Assume_role_policy="$(echo $Assume_role_policy | jq --arg awsaccountid "$awsaccountid" '.Statement[0].Principal.AWS |= .+["arn:aws:iam::'$awsaccountid':root"]' 2>/dev/null )"
                Assume_role_policy=$Updated_Assume_role_policy
            fi
        done

        if [[ $Updated_Assume_role_policy != "" ]]; then
            aws iam update-assume-role-policy --role-name ZCSPM-Remediation-Invocation-Role --policy-document "$Updated_Assume_role_policy" 2>/dev/null
            update_status=$?

            if [[ $update_status -eq 0 ]]; then
                echo "Successfully updated the remediation framework role with the specified member Account(s) in the AWS Organization!!"
            else
                echo "Something went wrong! Please contact ZCSPM support!"
            fi
        fi
    fi
fi

#Regional deployments for framework
echo
echo "Configuring Regional Deployments...."
cd ..

if [[ "$secondary_regions" != "na" ]] && [[ "$s3_status" -eq 0 ]]; then
    #Deploy Regional Stack
    for region in "${secondary_regions[@]}"; do
        if [[ "$region" != "$primary_deployment" ]]; then
            Lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $region 2>/dev/null)"
            Lambda_status=$?

            Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null)"
            Regional_stack_status=$?
            
            if [[ "$Regional_stack_status" -ne 0 ]] && [[ "$Lambda_status" -eq 0 ]]; then
                echo "Region $region is not configured because of existing resources, please delete them and redeploy framework to configure this region"
            else
                aws cloudformation deploy --template-file deploy-invoker-function.yml --stack-name zcspm-rem-$env-$region-$acc_sha  --region $region --parameter-overrides awsaccountid=$awsaccountid --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                Regional_stack_status=$?

                if [[ "$Regional_stack_status" -eq 0 ]]; then
                    echo "Successfully configured region $region in remediation framework"
                    aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-rem-$env-$region-$acc_sha" --region $region 2>/dev/null
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
    echo "Something went wrong! Please contact ZCSPM support for more details"
fi

echo "$masterawsaccountid"

if [[ $org_detail ]] && [[ "$multimode_deployment" -eq "yes" ]]; then

    cd ./multi-mode-remediation/

    echo    
    echo "Deploying framework in member accounts of the organization..."
    
    for awsaccountid in "${valid_memberaccounts[@]}"; do
        roleName='OrganizationAccountAccessRole'

        if [[ "$awsaccountid" -ne "$masterawsaccountid" ]]; then
            echo
            echo "Deploying framework in member account: $awsaccountid"
            roleArn='arn:aws:iam::'$awsaccountid':role/'$roleName

            credentials="$(aws sts assume-role --role-arn $roleArn --role-session-name zcspm-session --output json | jq .Credentials 2>/dev/null)"
            AccessKey="$(echo $credentials | jq -r .AccessKeyId)"
            SecretAccessKey="$(echo $credentials | jq -r .SecretAccessKey)"
            SessionToken="$(echo $credentials | jq -r .SessionToken)"
            
            export AWS_ACCESS_KEY_ID=$AccessKey
            export AWS_SECRET_ACCESS_KEY=$SecretAccessKey
            export AWS_SESSION_TOKEN=$SessionToken

            acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"

            echo "Checking if the remediation is already enabled for the account $awsaccountid....."

            invoker_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Invoker 2>/dev/null)"
            invoker_role=$?

            rem_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Role 2>/dev/null)"
            Rem_role=$?

            CT_det="$(aws cloudtrail get-trail-status --name zcspm-remediation-trail --region $primary_deployment 2>/dev/null)"
            CT_status=$?

            s3_detail="$(aws s3api get-bucket-versioning --bucket zcspm-multirem-$env-$acc_sha 2>/dev/null)"
            s3_status=$?

            rem_location="$(aws s3api get-bucket-location --bucket zcspm-multirem-$env-$acc_sha --query "LocationConstraint" 2>/dev/null)"
            primary_location="$(eval echo $rem_location)"

            if [[ "$invoker_role" -eq 0 ]] || [[ "$Rem_role" -eq 0 ]] || [[ "$CT_status" -eq 0 ]] || [[ "$s3_status" -eq 0 ]]; then
                echo "Remediation components already exist. Attempting to redeploy framework with latest updates !"
                #Redeploy framework
                if [[ "$s3_status" -eq 0 ]]; then
                    if [[ $primary_location == $primary_deployment ]]; then
                        echo "Redeploying framework....."
                        aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name zcspm-multirem-$env-$acc_sha --parameter-overrides Stack=zcspm-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$masterawsaccountid region=$primary_deployment remediationversion=$version --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM
                        Lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
                        Lambda_status=$?
                        
                        if [[ $Lambda_status -eq 0 ]]; then
                            echo "Successfully deployed remediation framework with latest updates!!"
                        else
                            echo "Something went wrong! Please contact ZCSPM support for more details"
                            exit 1
                        fi
                    else
                        echo "Remediation components already exist in $primary_location region. Please run configure-multi-mode-remediation.sh with primary region as $primary_location !"
                        exit 1
                    fi
                else
                    echo "Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !"
                    exit 1
                fi
            else
                #Deploy framework from scratch
                echo "Existing remediation setup not found. Deploying required setup for remediation framework...."
                aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name zcspm-multirem-$env-$acc_sha --parameter-overrides Stack=zcspm-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$masterawsaccountid region=$primary_deployment remediationversion=$version --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
                lambda_status=$?

                if [[ $lambda_status -eq 0 ]]; then
                    echo "Successfully deployed remediation framework with latest updates!!"
                    #Enabling termination protection for stack(s)
                    aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-$env-$acc_sha" --region $primary_deployment
                else
                    echo "Something went wrong! Please contact ZCSPM support for more details"
                    exit 1
                fi
            fi

            #Regional deployments for framework
            echo
            echo "Configuring regional deployments for member account: $awsaccountid...."
            s3_status=$?

            if [[ "$secondary_regions" -ne "na" ]] && [[ "$s3_status" -eq 0 ]]; then
                #Deploy Regional Stack
                for region in "${secondary_regions[@]}"; do
                    if [[ "$region" != "$primary_deployment" ]]; then
                        Lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $region 2>/dev/null)"
                        Lambda_status=$?

                        Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                        Regional_stack_status=$?
                        
                        if [[ "$Regional_stack_status" -ne 0 ]] && [[ "$Lambda_status" -eq 0 ]]; then
                            echo "Region $region is not configured because of existing resources, please delete them and redeploy framework to configure this region"
                        else
                            aws cloudformation deploy --template-file deploy-invoker-multi-mode.yml --stack-name zcspm-multirem-$env-$region-$acc_sha --parameter-overrides awsaccountid=$awsaccountid remaccountid=$masterawsaccountid --region $region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                            Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                            Regional_stack_status=$?
                            
                            if [[ "$Regional_stack_status" -eq 0 ]]; then
                                echo "Successfully configured region $region in remediation framework"
                                #Enabling termination protection for stack(s)
                                aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-$env-$region-$acc_sha" --region $region 2>/dev/null
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
                echo "Something went wrong! Please contact ZCSPM support for more details"
            fi
            #reset environment variables
            export AWS_ACCESS_KEY_ID=""
            export AWS_SECRET_ACCESS_KEY=""
            export AWS_SESSION_TOKEN=""
        fi
    done
else
    echo "Unable to fetch member accounts. Ensure that the configured account is master of the organization."
fi

