#!/bin/bash

: '

#SYNOPSIS
    Deployment of Organization based multi-mode Remediation Framework.
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
    Command to execute : bash deploy-org-remediation-framework.sh [-a <12-digit-aws-account-id>] [-z <12-digit-zcspm-aws-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v version] [-s <list of regions where auto-remediation is to enabled>] [-m organization member accounts where framework components are to be deployed] [-o organization IAM role name] [-g <select auto remediation deployment for global services>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where the primary remediation framework is to be deployed
    **Optional(-z)ZCSPM Account Id : Enter 12-digit account Id of ZCSPM AWS Account, only if you wish to integrate the remediation framework with ZCSPM
    **Mandatory(-p)AWS Region: Region where you want to deploy all major components of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by ZCSPM)
    (-g)Global Services: Enable Auto remediation for global services (Using "US East (N. Virginia)us-east-1" Region)
    (-s)Region list: Comma seperated list(with no spaces) of the regions where the auto-remediation is to be enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you want to enable auto-remediation in all other available regions
        **Pass "na" if you do not want to enable auto-remediation in any other region
    (-m) Member AWS Account Id(s): Comma seperated list of 12-digit organization member AWS Account Id(s), where the framework components are to be deployed
    (-o) Organization IAM Role Name: Name of the IAM role used by AWS organizations to manage the member accounts
    (-g) Global resource support flag: Pass yes if auto-remediation for global services (like IAM) needs to be enabled. [Deployed in N. Virginia us-east-1 region by default]
.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit AWS organization master account-id>] [-z <12-digit-zcspm-aws-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v version] [-s <list of regions where auto-remediation is to enabled>] [-m organization member accounts where framework components are to be deployed] [-o organization IAM role name] [-g <select auto remediation deployment for global services>]" 1>&2; exit 1; }
reset_env_variables() { export AWS_ACCESS_KEY_ID=""; export AWS_SECRET_ACCESS_KEY=""; export AWS_SESSION_TOKEN=""; }
env="dev"
version="2.2"
secondaryregions=('na')
#organizationrole='OrganizationAccountAccessRole'
while getopts "a:z:p:e:v:s:m:o:g:" o; do
    case "${o}" in
        a)
            remawsaccountid=${OPTARG}
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
        o) 
            organizationrole=${OPTARG}
            ;;
        g) 
            globalservices=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

valid_values=( "na" "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

#validate aws account-id and region
if [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]] || [[ $primaryregion == "" ]] || [[ $memberaccounts == "" ]] || [[ $organizationrole == "" ]]; then
    echo -e "${YELLOW}Entered AWS Account Id(s) or the primary deployment region are invalid!!${NC}"
    usage
fi
        
roleName=$organizationrole

echo "Verifying if pre-requisites are set-up.."
sleep 5
if [[ "$(which serverless)" != "" ]] && [[ "$(which aws)" != "" ]];then
    echo -e "${GREEN}All pre-requisite packages are installed!!${NC}"
else
    echo -e "${RED}Package(s)/tool(s) mentioned as pre-requisites have not been correctly installed. Please verify the installation and try re-running the script.${NC}"
    exit 1
fi

echo
echo "Validating input parameters..."

# Validate global service integration
if [[ -z "$globalservices" ]]; then
    read -p "The AWS Global Services Auto Remediation integration is not selected [i.e. parameter (-g)]. This signifies that the auto remediation will not be enabled for AWS Global Services. Do you still want to continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    globalservices="No"
fi
globalservices=${globalservices,,}

echo
echo "Validating if AWS CLI is configured for the Organization master account.."

configured_account="$(aws sts get-caller-identity | jq '.Account')"

org_detail=""

org_detail="$(aws organizations list-accounts --output json 2>/dev/null)"

if [[ $org_detail == "" ]]; then
    echo "AWS CLI is not configured for Organization master account. Please verify the credentials and try again"
    exit 1
fi
echo -e "${YELLOW}AWS CLI is configured for organization master account: $configured_account ${NC}"

echo
echo "Validating framework version"

if [[ "$inputversion" != "$version" ]]; then
    echo -e "${RED}Incorrect framework version provided. Current framework version is: $version ${NC}"
    exit 1
fi

echo "Framework version that will be deployed is: $version"

echo
echo "Verifying entered AWS Account Id(s) and region(s)..."

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

if [[ "$zcspmawsaccountid" == "" ]] || [[ "$zcspmawsaccountid" == "na" ]]; then
    read -p "The ZCSPM Account Id parameter (-z) was not passed as an input. This signifies that the remediation framework cannot be integrated with ZCSPM portal. Do you still want to continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    zcspmawsaccountid=$remawsaccountid
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
    organization_accounts+=("$memberaccountid")
done

if [[ $memberaccounts == "all" ]]; then
    input_memberaccounts=("${organization_accounts[@]}")
else
    input_memberaccounts="${memberaccounts[@]}"
fi

IFS=, read -a input_memberaccounts <<<"${input_memberaccounts[@]}"
printf -v ips ',"%s"' "${input_memberaccounts[@]}"
ips="${ips:1}"
input_memberaccounts=($(echo "${input_memberaccounts[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))

valid_memberaccounts=()
for account in "${input_memberaccounts[@]}"; do
    if [[ ${#account} != 12 ]] || ! [[ "$account" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Incorrect member account id(s) provided. Expected values are: ${organization_accounts[@]} ${NC}"
        exit 1
    fi

    if [[ "${organization_accounts[@]}" =~ "${account}" ]]; then
        valid_memberaccounts+=("$account")
    else
        echo -e "${RED}Incorrect member account id(s) provided. Expected values are: ${organization_accounts[@]} ${NC}"
        exit 1
    fi
done

if ! [[ "${organization_accounts[@]}" =~ "${remawsaccountid}" ]]; then
    echo -e "${RED}Remediation account id $remawsaccountid provided is not a part of the current AWS Organization. Expected values are: ${organization_accounts[@]} ${NC}"
    exit 1
fi

echo "Account and region validations complete. Entered AWS Account Id(s) and region(s) are in correct format."

#Verify deployment of remediation framework
cd ../remediation-functions/

deployment_status=()
echo
echo "Deploying master remediation framework on AWS Account: $remawsaccountid"

if ! [[ $configured_account =~ "$remawsaccountid" ]]; then
    roleArn='arn:aws:iam::'$remawsaccountid':role/'$roleName

    sts_assumerole="$(aws sts assume-role --role-arn $roleArn --role-session-name zcspm-session --output json 2>/dev/null)"
    assumerole_status=$?

    if [[ "$assumerole_status" -ne "0" ]]; then
        echo "Error while trying to Assume Role. Unable to deploy master remediation framework setup on : $remawsaccountid."
        echo -e "${RED}Please verify the Organization IAM Role Name provided and try again.${NC}"
        exit 1
    fi
    
    credentials="$(echo $sts_assumerole | jq .Credentials )"
    AccessKey="$(echo $credentials | jq -r .AccessKeyId)"
    SecretAccessKey="$(echo $credentials | jq -r .SecretAccessKey)"
    SessionToken="$(echo $credentials | jq -r .SessionToken)"
    
    export AWS_ACCESS_KEY_ID=$AccessKey
    export AWS_SECRET_ACCESS_KEY=$SecretAccessKey
    export AWS_SESSION_TOKEN=$SessionToken
fi

acc_sha="$(echo -n "${remawsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo
echo "Checking if the remediation framework already exists in the configured account....."

orches_role_det="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role 2>/dev/null)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name ZCSPM-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

invoker_role_det="$(aws iam get-role --role-name ZCSPM-AutoRem-InvokerFunction-Role 2>/dev/null)"
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
            serverless deploy --env $env --accounthash $env-$acc_sha --aws-account-id $remawsaccountid --zcspm-aws-account-id $zcspmawsaccountid --region $primary_deployment --remediationversion $version
            Lambda_det="$(aws lambda get-function --function-name zcspm-aws-remediate-orchestrator --region $primary_deployment 2>/dev/null)"
            Lambda_status=$?

            if [[ $lambda_status -eq 0 ]]; then
                echo -e "${GREEN}Successfully deployed remediation framework with latest updates!!${NC}"
                deployment_status+=("      $remawsaccountid      |       successful       ")
            else
                echo -e "${RED}Something went wrong! Please contact ZCSPM support for more details${NC}"
            fi
        else
            echo -e "${RED}Remediation components already exist in $primary_location region. Please run deploy-remediation-framework.sh with primary region as $primary_location !${NC}"
            reset_env_variables
            exit 1
        fi
    else
        echo -e "${RED}Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !${NC}"
        reset_env_variables
        exit 1
    fi
else
    #Deploy framework from scratch
    echo "Existing remediation setup not found. Deploying new setup for remediation framework...."
    aws cloudformation deploy --template-file deployment-bucket.yml --stack-name zcspm-rem-$env-$acc_sha --parameter-overrides Stack=zcspm-rem-$env-$acc_sha awsaccountid=$remawsaccountid region=$primary_deployment --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    s3_status=$?
    if [[ "$s3_status" -eq 0 ]]; then
        serverless deploy --env $env --accounthash $env-$acc_sha --aws-account-id $remawsaccountid --zcspm-aws-account-id $zcspmawsaccountid --region $primary_deployment --remediationversion $version
        lambda_status=$?

        #Enabling termination protection for stack(s)
        aws cloudformation update-termination-protection --enable-termination-protection --stack-name zcspm-rem-$env-$acc_sha --region $primary_deployment 2>/dev/null
        aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-rem-functions-$env-$acc_sha" --region $primary_deployment 2>/dev/null
    else
        echo -e "${RED}Something went wrong during remediaion framework deployment for account $remawsaccountid! Please contact ZCSPM support for more details${NC}"
        reset_env_variables
        exit 1
    fi
    echo -e "${GREEN}Successfully deployed master remediation setup in region $primary_deployment of AWS account: $remawsaccountid ${NC}"
    deployment_status+=("      $remawsaccountid      |       successful       ")
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
                echo -e "${YELLOW}Region $region is not configured because of existing resources, please delete them and redeploy framework to configure this region${NC}"
            else
                aws cloudformation deploy --template-file deploy-invoker-function.yml --stack-name zcspm-rem-$env-$region-$acc_sha  --region $region --parameter-overrides awsaccountid=$remawsaccountid remediationregion=$primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-rem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                Regional_stack_status=$?

                if [[ "$Regional_stack_status" -eq 0 ]]; then
                    echo -e "${GREEN}Successfully configured region $region in remediation framework ${NC}"
                    aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-rem-$env-$region-$acc_sha" --region $region 2>/dev/null
                else
                    echo " ${RED}Failed to configure region $region in remediation framework ${NC}"
                fi
            fi
        fi
    done
else
    echo -e "${YELLOW}Regional Deployments skipped with input na!..${NC}"
fi

echo "Deploying Global Services Auto remediation Template...."

#Global services deployment
if [[ "$globalservices" == "yes" ]] || [[ "$globalservices" == "y" ]]; then
    aws cloudformation deploy --template-file deploy-global-services-invoker-function.yml --stack-name zcspm-rem-global-resources-$env-$acc_sha --parameter-overrides awsaccountid=$remawsaccountid remediationregion=$primary_deployment --region "us-east-1" --capabilities CAPABILITY_NAMED_IAM 2>/dev/null

    sleep 5
    # Validate deployment
    Global_services_stack="$(aws cloudformation describe-stacks --stack-name zcspm-rem-global-resources-$env-$acc_sha --region "us-east-1" 2>/dev/null)"
    Global_services_stack_status=$?
    
    if [[ "$Global_services_stack_status" -eq 0 ]]; then
        echo -e "${GREEN}Successfully enabled autoremediation for global services${NC}"
        aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-rem-global-resources-$env-$acc_sha" --region "us-east-1" 2>/dev/null
    else
        echo -e "${RED}Failed to configure auto remediation for global services ${NC}"
    fi
else
    echo -e "${YELLOW}Global Services Autoremediation Support is Not Enabled!..${NC}"
fi

if [[ $lambda_status -eq 0 ]]; then
    echo -e "${GREEN}Successfully deployed remediation framework!! ${NC}"
else
    echo -e "${RED}Something went wrong during remediation framework deployment for account $remawsaccountid! Please contact ZCSPM support for more details${NC}"
    deployment_status+=("      $remawsaccountid      |         failed         ")
fi

if [[ $org_detail ]]; then

    echo
    echo "Updating invocation role with the specified member Account(s) in the AWS Organization...."
    role_detail="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role --output json 2>/dev/null)"
    role_status=$?
    if [[ $role_status -ne 0 ]]; then
        echo -e "${RED}Remediation role does not exist!! Please verify if the remediation framework is correctly deployed or not.${NC}"
        reset_env_variables
        exit 1
    fi

    Assume_role_policy="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role --output json | jq '.Role.AssumeRolePolicyDocument' 2>/dev/null )"
    role_status=$?

    if [[ $role_status -ne 0 ]]; then
        echo -e "${RED}Unable to get role details. Please contact ZCSPM support!${NC}"
        reset_env_variables
        exit 1
    fi

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
            echo -e "${GREEN}Successfully updated the remediation framework role with the specified member Account(s) in the AWS Organization!!${NC}"
        else
            echo -e "${RED}Something went wrong! Please contact ZCSPM support!${NC}"
        fi
    fi

    if ! [[ $configured_account =~ "$remawsaccountid" ]]; then
        reset_env_variables
    fi

    echo    
    echo "Deploying framework in member accounts of the organization..."
    
    cd ./multi-mode-remediation/

    for awsaccountid in "${valid_memberaccounts[@]}"; do
        if [[ "$awsaccountid" -ne "$remawsaccountid" ]]; then
            echo
            echo "Deploying framework in member account: $awsaccountid"
            roleArn='arn:aws:iam::'$awsaccountid':role/'$roleName

            sts_assumerole="$(aws sts assume-role --role-arn $roleArn --role-session-name zcspm-session --output json 2>/dev/null)"
            assumerole_status=$?

            if [[ "$assumerole_status" -ne 0 ]]; then
                echo -e "${YELLOW}Error while trying to Assume Role. Skipping deployment for AWS Account: $awsaccountid ${NC}"
                deployment_status+=("      $awsaccountid      |         failed         ")
                continue
            fi

            credentials="$(echo $sts_assumerole | jq .Credentials )"
            AccessKey="$(echo $credentials | jq -r .AccessKeyId)"
            SecretAccessKey="$(echo $credentials | jq -r .SecretAccessKey)"
            SessionToken="$(echo $credentials | jq -r .SessionToken)"
            
            export AWS_ACCESS_KEY_ID=$AccessKey
            export AWS_SECRET_ACCESS_KEY=$SecretAccessKey
            export AWS_SESSION_TOKEN=$SessionToken

            acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"

            echo "Checking if the remediation is already enabled for the account $awsaccountid"

            invoker_role_det="$(aws iam get-role --role-name ZCSPM-AutoRem-InvokerFunction-Role 2>/dev/null)"
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
                        aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name zcspm-multirem-$env-$acc_sha --parameter-overrides Stack=zcspm-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$remawsaccountid region=$primary_deployment remediationversion=$version --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM
                        Lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
                        Lambda_status=$?
                        
                        if [[ $Lambda_status -eq 0 ]]; then
                            echo -e "${GREEN}Successfully deployed remediation framework with latest updates for account: $awsaccountid!!${NC}"
                            deployment_status+=("      $awsaccountid      |       successful       ")
                        else
                            deployment_status+=("      $awsaccountid      |         failed         ")
                            reset_env_variables
                        fi
                    else
                        echo -e "${RED}Remediation components already exist in $primary_location region for account: $awsaccountid. Please run configure-multi-mode-remediation.sh with primary region as $primary_location !${NC}"
                        deployment_status+=("      $awsaccountid      |         failed         ")
                        reset_env_variables
                    fi
                else
                    echo -e "${RED}Remediation components already exist with a different environment prefix for account: $awsaccountid. Please run verify-remediation-setup.sh for more details !${NC}"
                    deployment_status+=("      $awsaccountid      |         failed         ")
                    reset_env_variables
                fi
            else
                #Deploy framework from scratch
                echo "Existing remediation setup not found. Deploying required setup for remediation framework...."
                aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name zcspm-multirem-$env-$acc_sha --parameter-overrides Stack=zcspm-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$remawsaccountid region=$primary_deployment remediationversion=$version --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
                lambda_status=$?

                if [[ $lambda_status -eq 0 ]]; then
                    echo -e "${GREEN}Successfully deployed remediation framework with latest updates for account $awsaccountid!!${NC}"
                    deployment_status+=("      $awsaccountid      |       successful       ")
                    #Enabling termination protection for stack(s)
                    aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-$env-$acc_sha" --region $primary_deployment
                else
                    deployment_status+=("      $awsaccountid      |         failed         ")
                    reset_env_variables
                fi
            fi

            #Regional deployments for framework
            echo
            echo "Configuring regional deployments for member account: $awsaccountid"
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
                            aws cloudformation deploy --template-file deploy-invoker-multi-mode.yml --stack-name zcspm-multirem-$env-$region-$acc_sha --parameter-overrides awsaccountid=$awsaccountid remaccountid=$remawsaccountid --region $region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                            Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                            Regional_stack_status=$?
                            
                            if [[ "$Regional_stack_status" -eq 0 ]]; then
                                echo -e "${GREEN}Successfully configured region $region for account $awsaccountid in remediation framework ${NC}"
                                #Enabling termination protection for stack(s)
                                aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-$env-$region-$acc_sha" --region $region 2>/dev/null
                            else
                                echo -e "${RED}Failed to configure region $region for account $awsaccountid in remediation framework ${NC}"
                            fi
                        fi
                    fi
                done
            else
                echo -e "${YELLOW}Regional Deployments skipped with input na!..${NC}"
            fi

            echo
            echo "Deploying Global Services Autoremediation Template for member account: $awsaccountid"

            #Global services deployment
            if [[ "$globalservices" == "yes" ]] || [[ "$globalservices" == "y" ]]; then
                aws cloudformation deploy --template-file deploy-global-services-invoker-multi-mode.yml --stack-name zcspm-multirem-global-resources-$env-$acc_sha --parameter-overrides awsaccountid=$awsaccountid remaccountid=$remawsaccountid --region "us-east-1" --capabilities CAPABILITY_NAMED_IAM 2>/dev/null

                sleep 5
                # Validate deployment
                Global_services_stack="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-global-resources-$env-$acc_sha --region "us-east-1" 2>/dev/null)"
                Global_services_stack_status=$?
                
                if [[ "$Global_services_stack_status" -eq 0 ]]; then
                    echo -e "${GREEN}Successfully enabled auto remediation for global services${NC}"
                    aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-global-resources-$env-$acc_sha" --region "us-east-1" 2>/dev/null
                else
                    echo -e "${YELLOW}Failed to configure auto remediation for global services${NC}"
                fi
            else
                echo "Global Services auto remediation Support is not selected for member account: $awsaccountid!.."
            fi

            if [[ $lambda_status -eq 0 ]]; then
                echo -e "${GREEN}Successfully deployed remediation framework for account $awsaccountid!!${NC}"
            else
                echo -e "${RED}Something went wrong during remediation framework deployment for account $awsaccountid! Please contact ZCSPM support for more details${NC}"
                deployment_status+=("      $awsaccountid      |         failed         ")
            fi
            reset_env_variables
        fi
    done

    echo
    echo "***********Framework Deployment Summary**************"
    echo "-----------------------------------------------------"
    echo "|      AWS Account Id     |    Deployment Status    |"
    echo "-----------------------------------------------------"
    for status in "${deployment_status[@]}"; do
        echo "| $status |"
        echo "-----------------------------------------------------"
    done

else
    echo -e "${RED}Unable to fetch member accounts. Ensure that the configured account is master of the organization. ${NC}"
fi
