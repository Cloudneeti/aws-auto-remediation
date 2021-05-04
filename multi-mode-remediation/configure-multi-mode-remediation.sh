#!/bin/bash

: '
#SYNOPSIS
    Enable Remediation.
.DESCRIPTION
    This script will deploy all the services required for the remediation framework and enable remediation for this account.

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
    Command to execute : bash configure-multi-mode-remediation.sh [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v version] [-s <list of regions where auto-remediation is to enabled>] [-g <select auto remediation deployment for global services>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account for which you want to enable the remediation
    **Mandatory(-r)Remediation Account Id: 12-digit AWS account Id of the account where the remediation framework is deployed
    **Mandatory(-p)AWS Region: Region where you want to deploy all major components of remediation framework
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by ZCSPM)
    (-s)Region list: Comma seperated list(with no spaces) of the regions where the auto-remediation is to be enabled(eg: us-east-1,us-east-2)
        **Pass "all" if you want to enable auto-remediation in all other available regions
        **Pass "na" if you do not want to enable auto-remediation in any other region
    (-g) Global resource support flag: Pass yes if auto-remediation for global services (like IAM) needs to be enabled. [Deployed in N. Virginia us-east-1 region by default]
.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-r <12-digit-account-id>] [-p <primary-deployment-region>] [-e <environment-prefix>] [-v version] [-s <list of regions where auto-remediation is to enabled>] [-g <select auto remediation deployment for global services>]" 1>&2; exit 1; }

env="dev"
version="2.2"
secondaryregions=('na')
while getopts "a:r:p:e:v:s:g:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        r)
            remawsaccountid=${OPTARG}
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
        g) 
            globalservices=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))
valid_values=( "na" "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]] || [[ $primaryregion == "" ]]; then
    usage
fi

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

if [[ -z "$globalservices" ]]; then
    read -p "The AWS Global Services Auto Remediation integration is not selected [i.e. parameter (-g)]. This signifies that the auto remediation will not be enabled for AWS Global Services. Do you still want to continue? (Y/N): " confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    globalservices="No"
fi
globalservices=${globalservices,,}

echo
echo "Validating framework version"

if [[ "$inputversion" != "$version" ]]; then
    echo -e "${RED}Incorrect framework version provided. Current framework version is: $version ${NC}"
    exit 1
fi

echo "Framework version that will be deployed is: $version"

echo
echo "Verifying entered AWS Account Id(s) and region(s)..."

configured_account="$(aws sts get-caller-identity | jq '.Account')"

if [[ "$configured_account" != *"$awsaccountid"* ]];then
    echo -e "${RED}AWS CLI is configured for $configured_account whereas input AWS Account Id entered is $awsaccountid. Please ensure that CLI configuration and the input Account Id is for the same AWS Account.${NC}"
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

echo "Input validation complete!"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo
echo "Checking if the remediation is already enabled for the account....."

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
                echo -e "${GREEN}Successfully deployed remediation framework with latest updates!!${NC}"
            else
                echo -e "${RED}Something went wrong! Please contact ZCSPM support for more details${NC}"
                exit 1
            fi
        else
            echo -e "${RED}Remediation components already exist in $primary_location region. Please run configure-multi-mode-remediation.sh with primary region as $primary_location !${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !${NC}"
        exit 1
    fi
else
    #Deploy framework from scratch
    echo
    echo "Existing remediation setup not found. Deploying new setup for remediation framework...."
    aws cloudformation deploy --template-file deploy-multi-mode-resources.yml --stack-name zcspm-multirem-$env-$acc_sha --parameter-overrides Stack=zcspm-multirem-$env-$acc_sha awsaccountid=$awsaccountid remaccountid=$remawsaccountid region=$primary_deployment remediationversion=$version --region $primary_deployment --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
    lambda_det="$(aws lambda get-function --function-name zcspm-aws-auto-remediate-invoker --region $primary_deployment 2>/dev/null)"
    lambda_status=$?

    if [[ $lambda_status -eq 0 ]]; then
        echo -e "${GREEN}Successfully deployed remediation framework with latest updates!!${NC}"
        #Enabling termination protection for stack(s)
        aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-$env-$acc_sha" --region $primary_deployment
    else
        echo -e "${RED}Something went wrong! Please contact ZCSPM support for more details${NC}"
        exit 1
    fi
    echo -e "${GREEN}Successfully deployed remediation setup in region $primary_deployment of AWS account: $awsaccountid ${NC}"
fi

#Regional deployments for framework
echo
echo "Configuring regional deployments...."
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
                echo -e "${YELLOW}Region $region is not configured because of existing resources, please delete them and redeploy framework to configure this region${NC}"
            else
                aws cloudformation deploy --template-file deploy-invoker-multi-mode.yml --stack-name zcspm-multirem-$env-$region-$acc_sha --parameter-overrides awsaccountid=$awsaccountid remaccountid=$remawsaccountid --region $region --capabilities CAPABILITY_NAMED_IAM 2>/dev/null
                Regional_stack="$(aws cloudformation describe-stacks --stack-name zcspm-multirem-$env-$region-$acc_sha --region $region 2>/dev/null)"
                Regional_stack_status=$?
                
                if [[ "$Regional_stack_status" -eq 0 ]]; then
                    echo "Successfully deployed remediation framework components in region $region"
                    #Enabling termination protection for stack(s)
                    aws cloudformation update-termination-protection --enable-termination-protection --stack-name "zcspm-multirem-$env-$region-$acc_sha" --region $region 2>/dev/null
                else
                    echo -e "${RED}Failed to configure region $region in remediation framework${NC}"
                fi
            fi
        fi
    done
else
    echo -e "${YELLOW}Regional Deployments skipped with input na!..${NC}"
fi

echo "Deploying Global Services Autoremediation Template...."

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
        echo -e "${RED}Failed to configure auto remediation for global services${NC}"
    fi
else
    echo -e "${YELLOW}Global Services auto remediation Support is not selected!..${NC}"
fi

if [[ $lambda_status -eq 0 ]]; then
    echo -e "${GREEN}Successfully deployed remediation framework!!${NC}"
else
    echo -e "${RED}Something went wrong! Please contact ZCSPM support for more details${NC}"
fi