#!/bin/bash

: '
#SYNOPSIS
    Update remediation framework role.
.DESCRIPTION
    This script will update the role of the Remediation framework with the details of the newly added account for remediation.

.NOTES

    Copyright (c) Cloudneeti. All rights reserved.
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

    Version: 2.3

    # PREREQUISITE
      - Install aws cli
        Link : https://docs.aws.amazon.com/cli/latest/userguide/install-linux-al2017.html
      - Install json parser jq
        Installation command: sudo apt-get install jq
      - Configure your aws account using the below command:
        aws configure
        Enter the required inputs: (configure using details of the AWS account with remediation framework)
            AWS Access Key ID: Access key of any admin user of the account in consideration.
            AWS Secret Access Key: Secret Access Key of any admin user of the account in consideration
            Default region name: Programmatic region name where you want to deploy the framework (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash update-remediation-role.sh [-r <12-digit-account-id>] [-a <12-digit-account-id>]

.INPUTS
    (-r)Remediation Account Id: 12-digit AWS account Id of the account where the remediation framework is deployed
    (-a)New AWS Account Id: 12-digit AWS Account Id of the account which is newly added to use the remediation framework

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-r <12-digit-account-id>] [-a <12-digit-account-id>] " 1>&2; exit 1; }

while getopts "r:a:" o; do
    case "${o}" in
        r)
            remawsaccountid=${OPTARG}
            ;;
        a)
            awsaccountid=${OPTARG}
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

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]]; then
    usage
fi

echo "Verifying if pre-requisites are set-up.."
sleep 5
if [[ "$(which serverless)" != "" ]] && [[ "$(which aws)" != "" ]] && [[ "$(which jq)" != "" ]];then
    echo -e "${GREEN}All pre-requisite packages are installed!!${NC}"
else
    echo -e "${RED}Package(s)/tool(s) mentioned as pre-requisites have not been correctly installed. Please verify the installation and try re-running the script.${NC}"
    exit 1
fi

echo
echo "Getting existing role details...."

role_detail="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role --output json 2>/dev/null)"
role_status=$?
if [[ $role_status -ne 0 ]]; then
    echo -e "${RED}Remediation role does not exist!! Please verify if the remediation framework is correctly deployed or not.${NC}"
    exit 1
fi

Assume_role_policy="$(aws iam get-role --role-name ZCSPM-Remediation-Invocation-Role --output json | jq '.Role.AssumeRolePolicyDocument' 2>/dev/null )"
role_status=$?

if [[ $role_status -ne 0 ]]; then
    echo -e "${RED}Unable to get role details. Please contact ZCSPM support!${NC}"
    exit 1
fi

if [[ $Assume_role_policy =~ "$awsaccountid" ]]
then
   echo -e "${RED}Role is already updated for the entered account!! You can proceed to next steps provided in the remediation document!${NC}"
   exit 1
fi

echo
echo "Updating existing role..."

Updated_Assume_role_policy="$(echo $Assume_role_policy | jq --arg awsaccountid "$awsaccountid" '.Statement[.Statement| length] |= .+{"Effect": "Allow","Principal": {"AWS": "arn:aws:iam::'$awsaccountid':root"},"Action": "sts:AssumeRole"}' 2>/dev/null )"
append_status=$?

echo "Updated IAM Role policy json: $Updated_Assume_role_policy"

if [[ $append_status -eq 0 ]]; then
    aws iam update-assume-role-policy --role-name ZCSPM-Remediation-Invocation-Role --policy-document "$Updated_Assume_role_policy" 2>/dev/null
    update_status=$?
else
    echo -e "${RED}Something went wrong! Please contact ZCSPM support!${NC}"
    exit 1
fi

if [[ $update_status -eq 0 ]]; then
    echo -e "${GREEN}Successfully updated the remediation framework role!!${NC}"
else
    echo -e "${RED}Something went wrong! Please contact ZCSPM support!${NC}"
fi
