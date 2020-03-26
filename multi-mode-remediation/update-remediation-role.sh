#!/bin/bash

: '
#SYNOPSIS
    Update remediation framework role.
.DESCRIPTION
    This script will update the role of the Remediation framework with the details of the newly added account for remediation.
.NOTES
    Version: 2.0

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

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]] || [[ "$remawsaccountid" == "" ]] || ! [[ "$remawsaccountid" =~ ^[0-9]+$ ]] || [[ ${#remawsaccountid} != 12 ]]; then
    usage
fi

echo "Getting existing role details...."

role_detail="$(aws iam get-role --role-name CN-Remediation-Invocation-Role --output json 2>/dev/null)"
role_status=$?
if [[ $role_status -ne 0 ]]; then
    echo "Remediation role does not exist!! Please verify if the remediation framework is correctly deployed or not."
    exit 1
fi

Assume_role_policy="$(aws iam get-role --role-name CN-Remediation-Invocation-Role --output json | jq '.Role.AssumeRolePolicyDocument' 2>/dev/null )"
role_status=$?

if [[ $role_status -ne 0 ]]; then
    echo "Unable to get role details. Please contact Cloudneeti support!"
    exit 1
fi

if [[ $Assume_role_policy =~ "$awsaccountid" ]]
then
   echo "Role is already updated for the entered account!! You can proceed to next steps provided in the remediation document!"
   exit 1
fi

echo "Updating existing role..."

Updated_Assume_role_policy="$(echo $Assume_role_policy | jq --arg awsaccountid "$awsaccountid" '.Statement[.Statement| length] |= .+{"Effect": "Allow","Principal": {"AWS": "arn:aws:iam::'$awsaccountid':root"},"Action": "sts:AssumeRole"}' 2>/dev/null )"
append_status=$?

echo "Updated IAM Role policy json: $Updated_Assume_role_policy"

if [[ $append_status -eq 0 ]]; then
    aws iam update-assume-role-policy --role-name CN-Remediation-Invocation-Role --policy-document "$Updated_Assume_role_policy" 2>/dev/null
    update_status=$?
else
    echo "Something went wrong! Please contact Cloudneeti support!"
    exit 1
fi

if [[ $update_status -eq 0 ]]; then
    echo "Successfully updated the remediation framework role!!"
else
    echo "Something went wrong! Please contact Cloudneeti support!"
fi
