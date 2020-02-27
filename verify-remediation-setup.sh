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
    Command to execute : bash verify-remediation-setup.sh [-a <12-digit-account-id>] [-e <environment-prefix>]
.INPUTS
    (-a)Account Id: 12-digit AWS account Id of the account for which you want to verify if remediation framework is deployed or not.
    (-e)Environment prefix: Enter any suitable prefix for your deployment
.OUTPUTS
    None
'
usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>] [-m <region1> -m <region2> ...]" 1>&2; exit 1; }
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
		m) regionlist+=("$OPTARG");;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

Regions=( "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )

#Validating user input for custom regions
selectedregions=" ${regionlist[*]}"                    # add framing blanks
for value in ${Regions[@]}; do
  if [[ $selectedregions =~ " $value " ]] ; then    # use $value as regexp to validate
    customregions+=($value)
  fi
done

if [[ "$env" == "" ]] || [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

stack_detail="$(aws cloudformation describe-stacks --stack-name cn-rem-$env-$acc_sha --region $aws_region 2>/dev/null)"
stack_status=$?

echo "Validating environment prefix..."
sleep 5

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
CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region)"
CT_status=$?

CT_log="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region | jq -r '.IsLogging')"

echo "Verifying Lambda deployment...."
Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator --region $aws_region)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

if [[ "$orches_role" -ne 0 ]] && [[ "$Rem_role" -ne 0 ]] && [[ "$CT_status" -ne 0 ]] && [[ "$Lambda_status" -ne 0 ]] && [[ "$s3_status" -ne 0 ]]; then
   echo "Remediation framework is not deployed"
elif [[ "$orches_role" -ne 0 ]] || [[ "$Rem_role" -ne 0 ]];
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
elif [[ "$orches_role" -eq 0 ]] && [[ "$Rem_role" -eq 0 ]] && [[ "$CT_status" -eq 0 ]] && [[ "$Lambda_status" -eq 0 ]] && [[ "$s3_status" -eq 0 ]];
then
   echo "Remediation framework is correctly deployed"
else
   echo "Something went wrong!"
fi

echo "Verifying Regional Configuration...."

RemediationRegion=( $aws_region )

DeploymentRegion=()
if [[ "$regionlist" -eq "All" ]]; then
	#Remove AWS_Region from all regions
	for Region in "${Regions[@]}"; do
		skip=
		for DefaultRegion in "${RemediationRegion[@]}"; do
			[[ $Region == $DefaultRegion ]] && { skip=1; break; }
		done
		[[ -n $skip ]] || DeploymentRegion+=("$Region")
	done

	declare -a DeploymentRegion
else
	#Remove AWS_Region from custom region list
	for Region in "${customregions[@]}"; do
		skip=
		for DefaultRegion in "${RemediationRegion[@]}"; do
			[[ $Region == $DefaultRegion ]] && { skip=1; break; }
		done
		[[ -n $skip ]] || DeploymentRegion+=("$Region")
	done

	declare -a DeploymentRegion
fi

Invoker_rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role)"
Invoker_Rem_role=$?

for i in "${DeploymentRegion[@]}";
do
    regional_stack_detail="$(aws cloudformation describe-stacks --stack-name cn-rem-$env-$i-$acc_sha --region $i 2>/dev/null)"
    regional_stack_status=$?

    Invoker_Lambda_det="$(aws lambda get-function --function-name cn-aws-auto-remediate-invoker --region $i 2>/dev/null)"
    Invoker_Lambda_status=$?

    if [[ "$Invoker_Rem_role" -ne 0 ]]; then
        echo "Remediation framework Role is not configured in region $i Please delete and redploy the framework"
    elif [[ "$regional_stack_status" -ne 0 ]] && [[ "$Invoker_Lambda_status" -ne 0 ]] && [[ "$Invoker_Rem_role" -ne 0 ]];
    then
        echo "Remediation framework is not configured. Please delete and redploy the framework"
    elif [[ "$Invoker_Lambda_status" -ne 0 ]];
    then
        echo "Remediation framework Invoker lambda function is not deployed in region $i. Please delete and redploy the framework"
    elif [[ "$regional_stack_status" -ne 0 ]];
    then
        echo "Remediation framework stack is not deployed in region $i. Please delete and redploy the framework"
    elif [[ "$regional_stack_status" -eq 0 ]] && [[ "$Invoker_Lambda_status" -eq 0 ]] && [[ "$Invoker_Rem_role" -eq 0 ]];
    then
        echo "Remediation framework is correctly deployed in region $i"
    else
        echo "Something went wrong!"
    fi
done