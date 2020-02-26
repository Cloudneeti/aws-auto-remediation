#!/bin/bash

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>] [-m <region1>] [-m <region2>] ..." 1>&2; exit 1; }
env="dev"
version="1.0"
while getopts "a:e:v:m:" o; do
    case "${o}" in
        a)
            awsaccountid=${OPTARG}
            ;;
        e)
            env=${OPTARG}
            ;;
        v)
            version=${OPTARG}
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

#validate aws account-id
if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

#Verify deployment of remediation framework
cd remediation-functions/
aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Checking if the remediation framework already exists in the configured account....."

orches_role_det="$(aws iam get-role --role-name CN-Remediation-Invocation-Role 2>/dev/null)"
orches_role=$?

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region 2>/dev/null)"
CT_status=$?

Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator --region $aws_region 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

#Update existing remediation framework
if [[ "$orches_role" -eq 0 ]] || [[ "$Rem_role" -eq 0 ]] || [[ "$CT_status" -eq 0 ]] || [[ "$Lambda_status" -eq 0 ]] || [[ "$s3_status" -eq 0 ]]; then
	echo "Remediation components already exist. Attempting to redploy framework with latest updates !"

    if [[ "$s3_status" -eq 0 ]]; then
        echo "Redploying framework....."
        serverless deploy --env $env-$acc_sha --aws-account-id $awsaccountid --region $aws_region --remediationversion $version
        lambda_status=$?

        if [[ $lambda_status -eq 0 ]]; then
            echo "Successfully deployed remediation framework with latest updates!!"
        else
            echo "Something went wrong! Please contact Cloudneeti support for more details"
        fi
        exit 1
    else
        echo "Remediation components already exist with a different environment prefix. Please run verify-remediation-setup.sh for more details !"
        exit 1
    fi
fi

#Deploy framework from scrach
echo "Deploying remediation framework...."
aws cloudformation deploy --template-file deployment-bucket.yml --stack-name cn-rem-$env-$acc_sha --parameter-overrides Stack=cn-rem-$env-$acc_sha awsaccountid=$awsaccountid region=$aws_region --capabilities CAPABILITY_NAMED_IAM
bucket_status=$?
if [[ "$bucket_status" -eq 0 ]]; then
    serverless deploy --env $env-$acc_sha --aws-account-id $awsaccountid --region $aws_region --remediationversion $version
    lambda_status=$?
else
    echo "Something went wrong! Please contact Cloudneeti support for more details"
    exit 1
fi

#Regional deployments for framework
cd ..
cd regional-deployment/
echo "Configure Regional Deployments...."

RemediationRegion=( $aws_region )

DeploymentRegion=()
if [[ "$regionlist" -eq 0 ]]; then
	#Remove AWS_Region for remediation deployment
	for Region in "${Regions[@]}"; do
		skip=
		for DefaultRegion in "${RemediationRegion[@]}"; do
			[[ $Region == $DefaultRegion ]] && { skip=1; break; }
		done
		[[ -n $skip ]] || DeploymentRegion+=("$Region")
	done

	declare -a DeploymentRegion
else
	#Remove AWS_Region for remediation deployment
	for Region in "${customregions[@]}"; do
		skip=
		for DefaultRegion in "${RemediationRegion[@]}"; do
			[[ $Region == $DefaultRegion ]] && { skip=1; break; }
		done
		[[ -n $skip ]] || DeploymentRegion+=("$Region")
	done

	declare -a DeploymentRegion
fi

for i in "${DeploymentRegion[@]}";
do
    aws cloudformation deploy --template-file deployment-bucket.yml --stack-name cn-rem-$env-$acc_sha --parameter-overrides Stack=cn-rem-$env-$acc_sha awsaccountid=$awsaccountid region=$aws_region --capabilities CAPABILITY_NAMED_IAM
done

if [[ $lambda_status -eq 0 ]]; then
    echo "Successfully deployed remediation framework!!"
else
    echo "Something went wrong! Please contact Cloudneeti support for more details"
fi