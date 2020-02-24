#!/bin/bash

: '
#SYNOPSIS
    Deployment of Remediation Framework.
.DESCRIPTION
    This script will deploy all the services required for the remediation framework.
.NOTES
    Version: 1.0

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
            Default region name: Programmatic region name where you want to deploy the framework (eg: us-east-1)
            Default output format: json  
      - Run this script in any bash shell (linux command prompt)

.EXAMPLE
    Command to execute : bash deploy-remediation-framework.sh [-a <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>]

.INPUTS
    **Mandatory(-a)Account Id: 12-digit AWS account Id of the account where you want the remediation framework to be deployed
    (-e)Environment prefix: Enter any suitable prefix for your deployment
    (-v)Version: Enter the remediation framework version (Would be provided by Cloudneeti)

.OUTPUTS
    None
'

usage() { echo "Usage: $0 [-a <12-digit-account-id>] [-e <environment-prefix>] [-v <1.0>]" 1>&2; exit 1; }
env="dev"
version="1.0"
while getopts "a:e:v:" o; do
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
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [[ "$awsaccountid" == "" ]] || ! [[ "$awsaccountid" =~ ^[0-9]+$ ]] || [[ ${#awsaccountid} != 12 ]]; then
    usage
fi

cd remediation-functions/
aws_region="$(aws configure get region 2>/dev/null)"

acc_sha="$(echo -n "${awsaccountid}" | md5sum | cut -d" " -f1)"
env="$(echo "$env" | tr "[:upper:]" "[:lower:]")"

echo "Checking if the remediation framework already exists in the configured account....."

orches_role_det="$(aws iam get-role --role-name CN-Remediation-Invocation-Role 2>/dev/null)"
orches_role=$?
InvokerRole=$(echo $orches_role_det | jq '.Role.Arn')

rem_role_det="$(aws iam get-role --role-name CN-Auto-Remediation-Role 2>/dev/null)"
Rem_role=$?

CT_det="$(aws cloudtrail get-trail-status --name cn-remediation-trail --region $aws_region 2>/dev/null)"
CT_status=$?

Lambda_det="$(aws lambda get-function --function-name cn-aws-remediate-orchestrator --region $aws_region 2>/dev/null)"
Lambda_status=$?

s3_detail="$(aws s3api get-bucket-versioning --bucket cn-rem-$env-$acc_sha 2>/dev/null)"
s3_status=$?

cd ..
cd regional-deployment/
echo "Configure Regional Deployments...."

Regions=( "us-east-1" "us-east-2" "us-west-1" "us-west-2" "ap-south-1" "ap-northeast-2" "ap-southeast-1" "ap-southeast-2" "ap-northeast-1" "ca-central-1" "eu-central-1" "eu-west-1" "eu-west-2" "eu-west-3" "eu-north-1" "sa-east-1" "ap-east-1" )
RemediationRegion=( $aws_region )

DeploymentRegion=()

#Remove AWS_Region for remediation deployment
for Region in "${Regions[@]}"; do
    skip=
    for DefaultRegion in "${RemediationRegion[@]}"; do
        [[ $Region == $DefaultRegion ]] && { skip=1; break; }
    done
    [[ -n $skip ]] || DeploymentRegion+=("$Region")
done

declare -a DeploymentRegion

zip -r cninvoker.zip invoker.py

for i in "${DeploymentRegion[@]}";
do
    Invoker = "$(aws lambda create-function --function-name cn-rem-$i-invoker --runtime python3.7 --zip-file fileb://cninvoker.zip --handler invoker.lambda_handler --role $InvokerRole --region $i)"
    echo "$i"

    aws events put-rule --name "cn-aws-rds-event-rule" --event-pattern "{\"source\":[\"aws.rds\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"rds.amazonaws.com\"],\"eventName\":[\"CreateDBCluster\",\"ModifyDBCluster\",\"CreateDBInstance\",\"ModifyDBInstance\",\"RemoveTagsFromResource\"]}}"

    aws events put-targets --rule "cn-aws-rds-event-rule" --targets "Id"="1","Arn"=$Invoker
    aws events put-rule --name "cn-aws-cloudtrail-event-rule" --event-pattern "{\"source\":[\"aws.cloudtrail\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"cloudtrail.amazonaws.com\"],\"eventName\":[\"CreateTrail\",\"UpdateTrail\"]}}"

    aws events put-targets --rule "cn-aws-cloudtrail-event-rule" --targets "Id"="1","Arn"=$Invoker

    aws events put-rule --name "cn-aws-kinesis-event-rule" --event-pattern "{\"source\":[\"aws.kinesis\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"kinesis.amazonaws.com\"],\"eventName\":[\"CreateStream\",\"DisableEnhancedMonitoring\"]}}"

    aws events put-targets --rule "cn-aws-kinesis-event-rule" --targets "Id"="1","Arn"=$Invoker

    aws events put-rule --name "cn-aws-kms-event-rule" --event-pattern "{\"source\":[\"aws.kms\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"kms.amazonaws.com\"],\"eventName\":[\"CreateKey\",\"DisableKeyRotation\"]}}"

    aws events put-targets --rule "cn-aws-kms-event-rule" --targets "Id"="1","Arn"=$Invoker

    aws events put-rule --name "cn-aws-elb-event-rule" --event-pattern "{\"source\":[\"aws.elasticloadbalancing\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"elasticloadbalancing.amazonaws.com\"],\"eventName\":[\"CreateLoadBalancer\",\"ModifyLoadBalancerAttributes\"]}}"

    aws events put-targets --rule "cn-aws-elb-event-rule" --targets "Id"="1","Arn"=$Invoker

    aws events put-rule --name "cn-aws-s3bucket-event-rule" --event-pattern "{\"source\":[\"aws.s3\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"s3.amazonaws.com\"],\"eventName\":[\"CreateBucket\",\"PutBucketVersioning\",\"DeleteBucketEncryption\",\"PutBucketAcl\"]}}"

    aws events put-targets --rule "cn-aws-s3bucket-event-rule" --targets "Id"="1","Arn"=$Invoker

    aws events put-rule --name "cn-aws-redshift-event-rule" --event-pattern "{\"source\":[\"aws.redshift\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventSource\":[\"redshift.amazonaws.com\"],\"eventName\":[\"CreateCluster\",\"ModifyCluster\"]}}"

    aws events put-targets --rule "cn-aws-redshift-event-rule" --targets "Id"="1","Arn"=$Invoker    
done

rm cninvoker.zip


if [[ $lambda_status -eq 0 ]]; then
    echo "Successfully deployed remediation framework!!"
else
    echo "Something went wrong! Please contact Cloudneeti support for more details"
fi