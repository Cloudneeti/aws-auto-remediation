'''
Enable Load balancer deletion protection
'''

from botocore.exceptions import ClientError

def run_remediation(elbv2, LoadBalancerArn):
    print("Executing load balancer remediation..")            

    deletion_protection=False
    try:
        response=elbv2.describe_load_balancer_attributes(LoadBalancerArn=LoadBalancerArn)['Attributes']
        for i in range(len(response)):
            if AppLBAttr[i]['Key'] == 'deletion_protection.enabled' and AppLBAttr[i]['Value'] == 'false':
                deletion_protection = False
    except:
        deletion_protection=False

    if not deletion_protection:   
        try:
            result = elbv2.modify_load_balancer_attributes(
                LoadBalancerArn=LoadBalancerArn,
                Attributes=[
                    {
                    'Key':'deletion_protection.enabled',
                    'Value':'true'
                    }
                ]
            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Connection draining is enabled for: %s \n" % LoadBalancerArn
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    else:
        responseCode=200
        output="Connection draining is already enabled for: %s \n" % LoadBalancerArn

    print(str(responseCode)+'-'+output)
    return responseCode,output