'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Enable Load balancer deletion protection
'''

from botocore.exceptions import ClientError

def run_remediation(elbv2, LoadBalancerArn):
    print("Executing load balancer remediation..")            

    deletion_protection=False
    if 'arn:aws:' not in LoadBalancerArn:
        try:
            loadbalancer_detail=elbv2.describe_load_balancers(Names=[LoadBalancerArn])
            LoadBalancerArn=loadbalancer_detail['LoadBalancers'][0]['LoadBalancerArn']
        except:
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
                output = "Deletion Protection enabled for: %s \n" % LoadBalancerArn
                    
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
        output="Deletion Protection is already enabled for: %s \n" % LoadBalancerArn

    print(str(responseCode)+'-'+output)
    return responseCode,output