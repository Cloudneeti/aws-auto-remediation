'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Make redshift private
'''

from botocore.exceptions import ClientError
import time

def run_remediation(redshift, cluster_name):
    print("Executing remediation")    

    public_access = True
    
    try:
        public_access = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters'][0]['PubliclyAccessible']
    except:
        public_access = False    

    if public_access:
        flag=1
        while flag:
            redshift_detail = redshift.describe_clusters(ClusterIdentifier=cluster_name)['Clusters']
            if redshift_detail[0]['ClusterStatus'] not in ['modifying', 'rebooting', 'creating']:        
            
                try:
                    result = redshift.modify_cluster(
                                ClusterIdentifier=cluster_name,
                                MaintenanceTrackName='trailing',
                                PubliclyAccessible=False
                            )

                    responseCode = result['ResponseMetadata']['HTTPStatusCode']
                    if responseCode >= 400:
                        output = "Unexpected error: %s \n" % str(result)
                    else:
                        output = "Redshift cluster is now private: %s \n" % cluster_name
                            
                except ClientError as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                    print(output)
                except Exception as e:
                    responseCode = 400
                    output = "Unexpected error: " + str(e)
                    print(output)
                flag = 0
            else:
                time.sleep(10)
    
    else:
        responseCode = 200
        output = "Redshift already remediated"

    print(str(responseCode)+'-'+output)
    return responseCode,output

