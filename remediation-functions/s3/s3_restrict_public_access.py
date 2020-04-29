'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Ensure that S3 buckets are not publicly accessible
'''

from botocore.exceptions import ClientError

#def run_remediation(boto_session, rule, resource):
def run_remediation(s3_client, bucket_name):
    print("Executing remediation")
    #Update Public access settings for bucket
    try:
        result = s3_client.put_public_access_block(
                                            Bucket = bucket_name,
                                            PublicAccessBlockConfiguration = {
                                                'BlockPublicAcls': True,
                                                'IgnorePublicAcls': True,
                                                'BlockPublicPolicy': True,
                                                'RestrictPublicBuckets': True
                                            }
                                        )

        responseCode = result['ResponseMetadata']['HTTPStatusCode']
        if responseCode >= 400:
            output = "Unexpected error: %s \n" % str(result)
        else:
            output = "Block publicly access flags set to true for S3 Bucket : %s \n" % bucket_name

    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        print(output)

    print(str(responseCode)+'-'+output)   
    return responseCode,output