'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Global resources are included into Amazon Config service
'''

from botocore.exceptions import ClientError

def run_remediation(config, ConfigRoleARN, Name):
    print("Executing config remediation")

    try:
        config_det = config.describe_configuration_recorders()["ConfigurationRecorders"]
        ConfigRoleARN = config_det[0]['roleARN']
        Name = config_det[0]['name']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)  

    if not config_det[0]['recordingGroup']['includeGlobalResourceTypes']: 
        try:
            result = config.put_configuration_recorder(
                                ConfigurationRecorder={
                                    'name': Name,
                                    'roleARN': ConfigRoleARN,
                                    'recordingGroup': {
                                        'allSupported': config_det[0]['recordingGroup']['allSupported'],
                                        'includeGlobalResourceTypes': True,
                                        'resourceTypes': config_det[0]['recordingGroup']['resourceTypes']
                                    }
                                }
                            )

            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Enabled inclusion of global resources for config : %s \n" % Name
                    
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    else:
        responseCode = 200
        output = "config is already compliant"

    print(str(responseCode)+'-'+output)
    return responseCode,output