'''
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