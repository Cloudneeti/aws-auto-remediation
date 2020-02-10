'''
Use latest block encryption algorithms for RDS MySQL Instance
Enable FIPS standards for ssl encryption on the server side for RDS MySQL Instance
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")  
    ssl_fips = 1
    enable_aes_latest = 2
    parametervalues = []
    parametergroups = []
    db_engine_flag = 0
    db_version_flag = 0
    ParameterFIPS = ['1','STRICT']
    ParameterBlockEncryption = ['aes-192-ecb','aes-256-ecb','aes-192-cbc','aes-256-cbc']
    
    #Flag resources for identification of dependencies 
    try:
        dbinstance_details = rds.describe_db_instances(DBInstanceIdentifier = RDSInstanceName)['DBInstances']
        if dbinstance_details[0]['Engine'] == 'mysql':
            db_engine_flag = 1
        if dbinstance_details[0]['EngineVersion'] in ['mysql8.0.11','mysql8.0.13','mysql8.0.15','mysql8.0.16']:
            db_version_flag = 1
        RDSParameterGroup = Instance_Det[0]['DBParameterGroups']
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
        
    #Verify Parameter values for db-instance
    try:        
        for parameter in RDSParameterGroup:
            if parameter['DBParameterGroupName'] and str(parameter['DBParameterGroupName']).find('default') == -1:
                parametergroups.append(parameter['DBParameterGroupName'])
        for parameter in parametergroups:
            Parameter_Det = rds.describe_db_parameters(DBParameterGroupName = parameter, Source = 'user')['Parameters']
            for protocol in Parameter_Det:
                #Checking for MySQL Instance to use latest  block encryption mode for block-based algorithms   
                if protocol['ParameterName'] == 'block_encryption_mode':
                    if str(protocol['ParameterValue']) and str(protocol['ParameterValue']) in ParameterBlockEncryption:
                        enable_aes_latest = 0
                
                #Checking for MySQL Instance to enable FIPS mode on the server side   
                if protocol['ParameterName'] == 'ssl_fips_mode':
                    if str(protocol['ParameterValue']) and str(protocol['ParameterValue']) in ParameterFIPS:
                        ssl_fips = 0
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if db_engine_flag and db_version_flag:
        #Update db parameter ssl_fips_mode     
        if 1 in parametervalues:
            try:
                result = rds.modify_db_parameter_group(DBParameterGroupName = mysql_parameter_group, Parameters = [{'ParameterName': 'ssl_fips_mode','ParameterValue': '1','Description': 'enable FIPS mode on the server side','ApplyMethod': 'immediate'}])

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "Enabled FIPS standards for ssl encryption on the server side for RDS MySQL Instance : %s \n" % RDSInstanceName
                        
            except ClientError as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
            except Exception as e:
                responseCode = 400
                output = "Unexpected error: " + str(e)
                print(output)
                
        #Update db parameter block_encryption_mode
        elif 2 in parametervalues:
            try:
                result = rds.modify_db_parameter_group(DBParameterGroupName = mysql_parameter_group, Parameters = [{'ParameterName': 'block_encryption_mode','ParameterValue': 'aes-256-cbc','Description': 'use latest  block encryption mode','ApplyMethod': 'immediate'}])

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "Enabled use latest block encryption algorithms for RDS MySQL Instance : %s \n" % RDSInstanceName
                        
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
            output = 'DB parameters are already for RDS Instance : '+ RDSInstanceName
            print(output)
        parametervalues = []
    else:
        responseCode = 200
        output = 'These Configuration are not supported for rds instance please upgraded mysql instance : '+ RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output