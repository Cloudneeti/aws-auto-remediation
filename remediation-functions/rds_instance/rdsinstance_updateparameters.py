'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Use latest block encryption algorithms for RDS MySQL Instance
Enable FIPS standards for ssl encryption on the server side for RDS MySQL Instance
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSInstanceName):
    print("Executing RDS Instance remediation")  
    ssl_fips = 1
    enable_aes_latest = 1
    default_group = 0
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
        if str(8.0) in dbinstance_details[0]['EngineVersion']:
            db_version_flag = 1
        RDSParameterGroup = dbinstance_details[0]['DBParameterGroups']
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
                default_group = 1
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
    
    if db_engine_flag and db_version_flag and default_group:
        #Update db parameter ssl_fips_mode     
        if ssl_fips == 1:
            try:
                result = rds.modify_db_parameter_group(DBParameterGroupName = RDSParameterGroup[0]['DBParameterGroupName'], Parameters = [{'ParameterName': 'ssl_fips_mode','ParameterValue': '1','Description': 'enable FIPS mode on the server side','ApplyMethod': 'immediate'}])
                
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
        elif enable_aes_latest == 2:
            try:
                result = rds.modify_db_parameter_group(DBParameterGroupName = RDSParameterGroup[0]['DBParameterGroupName'], Parameters = [{'ParameterName': 'block_encryption_mode','ParameterValue': 'aes-256-cbc','Description': 'use latest  block encryption mode','ApplyMethod': 'immediate'}])
                
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
            output = 'DB parameters are already updated for RDS Instance : '+ RDSInstanceName
            print(output)
    else:
        responseCode = 200
        output = 'SSL FIPS or Block Encryption Parameters Configuration are not supported for rds mysql instance please upgraded instance : '+ RDSInstanceName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output