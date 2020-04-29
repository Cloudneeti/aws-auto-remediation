'''
Copyright (c) Cloudneeti. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is  furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Private RDS-Snapshot
'''

from botocore.exceptions import ClientError

def run_remediation(rds, RDSSnapshotName):
    print("Executing RDS Instance remediation")
    Snapshot_Detail = ''
    snapshot_not_encrypted = False
    access_flag = False
    try:
        Snapshot_Detail = rds.describe_db_snapshots(DBSnapshotIdentifier=RDSSnapshotName,SnapshotType='manual')['DBSnapshots']
        if Snapshot_Detail[0]['Encrypted'] == False:
            snapshot_not_encrypted = True
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if snapshot_not_encrypted:
        
        try:    
            Snapshot_Attribute = rds.describe_db_snapshot_attributes(DBSnapshotIdentifier=RDSSnapshotName)['DBSnapshotAttributesResult']
            if 'all' in Snapshot_Attribute['DBSnapshotAttributes'][0]['AttributeValues']:
                access_flag = True
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            
        if access_flag:

            try:
                result = rds.modify_db_snapshot_attribute(
                            DBSnapshotIdentifier=RDSSnapshotName,
                            AttributeName='restore',
                            ValuesToRemove=[
                                'all'
                            ]
                        )

                responseCode = result['ResponseMetadata']['HTTPStatusCode']
                if responseCode >= 400:
                    output = "Unexpected error: %s \n" % str(result)
                else:
                    output = "RDS snapshot is now private : %s \n" % RDSSnapshotName
                        
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
            output='RDS snapshot is already private : '+RDSSnapshotName
            print(output)
    
    else:
        responseCode=200
        output='RDS snapshot is encrypted and hence private : '+RDSSnapshotName
        print(output)

    print(str(responseCode)+'-'+output)
    return responseCode,output