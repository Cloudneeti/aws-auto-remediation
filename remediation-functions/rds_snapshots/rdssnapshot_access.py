'''
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