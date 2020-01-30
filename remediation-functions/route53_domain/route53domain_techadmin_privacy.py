'''
Enable KMS Key Rotation
'''

from botocore.exceptions import ClientError

def run_remediation(route53domains,DomainName):
    print("Executing KMS remediation")  
    DomainTransferLock = 1
    DomainAutoRenew = 1
    TechPrivacy = 1
    AdminPrivacy = 1
    OwnerPrivacy = 1         
    try:
        Domain_detail = route53domains.get_domain_detail(DomainName = DomainName)
        if Route53_Domain_Name[0]['TransferLock']:
            DomainTransferLock = 0
        if Domain_detail['AutoRenew']:
            DomainAutoRenew = 0
        if Domain_detail['TechPrivacy']:
            TechPrivacy = 0
        if Domain_detail['AdminPrivacy']:
            AdminPrivacy = 0
        if Domain_detail['RegistrantPrivacy']:
            OwnerPrivacy = 0
    except ClientError as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    except Exception as e:
        responseCode = 400
        output = "Unexpected error: " + str(e)
    
    if DomainTransferLock:        
        try:
            result = route53domains.enable_domain_transfer_lock(DomainName=DomainName)
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Key Rotaion is enabled for: %s \n" % DomainName
                        
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    elif DomainAutoRenew:
        try:
            result = route53domains.enable_domain_auto_renew(DomainName=DomainName)
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Key Rotaion is enabled for: %s \n" % DomainName
                        
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    elif OwnerPrivacy:
        try:
            result = route53domains.update_domain_contact_privacy(
                                        DomainName=DomainName,
                                        RegistrantPrivacy=True
                                    )
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Key Rotaion is enabled for: %s \n" % DomainName
                        
        except ClientError as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
        except Exception as e:
            responseCode = 400
            output = "Unexpected error: " + str(e)
            print(output)
    elif TechPrivacy and AdminPrivacy:
        try:
            result = route53domains.update_domain_contact_privacy(
                                        DomainName=DomainName,
                                        AdminPrivacy=True,
                                        TechPrivacy=True
                                    )
            responseCode = result['ResponseMetadata']['HTTPStatusCode']
            if responseCode >= 400:
                output = "Unexpected error: %s \n" % str(result)
            else:
                output = "Key Rotaion is enabled for: %s \n" % DomainName
                        
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