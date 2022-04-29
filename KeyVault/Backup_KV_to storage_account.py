#Migrate Standard keyvault Certfificats, Secrets to Premium key vault
from pickle import TRUE
from azure.storage.blob import BlobClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from az.cli import az
import datetime
from datetime import date

#import automationassets
#from automationassets import AutomationAssetNotFound

# Azure login
def azure_login(client_id,client_secret,tenant_id):
  credential = ClientSecretCredential(tenant_id,client_id,client_secret)
  return credential

def time_stamp():
  x = datetime.datetime.now()
  mon = x.strftime("%b")+"_"
  date = x.strftime("%d")+"_"
  time = x.strftime("%X")
  time = time.split(":")
  time = "_".join(time)
  result = date+time
  return result

#Disable all older key version in key vault
def disable_older_key_version(isrckv_url, icredential, iignore_list, ikey_list=[]):
    key_client = KeyClient(vault_url=isrckv_url, credential=icredential)
    ls_keys = key_client.list_properties_of_keys()
    
    try:
        if len(ikey_list) == 0: #No key specified. Disable older version of all keys
            for key in ls_keys:
                key_name = key.name

                if key_name not in iignore_list:
                    key_obj = key_client.get_key(key_name)
                    current_version = key_obj.id[-32:]
                    ls_key_versions = key_client.list_properties_of_key_versions(key_name)

                    for version in ls_key_versions:
                        id = version.id[-32:]
                        
                        if id != current_version:
                            key_client.update_key_properties(key_name, id, enabled=False)

        else:   #Only disable older version of specified key
            for key in ikey_list:
                key_obj = key_client.get_key(key)
                key_name = key_obj.name
                current_version = key_obj.id[-32:]
                ls_key_versions = key_client.list_properties_of_key_versions(key_name)

                for version in ls_key_versions:
                    id = version.id[-32:]
                    
                    if id != current_version:
                        key_client.update_key_properties(key_name, id, enabled=False)

        print("[INFO] Disable Older version of keys: Success")

    except Exception as e:
        print("[ERROR] Exception - Function Name: disable_older_key_version")
        print("[Error] Exception Message: ", str(e)) 

#Disable older secret version in key vault
def disable_older_secret_version(isrckv_url, icredential, iignore_list, ils_disable=[]):
    secret_client = SecretClient(vault_url=isrckv_url, credential=icredential)
    ls_secrets = secret_client.list_properties_of_secrets()
    try:
        if len(ils_disable) == 0: #No secret specified. Disable older version of all secret
            for secret in ls_secrets:
                secret_name = secret.name

                if secret_name not in iignore_list:
                    secret_obj = secret_client.get_secret(secret_name)
                    current_version = secret_obj.id[-32:]
                    ls_secret_versions = secret_client.list_properties_of_secret_versions(secret_name)

                    for version in ls_secret_versions:
                        id = version.id[-32:]
                        
                        if id != current_version:
                            secret_client.update_secret_properties(secret_name, id, enabled=False)

        else:   #Only disable older version of specified secret
            for secret in ils_disable:
                secret_obj = secret_client.get_secret(secret)
                secret_name = secret_obj.name
                current_version = secret_obj.id[-32:]
                ls_secret_versions = secret_client.list_properties_of_secret_versions(secret_name)

                for version in ls_secret_versions:
                    id = version.id[-32:]
                    
                    if id != current_version:
                        secret_client.update_secret_properties(secret_name, id, enabled=False)
        print("[INFO] Disable Older version of secret: Success")

    except Exception as e:
        print("[ERROR] Exception - Function Name: disable_older_secret_version")
        print("[Error] Exception Message: ", str(e)) 

#Disable older certificate version in key vault
def disable_older_cert_version(isrckv_url, icredential, iignore_list, ils_disable=[]):
    cert_client = CertificateClient(vault_url=isrckv_url, credential=icredential)
    ls_certs = cert_client.list_properties_of_certificates()
    try:
        if len(ils_disable) == 0: #No certificate specified. Disable older version of all certificate
            
            for certs in ls_certs:
                cert_name = certs.name
                cert_obj = cert_client.get_certificate(cert_name)
                current_version = cert_obj.id[-32:]
                ls_cert_versions = cert_client.list_properties_of_certificate_versions(cert_name)

                for version in ls_cert_versions:
                    id = version.id[-32:]
                    
                    if id != current_version:
                        cert_client.update_certificate_properties(cert_name, id, enabled=False)

        else:   #Only disable older version of specified certificate
            for cert in ils_disable:
                cert_obj = cert_client.get_certificate(cert)
                cert_name = cert_obj.name
                current_version = cert_obj.id[-32:]
                ls_cert_versions = cert_client.list_properties_of_certificate_versions(cert_name)

                for version in ls_cert_versions:
                    id = version.id[-32:]
                    
                    if id != current_version:
                        cert_client.update_certificate_properties(cert_name, id, enabled=False)
        print("[INFO] Disable Older version of certificates: Success")

    except Exception as e:
        print("[ERROR] Exception - Function Name: disable_older_cert_version")
        print("[Error] Exception Message: ", str(e)) 

# Get list of certificates form Keyvault. 
# This list will be helpful in creating back up of Keys and Secrets as adding certificate will add a Key and Secret wwith same name to Keyvault
def get_lscertificates_from_kv(ikvurl, icredential):
    cert_client = CertificateClient(vault_url=ikvurl, credential=icredential)
    ls_certs = cert_client.list_properties_of_certificates()
    ary_ignore_certname = []

    for cert in ls_certs:
        cert_name = cert.name
        ary_ignore_certname.append(cert_name)  #Adding to array as to ignore processing of same values in keys and secrets

    return ary_ignore_certname

#Backup KeyVault keys to storage account
def backup_kvkeys_to_blob(ikv_url, icredential, iignore_list, iblob_conn_string, icontainer_name):
    key_client = KeyClient(vault_url=ikv_url, credential=icredential)
    ls_keys = key_client.list_properties_of_keys()
    
    for key in ls_keys:
        key_name = key.name
        key = key_client.get_key(key_name)
        current_version = key.id[-32:]

        if key_name not in iignore_list: #Skip processing elements in iignore_array
            blob_name = str(current_year) + "/keys/"+ current_month +"/" +  time_stamp() +"_" + key_name + "_" + current_version + ".keybackup"
            bykey_backup = key_client.backup_key(key_name)

            #Upload to storage account
            blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
            ret_blob = blob.upload_blob(bykey_backup)
        
        # if len(ret_blob) == 0:
        #     print("[Failed] backup_kvkeys_to_blob - Error in uploading keys backup to storage")
        #     return False

    print("[INFO] Upload key backup to storage: Success")
    return True

#Backup KeyVault secrets to storage account
def backup_kvsecrets_to_blob(ikv_url, icredential, iignore_list, iblob_conn_string, icontainer_name): #, iignore_array):
    secret_client = SecretClient(vault_url=ikv_url, credential=icredential)
    ls_secrets = secret_client.list_properties_of_secrets()
    
    for secret in ls_secrets:
        secret_name = secret.name

        #Get current version of secret
        secret = secret_client.get_secret(secret_name)
        current_version = secret.id[-32:]

        if secret_name not in iignore_list: #Skip processing elements in iignore_array
            blob_name = str(current_year) + "/secrets/"+ current_month +"/" + time_stamp() + "_"+ secret_name + "_" + current_version + ".secretbackup"
            bysecret_backup = secret_client.backup_secret(secret_name)

            #Upload to storage account
            blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
            ret_blob = blob.upload_blob(bysecret_backup)
        
        # if len(ret_blob) == 0:
        #     print("[Failed] backup_kvsecrets_to_blob - Error in uploading secret backup to storage")
        #     return False

    print("[INFO] Upload secret backup to storage: Success")
    return True

#Backup KeyVault certificates to storage account
def backup_kvcert_to_blob(ikv_url, icredential, iblob_conn_string, icontainer_name): #, iignore_array):
    cert_client = CertificateClient(vault_url=ikv_url, credential=icredential)
    ls_cert = cert_client.list_properties_of_certificates()
    
    for cert in ls_cert:
        cert_name = cert.name

        #Get current version of secret
        cert = cert_client.get_certificate(cert_name)
        current_version = cert.id[-32:]
        blob_name = str(current_year) + "/certs/"+ current_month +"/" + time_stamp() +"_" +  cert_name + "_" + current_version + ".certificatebackup"
        bysecret_backup = cert_client.backup_certificate(cert_name)

        #Upload to storage account
        blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
        ret_blob = blob.upload_blob(bysecret_backup)
        
        # if len(ret_blob) == 0:
        #     print("[Failed] backup_kvcert_to_blob - Error in uploading certificate backup to storage")
        #     return False

    print("[INFO] Upload certificate backup to storage: Success")
    return True

if __name__ == "__main__":
    #Azure Authentication details
    tenant_id = ""
    client_id = ""
    client_secret = ""
    local_credential = azure_login(client_id, client_secret, tenant_id)

    #Key Vault and Storage Account details
    key_url = ""
    stg_connection_str = ""
    container_name = ""
    
    #Get Current year and month
    #current_year and current_month variable is used for file path in backup operation
    todays_date = date.today()
    current_year = todays_date.year 
    x = datetime.datetime.now()
    current_month = x.strftime("%b")

    ignore_list = get_lscertificates_from_kv(key_url, local_credential)
    print("===================== Key Vault Backup operation starts =====================")
    # backup_kvkeys_to_blob(key_url, local_credential, ignore_list, stg_connection_str, container_name)
    # backup_kvsecrets_to_blob(key_url, local_credential, ignore_list, stg_connection_str, container_name)
    # backup_kvcert_to_blob(key_url, local_credential, stg_connection_str, container_name)
    print("=============================================================================")
    
    
    ls_disable = []
    print("===================== Disable older version operation starts =====================")    
    disable_older_key_version(key_url, local_credential, ignore_list) #, ls_disable)
    disable_older_secret_version(key_url, local_credential, ignore_list) #, ls_disable)
    disable_older_cert_version(key_url, local_credential, ignore_list) #, ls_disable)
    print("==================================================================================")

