#Migrate Standard keyvault Certfificats, Secrets to Premium key vault
from azure.storage.blob import BlobClient
from azure.keyvault.keys import KeyClient
from azure.keyvault.secrets import SecretClient
from azure.keyvault.certificates import CertificateClient
from azure.identity import ClientSecretCredential
from az.cli import az
import datetime

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
  result = mon+date+time
  return result

# Migrate/Move KeyVault secrets from one KeyVault to another KeyVault
def migrate_stdkvsecret_to_prekvsecret(isrckv_url, icredential, idstkv_url, iignore_array):
    src_secret_client = SecretClient(vault_url=isrckv_url, credential=icredential)  #SecretClient for Source KV
    dst_secret_client = SecretClient(vault_url=idstkv_url, credential=icredential)  #SecretClient for Destination KV
    ls_secrets = src_secret_client.list_properties_of_secrets()
   
    for secret in ls_secrets:
        secret_name = secret.name

        if secret_name not in iignore_array:  #Skip processing elements in iignore_array
            #Backup from source KeyVault
            bysecret_backup = src_secret_client.backup_secret(secret_name)
            
            #Restore backup to Destination KeyVault
            dst_secret_client.restore_secret_backup(bysecret_backup)

# Migrate/Move KeyVault Certificates from one KeyVault to another KeyVault
def migrate_stdkvcert_to_prekvcert(isrckv_url, icredential, idestkv_url):
    src_cert_client = CertificateClient(vault_url=isrckv_url, credential=icredential)   #CertificateClient for Source KV
    dest_cert_client = CertificateClient(vault_url=idestkv_url, credential=icredential) #CertificateClient for Destination KV
    ls_certs = src_cert_client.list_properties_of_certificates()

    for cert in ls_certs:
        cert_name = cert.name
        #Backup from source KeyVault
        bycert_backup = src_cert_client.backup_certificate(cert_name)
        
        #Restore backup to Destination KeyVault
        dest_cert_client.restore_certificate_backup(bycert_backup)

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

# Backup KeyVault keys to storage container
def backup_kvkeys_to_blob(ikv_url, icredential, iblob_conn_string, icontainer_name, iignore_array):
    key_client = KeyClient(vault_url=ikv_url, credential=icredential)
    ls_keys = key_client.list_properties_of_keys()
    
    for key in ls_keys:
        key_name = key.name

        if key_name not in iignore_array: #Skip processing elements in iignore_array
            blob_name = time_stamp() +"_keys_" + key_name + ".keybackup"
            bykey_backup = key_client.backup_key(key_name)

            #Upload to storage account
            blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
            ret_blob = blob.upload_blob(bykey_backup)
        
        if len(ret_blob) == 0:
            print("[Failed] backup_kvkeys_to_blob - Error in uploading keys backup to storage")
            return False

    print("[Success] backup_kvkeys_to_blob - Uploaded Keys backup to storage")
    return True   

if __name__ == "__main__":
    # # Login Details
    tenant_id = automationassets.get_automation_variable("tenant_id")
    client_id = automationassets.get_automation_variable("client_id")
    client_secret = automationassets.get_automation_variable("client_secret")

    local_credential = azure_login(client_id, client_secret, tenant_id)

    #credential is used to authenticate in multiple ways (Currently using azuer cli logged in credentials)
    #local_credential = DefaultAzureCredential()

    #*************** Test vera env details ***************
    std_kv_url = ""
    premium_kv_url = ""
    stg_container_name = ""
    connection_string = ""
    #******************************************************

    ignore_list = get_lscertificates_from_kv(std_kv_url, local_credential)
    print("[INFO] Back up KeyVault keys to Storage container")
    backup_kvkeys_to_blob(std_kv_url, local_credential, connection_string, stg_container_name, ignore_list)
    print("[INFO] Migrate Secretes from Standard KeyVault to Premium KeyVault")
    migrate_stdkvsecret_to_prekvsecret(std_kv_url, local_credential, premium_kv_url, ignore_list)
    print("[INFO] Migrate Certificates from Standard KeyVault to Premium KeyVault")
    migrate_stdkvcert_to_prekvcert(std_kv_url, local_credential, premium_kv_url)


