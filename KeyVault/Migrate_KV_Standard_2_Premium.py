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
   
    try:
        for secret in ls_secrets:
            secret_name = secret.name

            if secret_name not in iignore_array:  #Skip processing elements in iignore_array
                #Backup from source KeyVault
                bysecret_backup = src_secret_client.backup_secret(secret_name)
                
                #Restore backup to Destination KeyVault
                dst_secret_client.restore_secret_backup(bysecret_backup)

        print("[INFO] Migrate source Key Vault secrets to destination Key Vault: Success")

    except Exception as e:
        print("[ERROR] Exception - Function Name: migrate_stdkvsecret_to_prekvsecret")
        print("[Error] Exception Message: ", str(e))            

# Migrate/Move KeyVault Certificates from one KeyVault to another KeyVault
def migrate_stdkvcert_to_prekvcert(isrckv_url, icredential, idestkv_url):
    src_cert_client = CertificateClient(vault_url=isrckv_url, credential=icredential)   #CertificateClient for Source KV
    dest_cert_client = CertificateClient(vault_url=idestkv_url, credential=icredential) #CertificateClient for Destination KV
    ls_certs = src_cert_client.list_properties_of_certificates()
    
    try:
        for cert in ls_certs:
            cert_name = cert.name
            #Backup from source KeyVault
            bycert_backup = src_cert_client.backup_certificate(cert_name)
            
            #Restore backup to Destination KeyVault
            dest_cert_client.restore_certificate_backup(bycert_backup)
        print("[INFO] Migrate source Key Vault certificates to destination Key Vault: Success")

    except Exception as e:
        print("[ERROR] Exception - Function Name: migrate_stdkvcert_to_prekvcert")
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

if __name__ == "__main__":
    # Azure Authentication Details
    tenant_id = ""
    client_id = ""
    client_secret = ""
    local_credential = azure_login(client_id, client_secret, tenant_id)

    # Key Vault Details
    std_kv_url = ""
    premium_kv_url = ""

    ignore_list = get_lscertificates_from_kv(std_kv_url, local_credential)
    migrate_stdkvsecret_to_prekvsecret(std_kv_url, local_credential, premium_kv_url, ignore_list)
    migrate_stdkvcert_to_prekvcert(std_kv_url, local_credential, premium_kv_url)


