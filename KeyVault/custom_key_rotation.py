# Modules
from time import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from azure.identity import ClientSecretCredential
from azure.keyvault.keys import KeyClient
from az.cli import az
import datetime
import os
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient, __version__
#import automationassets
#from automationassets import AutomationAssetNotFound
from azure.keyvault.secrets import SecretClient #Added to Backup secrets from KeyVault
from azure.keyvault.certificates import CertificateClient #Added to Backup certificates from KeyVault
from azure.identity import DefaultAzureCredential #Added for authentication

# Azure login
def azure_login(client_id,client_secret,tenant_id):
  exit_code, result_dict, logs = az("login --service-principal -u {0} -p {1} --tenant {2}".format(client_id,client_secret,tenant_id))
  credential = ClientSecretCredential(tenant_id,client_id,client_secret)
  if exit_code == 0:
    return True,credential
  return False,None

# generate private/public key pair
def ssh_key_pair_generation():  
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, \
        key_size=3072)

    # get public key in OpenSSH format
    public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH, \
        serialization.PublicFormat.OpenSSH)

    # get private key in PEM container format
    pem = key.private_bytes(encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

    # decode to printable strings
    private_key_str = pem.decode('utf-8')
    public_key_str = public_key.decode('utf-8')
    return private_key_str

def time_stamp(keyName):
  x = datetime.datetime.now()
  mon = x.strftime("%b")+"_"
  date = x.strftime("%d")+"_"
  time = x.strftime("%X")
  time = time.split(":")
  time = "_".join(time)
  result = keyName+"_"+mon+date+time+".pem"
  return result

def private_key(filename,private_key_str):
  f = open(filename,'w')
  f.write(private_key_str)
  f.close()

def key_import(keyVaultName,keyName,filename):
  exit_code, result_dict, logs = az("keyvault key import --vault-name {0} --name {1} --pem-file {2} --protection hsm".format(keyVaultName,keyName,filename))
  if exit_code == 0:
    return True
  return False

# Adding the new key from key-vault to the server
def key_updation(server_name,resource_group_name):
  KVUri = "https://" + keyVaultName + ".vault.azure.net"
  client = KeyClient(vault_url=KVUri, credential=credential)
  retrieved_key = client.get_key(keyName)
  key_id = retrieved_key.id
  uploadfilename = key_id[-32:]  
  exit_code1, result_dict, logs = az("sql server key create --kid {0} --resource-group {1} --server {2}".format(key_id,resource_group_name,server_name))
  exit_code2, result_dict, logs = az("sql server tde-key set --server-key-type AzureKeyVault --kid {0} --resource-group {1} --server {2}".format(key_id,resource_group_name,server_name))
  if exit_code1!=0 and exit_code2!=0:
    return False
  return uploadfilename

def storage_key_updation(storage_account_name,resource_group_name,keyName,temp):
  KVUri = "https://" + keyVaultName + ".vault.azure.net/"
  exit_code, result_dict, logs = az("storage account update --name {0} --resource-group {1} --encryption-key-name {2} --encryption-key-version {3} --encryption-key-source Microsoft.Keyvault --encryption-key-vault {4}".format(storage_account_name,resource_group_name,keyName,temp,KVUri))
  if exit_code == 0:
    return True
  return False

def storageupload(connection_string,container_name,uploadfilename):
  blob_service_client = BlobServiceClient.from_connection_string(connection_string)
  blob_client = blob_service_client.get_blob_client(container=container_name, blob=uploadfilename)
  with open(uploadfilename, "rb") as data:
    blob_client.upload_blob(data)
  container_client = blob_service_client.get_container_client(container_name)
  blob_list = container_client.list_blobs()
  for blob in blob_list:
    if uploadfilename==blob.name:
      return True
  return False

#Disable older versions of keys in KeyVault
def disable_older_version_of_key(ikv_url, icredential, ikey_name):#, icurrent_keyversion):
    key_client = KeyClient(vault_url=ikv_url, credential=icredential)
    ls_keyversions = key_client.list_properties_of_key_versions(ikey_name)
    
    retrieved_key = key_client.get_key(keyName)
    current_key_id = retrieved_key.id
    curr_version = current_key_id[-32:]
    print(curr_version)

    # The following backup activity will be executed only when there is atleast one entry found  
    for version in ls_keyversions:
        ver_id = version.id
        key_id = ver_id[-32:]
        
        if key_id != curr_version:
          print(key_id)
          updated_key = key_client.update_key_properties(ikey_name, key_id, enabled=False)

          if updated_key is None:
            print("[Failed] disable_older_version_of_key - key updation failed")
            return False  #Return false if script fails to disable specified key version 
    
    print("[Success] disable_older_version_of_key - function succeded")
    return True

#Download KeyVault Secret to local
def backup_kvsecret_to_blob(ikv_url, icredential, iblob_conn_string, icontainer_name):
    secret_client = SecretClient(vault_url=ikv_url, credential=icredential)
    ls_secrets = secret_client.list_properties_of_secrets()

    # The following backup activity will be executed only when there is atleast one entry found  
    for secret in ls_secrets:
        secret_name = secret.name
        blob_name = time_stamp() +"_secret_" + secret_name + ".backup"
        bysecret_backup = secret_client.backup_secret(secret_name)

        #Upload to storage account
        blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
        ret_blob = blob.upload_blob(bysecret_backup)

        if len(ret_blob) == 0:
            print("[Failed] backup_kvsecret_to_blob - Error in uploading secret backup to storage")
            return False
    
    print("[Success] backup_kvsecret_to_blob - Uploaded secret backup to storage")
    return True



#Download KeyVault Certificate to local
def backup_kvcert_to_blob(ikv_url, icredential, iblob_conn_string, icontainer_name):
    certificate_client = CertificateClient(vault_url=ikv_url, credential=icredential)
    ls_certs = certificate_client.list_properties_of_certificates()
    
    # The following backup activity will be executed only when there is atleast one entry found  
    for certs in ls_certs:
        cert_name = certs.name
        blob_name = time_stamp() +"_cert_" + cert_name  + ".backup"
        bycert_backup = certificate_client.backup_certificate(cert_name)
        
        #Upload to storage account
        blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
        ret_blob = blob.upload_blob(bycert_backup)
        
        if len(ret_blob) == 0:
            print("[Failed] backup_kvcert_to_blob - Error in uploading secret backup to storage")
            return False
    
    print("[Success] backup_kvcert_to_blob - Uploaded Certs backup to storage")
    return True        

#Download KeyVault keys to local
def backuop_kvkeys_to_blob(ikv_url, icredential, iblob_conn_string, icontainer_name):
    key_client = KeyClient(vault_url=ikv_url, credential=icredential)
    ls_keys = key_client.list_properties_of_keys()
      
    for key in ls_keys:
        key_name = key.name
        blob_name = time_stamp() +"_keys_" + key_name + ".backup"
        bycert_backup = key_client.backup_key(key_name)

        #Upload to storage account
        blob = BlobClient.from_connection_string(conn_str=iblob_conn_string, container_name=icontainer_name, blob_name=blob_name)
        ret_blob = blob.upload_blob(bycert_backup)
        
        if len(ret_blob) == 0:
            print("[Failed] backuop_kvkeys_to_blob - Error in uploading keys backup to storage")
            return False

    print("[Success] backuop_kvkeys_to_blob - Uploaded Keys backup to storage")
    return True   

# Main Function
if __name__ == "__main__":
  # Login Details
  tenant_id = ""
  client_id = ""
  client_secret = ""
    #local_credential = azure_login(client_id, client_secret, tenant_id)

  # KeyVault Details
  keyVaultName = ""
  keyName = ""
  keyVer = ""

  # # SQL Server Details
  # resource_group_name = ""
  # server_name = ""

  # # Storage Details
  # connection_string = automationassets.get_automation_variable("connection_string")
  # storage_resource_group_name = ""
  # storage_account_name = ""
  # container_name = ""
  stg_container_name = ""
  connection_string = ""
    

  # Initial Variables
  initiate_key_generation = False
  initiate_key_import = False
  initiate_key_update = False
  initiate_key_backup = False
  initiate_file_upload = False

  # Function Calling
  try:
    boolval,credential = azure_login(client_id,client_secret,tenant_id)
    if boolval:
      initiate_key_generation = True
      print("1/8 Azure Login -- Success")
    else:
      print("1/8 Azure Login -- Failed")
  except:
    print("1/8 Azure Login -- Failed")

  if initiate_key_generation:
    private_key_str = ssh_key_pair_generation()
    print("2/8 SSH Key Generated -- Success")
    filename = time_stamp(keyName)
    privatekey = private_key(filename,private_key_str)
    initiate_key_import = True

  try:
    if initiate_key_import:
      if key_import(keyVaultName,keyName,filename):
        print("3/8 Key Import to Azure Key Vault -- Success")
        initiate_key_update = True
      else:
        print("3/8 Key Import to Azure Key Vault -- Failed")
  except:
    print("3/8 Key Import to Azure Key Vault -- Failed")

  # try:
  #   if initiate_key_update:
  #     uploadfilename = key_updation(server_name,resource_group_name)
  #     keyVer = uploadfilename
  #     temp = uploadfilename # For storage encryption
  #     uploadfilename = uploadfilename+".txt"
  #     print("")
  #     if uploadfilename:
  #       print("4/8 Key update to azure sql server TDE -- Success")
  #       intiate_key_update_in_storage = True
  #     else:
  #       print("4/8 Key update to azure sql server TDE -- Failed")
  # except:
  #   print("4/8 Key update to azure sql server TDE -- Failed")

  # try:
  #   if intiate_key_update_in_storage:
  #     if storage_key_updation(storage_account_name,storage_resource_group_name,keyName,temp):
  #       print("5/8 Key Updation in Storage Encryption -- Success")
  #       initiate_file_upload = True
  #     else:
  #       print("5/8 Key Updation in Storage Encryption -- Failed")
  # except:
  #   print("5/8 Key Updation in Storage Encryption -- Failed")

  # try:
  #   if initiate_file_upload:    
  #     os.rename(filename,uploadfilename)
  #     if storageupload(connection_string,container_name,uploadfilename):
  #       print("6/8 File Uploaded to Azure Storage -- Success")
  #       os.remove(uploadfilename)
  #     else:
  #       print("6/8 File Uploaded to Azure Storage -- Failed")
  # except:
  #   print("6/8 File Uploaded to Azure Storage -- Failed")

  try:
    if initiate_key_import:
      kv_url = "https://" + keyVaultName + ".vault.azure.net"
      is_old_ver_disabled = disable_older_version_of_key(kv_url, credential, keyName) #, keyVer)

      if is_old_ver_disabled:
        print("7/8 [INFO] Disable older key version: Success")
      else:
        print("7/8 [ERROR] Disable older key version: Failed")
  except:
    print("7/8 Key Import to Azure Key Vault -- Failed")

  # try:
  #   if initiate_key_import:
  #     kv_url = "https://" + keyVaultName + ".vault.azure.net"
  #     local_credential = DefaultAzureCredential()
  #     is_key_bkp_success = backuop_kvkeys_to_blob(kv_url, local_credential, connection_string, stg_container_name)
  #     is_secret_bkp_success = backup_kvsecret_to_blob(kv_url, local_credential, connection_string, stg_container_name)
  #     is_cert_bkp_success = backup_kvcert_to_blob(kv_url, local_credential, connection_string, stg_container_name)
      
  #   if is_key_bkp_success and is_secret_bkp_success and is_cert_bkp_success:
  #       print("[INFO] Backup : Success")
  #   else:
  #       print("[INFO] Backup : Failed")
  # except:
  #   print("8/8 Key Import to Azure Key Vault -- Failed")


