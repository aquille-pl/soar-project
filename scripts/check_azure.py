import os

from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from dotenv import load_dotenv

load_dotenv()

client = NetworkManagementClient(
    DefaultAzureCredential(), os.environ["AZURE_SUBSCRIPTION_ID"]
)
nsg = client.network_security_groups.get(
    os.environ["AZURE_RESOURCE_GROUP"], os.environ["AZURE_NSG_NAME"]
)
print("OK:", nsg.name, nsg.location, len(nsg.security_rules or []), "custom rules")