import subprocess
import sys

def install_package(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

required_packages = ['azure-identity', 'requests']
for package in required_packages:
    try:
        __import__(package.replace('-', '_'))
    except ImportError:
        print(f"Installing {package}...")
        install_package(package)

import requests
from azure.identity import ClientSecretCredential

# Azure Credentials
TENANT_ID = "50ea0418-683d-4007-87fb-c13c8f6b5d0b"
APPLICATION_ID = "66dff16a-801d-4d49-b0da-2d12b2664bef"
SECRET = "B718Q~3CGt0Uw6Nr5NxYHuISxDnkZSew7leApdwy"

# Authenticate and get token
credential = ClientSecretCredential(
    tenant_id=TENANT_ID,
    client_id=APPLICATION_ID,
    client_secret=SECRET
)

token = credential.get_token("https://graph.microsoft.com/.default")  # requires app permission Policy.Read.ConditionalAccess granted+consented

# Set up headers with the token
headers = {
    "Authorization": f"Bearer {token.token}",
    "Content-Type": "application/json"
}

# Call Microsoft Graph API to get Conditional Access Policies
url = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
response = requests.get(url, headers=headers)

# Get the count of policies
if response.status_code == 200:
    data = response.json()
    policies = data.get('value', [])
    NumberOfConditionalAccessPolicies = len(policies)
else:
    NumberOfConditionalAccessPolicies = 0

    print(NumberOfConditionalAccessPolicies)
