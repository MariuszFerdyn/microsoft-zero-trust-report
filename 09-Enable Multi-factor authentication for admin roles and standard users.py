#!/usr/bin/env python3
"""
Display Number of Conditional Access Policies
Retrieves and displays the count of Conditional Access Policies from Azure AD
"""

import subprocess
import sys

def install_package(package):
    """Install a package using pip"""
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

def get_conditional_access_policies_count():
    """
    Retrieve the number of Conditional Access Policies from Azure AD
    """
    try:
        # Authenticate using ClientSecretCredential
        credential = ClientSecretCredential(
            tenant_id=TENANT_ID,
            client_id=APPLICATION_ID,
            client_secret=SECRET
        )
        
        # Get access token with specific scope for Conditional Access
        token = credential.get_token("https://graph.microsoft.com/Policy.Read.ConditionalAccess")
        
        # Set up headers with the token
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json"
        }
        
        # Call Microsoft Graph API to get Conditional Access Policies
        url = "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            policies = data.get('value', [])
            NumberOfConditionalAccessPolicies = len(policies)
            return NumberOfConditionalAccessPolicies
        else:
            print(f"Error: {response.status_code}")
            print(f"Response: {response.text}")
            return 0
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return 0

def main():
    """
    Main function to display the number of Conditional Access Policies
    """
    print("Retrieving Conditional Access Policies...")
    print("-" * 50)
    
    # Get the number of Conditional Access Policies
    NumberOfConditionalAccessPolicies = get_conditional_access_policies_count()
    
    # Display the result
    print(f"Number Of Conditional Access Policies: {NumberOfConditionalAccessPolicies}")
    print("-" * 50)
    
    return NumberOfConditionalAccessPolicies

if __name__ == "__main__":
    result = main()
