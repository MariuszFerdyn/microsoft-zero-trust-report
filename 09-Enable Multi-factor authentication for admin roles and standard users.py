import subprocess

try:
    import requests
    from azure.identity import ClientSecretCredential
except ImportError:
    # Attempt to install via conda (Anaconda/Miniconda must be available)
    cmds = [
        ["conda", "install", "-y", "-c", "conda-forge", "azure-identity", "requests"],
        ["conda", "install", "-y", "azure-identity", "requests"],
    ]
    for cmd in cmds:
        print(f"Installing dependencies with: {' '.join(cmd)}", flush=True)
        result = subprocess.run(cmd, check=False)
        if result.returncode == 0:
            break
    else:
        raise ImportError(
            "conda install failed. Try: conda install -c conda-forge azure-identity requests"
        )
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
