# Import required Azure SDK libraries
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

# -----------------------------------------------------------------------------
# This program demonstrates how to call Azure Key Vault to perform read and write
# operations using DefaultAzureCredential.
#
# DefaultAzureCredential authentication order of precedence:
#   1. Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
#   2. Managed Identity (system-assigned or user-assigned in Azure)
#   3. Shared Token Cache (tokens cached by Azure CLI, Visual Studio, etc.)
#   4. Visual Studio / VS Code signed-in identity
#   5. Azure CLI (`az login`)
#   6. Azure PowerShell (`Connect-AzAccount`)
#   7. Interactive Browser (if enabled)
#
# Notes:
# - The credential stops at the first successful authentication in this order.
# - In production, Managed Identity is recommended.
# - In local development, environment variables or Azure CLI are common.
# -----------------------------------------------------------------------------

#print(f"AZURE_CLIENT_ID: {env('AZURE_CLIENT_ID')}")
#print(f"AZURE_TENANT_ID: {env('AZURE_TENANT_ID')}")
#print(f"AZURE_CLIENT_SECRET: {env('AZURE_CLIENT_SECRET')}")

# Function to read a secret from Key Vault
def read_secret(key_vault_url: str, secret_name: str) -> str:
    try:
        # Authenticate using DefaultAzureCredential
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Retrieve the secret
        secret = client.get_secret(secret_name)
        return secret.value
    except ResourceNotFoundError:
        return f"Secret '{secret_name}' was not found in the vault."
    except HttpResponseError as ex:
        return f"Error retrieving secret: {ex.message}"

# Function to write (set) a secret in Key Vault
def write_secret(key_vault_url: str, secret_name: str, secret_value: str) -> str:
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=key_vault_url, credential=credential)

        # Set or update the secret
        client.set_secret(secret_name, secret_value)
        return "Secret written successfully."
    except HttpResponseError as ex:
        return f"Error writing secret: {ex.message}"

# Function to export all secrets from Key Vault
def export_all_secrets(key_vault_url: str) -> dict:
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)
    secrets = {}

    # Iterate through all secret properties
    for secret_properties in client.list_properties_of_secrets():
        try:
            secret = client.get_secret(secret_properties.name)
            secrets[secret.name] = secret.value
        except Exception as ex:
            secrets[secret_properties.name] = f"Error retrieving value: {str(ex)}"

    return secrets

# -----------------------------------------------------------------------------
# Main program
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # Replace with your Key Vault URL and secret info
    key_vault_url = "https://markm-keys.vault.azure.net/"
    secret_name = "UberPassword"
    secret_value = "UberCulioDemo"

    # Read secret
    print("---------------------------- Read Secret Values ----------------------------")
    current_value = read_secret(key_vault_url, secret_name)
    print("Current Secret Value:", current_value)

    # Write secret
    print("---------------------------- Write Secret Values ---------------------------")
    result = write_secret(key_vault_url, secret_name, secret_value)
    print(result)

    # Read secret again
    new_value = read_secret(key_vault_url, secret_name)
    print("New Secret Value:", new_value)

    # Export all secrets
    print("------------------------- Export All Secret Values -------------------------")
    all_secrets = export_all_secrets(key_vault_url)
    for name, value in all_secrets.items():
        print(f"{name} = {value}")
