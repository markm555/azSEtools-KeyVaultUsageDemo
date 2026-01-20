
<# 
KeyVaultDemo.ps1

PowerShell version of the C# demo using:
- Env-based Service Principal (AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET)
- Managed Identity (when running in Azure)
- Existing Az context
- Interactive login fallback

Implements:
- Read-Secret
- Write-Secret
- Export-AllSecrets
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------- Helpers -------------------------

function Get-VaultNameFromInput {
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultInput
    )

    # Accept either:
    #   "https://myvault.vault.azure.net/"
    # or "myvault"
    if ($KeyVaultInput -match '^https?://') {
        try {
            $uri = [Uri]$KeyVaultInput
            # host looks like: myvault.vault.azure.net
            $vaultName = $uri.Host.Split('.')[0]
            return $vaultName
        }
        catch {
            throw "Invalid Key Vault URL: $KeyVaultInput"
        }
    }

    return $KeyVaultInput.Trim()
}

function Connect-AzDefaultLike {
    <#
    Tries a DefaultAzureCredential-like order:
      1) Env vars (SP)
      2) Managed Identity
      3) Existing Az context
      4) Interactive (Connect-AzAccount)
    #>

    # 3) Existing context?
    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if ($null -ne $ctx -and $null -ne $ctx.Account) {
        return
    }

    # 1) Environment variables (Service Principal)
    if ($env:AZURE_CLIENT_ID -and $env:AZURE_TENANT_ID -and $env:AZURE_CLIENT_SECRET) {
        $sec = ConvertTo-SecureString $env:AZURE_CLIENT_SECRET -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($env:AZURE_CLIENT_ID, $sec)

        Connect-AzAccount -ServicePrincipal -Tenant $env:AZURE_TENANT_ID -Credential $cred | Out-Null
        return
    }

    # 2) Managed Identity (works on Azure resources with MI enabled)
    try {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        return
    }
    catch {
        # ignore and continue
    }

    # 4) Interactive fallback
    Connect-AzAccount | Out-Null
}

# ------------------------- Key Vault Ops -------------------------

function Read-Secret {
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultInput,

        [Parameter(Mandatory)]
        [string]$SecretName
    )

    Connect-AzDefaultLike

    $vaultName = Get-VaultNameFromInput -KeyVaultInput $KeyVaultInput

    try {
        # -AsPlainText returns the secret value as a string
        return Get-AzKeyVaultSecret -VaultName $vaultName -Name $SecretName -AsPlainText
    }
    catch {
        # Best-effort "404-like" handling
        $msg = $_.Exception.Message
        if ($msg -match 'SecretNotFound|was not found|NotFound') {
            return "Secret '$SecretName' was not found in the vault."
        }
        return $msg
    }
}

function Write-Secret {
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultInput,

        [Parameter(Mandatory)]
        [string]$SecretName,

        [Parameter(Mandatory)]
        [string]$SecretValue
    )

    Connect-AzDefaultLike

    $vaultName = Get-VaultNameFromInput -KeyVaultInput $KeyVaultInput

    try {
        $secureValue = ConvertTo-SecureString $SecretValue -AsPlainText -Force
        Set-AzKeyVaultSecret -VaultName $vaultName -Name $SecretName -SecretValue $secureValue | Out-Null
        return ""  # match your C# behavior
    }
    catch {
        return $_.Exception.Message
    }
}

function Export-AllSecrets {
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultInput
    )

    Connect-AzDefaultLike

    $vaultName = Get-VaultNameFromInput -KeyVaultInput $KeyVaultInput

    $secrets = @{}

    # Lists secret metadata; does not include values.
    $secretRefs = Get-AzKeyVaultSecret -VaultName $vaultName

    foreach ($ref in $secretRefs) {
        try {
            $value = Get-AzKeyVaultSecret -VaultName $vaultName -Name $ref.Name -AsPlainText
            $secrets[$ref.Name] = $value
        }
        catch {
            $secrets[$ref.Name] = "Error retrieving value: $($_.Exception.Message)"
        }
    }

    return $secrets
}

# ------------------------- "Main" Demo -------------------------

# Optional: set SP env vars (persistent at User scope) like your C# sample
# Only run once per machine if desired:
<#
$clientId     = "<your-service-principal-client-id>"
$tenantId     = "<your-tenant-id>"
$clientSecret = "<your-service-principal-secret>"

[Environment]::SetEnvironmentVariable("AZURE_CLIENT_ID",     $clientId,     "User")
[Environment]::SetEnvironmentVariable("AZURE_TENANT_ID",     $tenantId,     "User")
[Environment]::SetEnvironmentVariable("AZURE_CLIENT_SECRET", $clientSecret, "User")


Write-Host ("AZURE_CLIENT_ID: " + $env:AZURE_CLIENT_ID)
Write-Host ("AZURE_TENANT_ID: " + $env:AZURE_TENANT_ID)
Write-Host ("AZURE_CLIENT_SECRET: " + ($(if ($env:AZURE_CLIENT_SECRET) { "***set***" } else { "" })))
#>

# Replace with your Key Vault URL or name
$keyVaultInput = "https://markm-keys.vault.azure.net/"
$secretName    = "PS1Secret"
$secretValue   = "ReallyCoolSecretValue"

$secr = Read-Secret -KeyVaultInput $keyVaultInput -SecretName $secretName
Write-Host "---------------------------- Read Secret Values ----------------------------"
Write-Host ("Current Secret Value: " + $secr)

$secw = Write-Secret -KeyVaultInput $keyVaultInput -SecretName $secretName -SecretValue $secretValue
# Write-Host "WriteSecret result: $secw"

$secr2 = Read-Secret -KeyVaultInput $keyVaultInput -SecretName $secretName
Write-Host "---------------------------- Read Secret Values ----------------------------"
Write-Host ("New Secret Value: " + $secr2)

Write-Host "------------------------- Export All Secret Values -------------------------"
$allSecrets = Export-AllSecrets -KeyVaultInput $keyVaultInput
$allSecrets.GetEnumerator() | Sort-Object Name | ForEach-Object {
    Write-Host ("{0} = {1}" -f $_.Name, $_.Value)
}



