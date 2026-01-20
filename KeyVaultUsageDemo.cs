using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.ComponentModel.Design;
using System.Net;
using System.Threading.Tasks;

/*
 * This Program is an example of how to call Azure KeyVault to do various read and write operations using Default Credentials
 * This would be fore a Managed Identity in Azure and a Service Principal stored in Environment Variables on you DEV machine that is not in Azure.
 * 
 * DefaultAzureCredential authentication order of precedence:

        1. Environment variables
           - Uses AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET
           - Typically for service principals configured via environment

        2. Managed Identity
           - Uses system-assigned or user-assigned managed identity if running in Azure (VM, App Service, Functions)

        3. Shared Token Cache
           - Uses tokens cached by developer tools (e.g., Azure CLI, Visual Studio)

        4. Visual Studio / Visual Studio Code
           - Authenticates with the identity signed into Visual Studio or VS Code

        5. Azure CLI
           - Uses the account signed in via `az login`

        6. Azure PowerShell
           - Uses the account signed in via `Connect-AzAccount`

        7. Interactive Browser (optional, if enabled)
           - Prompts the user to sign in via browser

        Notes:
        - The credential stops at the first successful authentication in this order.
        - In production, Managed Identity is recommended.
        - In local development, Environment variables or Azure CLI are common.
*/


namespace KeyVaultDemo
{
    class Program
    {
        static async Task<string> ReadSecret(string keyVaulName, string secretName)
        {
            try
            {

                var credential = new DefaultAzureCredential();

                var client = new SecretClient(new Uri(keyVaulName), credential);

                KeyVaultSecret secret = await client.GetSecretAsync(secretName);
                return (secret.Value);
            }
            catch (RequestFailedException ex)
            {
                if (ex.Status == 404)
                {
                    return $"Secret '{secretName}' was not found in the vault.";
                }
                else
                {
                    return (ex.Message);
                }
            }
        }

        static async Task<string> WriteSecret(string keyVaulName, string secretName, string secretValue)
        {
            try
            {
                // DefaultAzureCredential will:
                // - Use your Arc machine's managed identity when running on that machine
                // - Use az login / Visual Studio / environment variables when running locally
                var credential = new DefaultAzureCredential();
                var client = new SecretClient(new Uri(keyVaulName), credential);

                // Retrieve the secret
                //KeyVaultSecret secret = await client.GetSecretAsync(secretName);
                await client.SetSecretAsync(secretName, secretValue);


                //Console.WriteLine($"Secret '{secretName}' value: {secret.Value}");
                return ("");
            }
            catch (RequestFailedException ex)
            {
                return(ex.Message);
            }
        }
        static async Task<Dictionary<string, string>> ExportAllSecrets(string keyVaulName)
        {
            var credential = new DefaultAzureCredential();
            var client = new SecretClient(new Uri(keyVaulName), credential);
            var secrets = new Dictionary<string, string>();

            await foreach (SecretProperties secretProperties in client.GetPropertiesOfSecretsAsync())
            {
                try
                {
                    KeyVaultSecret secret = await client.GetSecretAsync(secretProperties.Name);
                    secrets[secret.Name] = secret.Value;
                }
                catch (Exception ex)
                {
                    secrets[secretProperties.Name] = $"Error retrieving value: {ex.Message}";
                }
            }

            return secrets;
        }
        
    



    static async Task Main(string[] args)
        {

            /* Replace with your service principal for dev work on yourI wa dev machine
             * Only needs to be run once per macvhine
             * These environment variables are persistent and will still be there after logout/login and reboots
             * 
            string clientId = "<your-service-principal-client-id>";
            string tenantId = "<your-tenant-id>";
            string clientSecret = "<your-service-principal-secret>";

            // Set environment variables at the user level
            Environment.SetEnvironmentVariable("AZURE_CLIENT_ID", clientId, EnvironmentVariableTarget.User);
            Environment.SetEnvironmentVariable("AZURE_TENANT_ID", tenantId, EnvironmentVariableTarget.User);
            Environment.SetEnvironmentVariable("AZURE_CLIENT_SECRET", clientSecret, EnvironmentVariableTarget.User);
            */

            Console.WriteLine("AZURE_CLIENT_ID: " + Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"));
            Console.WriteLine("AZURE_TENANT_ID: " + Environment.GetEnvironmentVariable("AZURE_TENANT_ID"));
            Console.WriteLine("AZURE_CLIENT_SECRET: " + Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET"));


            // Replace with your Key Vault URL and secret info you want to read, create or update.

            string keyVaultName = "https://markm-keys.vault.azure.net/";
            string secretName = "UberPassword";
            string secretValue = "UberCulioDemo";


            string secr = ReadSecret(keyVaultName, secretName).GetAwaiter().GetResult();
            Console.WriteLine("---------------------------- Read Secret Values ---------------------------- ");
            Console.WriteLine("Current Secret Value: " + secr);
            string secw = WriteSecret(keyVaultName, secretName, secretValue).GetAwaiter().GetResult();
            //Console.WriteLine("---------------------------- Write Secret Values ---------------------------- ");
            //Console.WriteLine("old secret value: " + secw);
            string secr2 = ReadSecret(keyVaultName, secretName).GetAwaiter().GetResult();
            Console.WriteLine("---------------------------- Read Secret Values ---------------------------- ");
            Console.WriteLine("new secret value: " + secr2);

            Console.WriteLine("------------------------- Export All Secret Values ------------------------- ");

            // Export all secrets
            var allSecrets = await ExportAllSecrets(keyVaultName); 
            foreach (var kvp in allSecrets) 
            { 
                Console.WriteLine($"{kvp.Key} = {kvp.Value}"); 
            }
        }
    }
}
