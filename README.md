[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/vaultserver?branch=master&svg=true)](https://ci.appveyor.com/project/pldmgg/vaultserver/branch/master)


# VaultServer
Create, configure, and interact with [Hashicorp Vault Server](https://www.vaultproject.io/) to help manage secrets on your domain.

Compatible with Windows PowerShell 5.1 and PowerShell Core 6.X (on Windows).

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the VaultServer folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module VaultServer

# Import the module.
    Import-Module VaultServer    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module VaultServer

# Get help
    Get-Help <VaultServer Function> -Full
    Get-Help about_VaultServer
```

## Examples

### Scenario 1: Configure Your Vault Server for LDAP (Active Directory) Authentication

```powershell
PS C:\Users\zeroadmin> $ConfigureVaultLDAPSplatParams = @{
    VaultServerNetworkLocation      = $VaultServerFQDN
    VaultServerPort                 = 8200
    VaultAuthToken                  = $VaultAuthToken
    LDAPServerHostNameOrIP          = "ZeroDC01.zero.lab"
    LDAPServicePort                 = 636
    LDAPBindCredentials             = $LDAPBindCredentials
    BindUserDN                      = "cn=vault,ou=OrgUsers,dc=zero,dc=lab"
    LDAPUserOUDN                    = "ou=OrgUsers,dc=zero,dc=lab"
    LDAPGroupOUDN                   = "ou=Groups,dc=zero,dc=lab"
    PerformOptionalSteps            = $True
    LDAPVaultUsersSecurityGroupDN   = "cn=VaultUsers,ou=Groups,dc=zero,dc=lab"
    LDAPVaultAdminsSecurityGroupDN  = "cn=VaultAdmins,ou=Groups,dc=zero,dc=lab"
}
PS C:\Users\zeroadmin> $ConfigureVaultLDAPResult = Configure-VaultServerForLDAPAuth @ConfigureVaultLDAPSplatParams
PS C:\Users\zeroadmin> $ConfigureVaultLDAPResult


EnableAuditLog           : @{default-audit/=}
CreateCustomRootPolicy   : @{name=custom-root; rules=path "*" {
                               capabilities = ["create", "read", "update", "delete", "list", "sudo"]
                           }; request_id=6f521b56-b674-a57d-e789-ac659ca1b436; lease_id=; renewable=False; lease_duration=0; data=; wrap_info=; warnings=;
                           auth=}
CreateVaultUsersPolicy   : @{name=vaultusers; rules=path "*" {
                               capabilities = ["create", "read", "update", "list"]
                           }; request_id=46991932-7dc5-0c07-fab9-2d09bec2963d; lease_id=; renewable=False; lease_duration=0; data=; wrap_info=; warnings=;
                           auth=}
BackupRootToken          : @{request_id=25b086d0-80aa-0c37-f043-e46265c42269; lease_id=; renewable=False; lease_duration=0; data=; wrap_info=;
                           warnings=System.Object[]; auth=}
LDAPAuthEngineEnabled    : @{token/=; ldap/=; request_id=23d27d1c-cd0a-5ce9-2fc0-e684bda73b75; lease_id=; renewable=False; lease_duration=0; data=;
                           wrap_info=; warnings=; auth=}
LDAPAuthConfiguration    : @{request_id=24d40181-93af-876f-8bec-4eb09e4b3445; lease_id=; renewable=False; lease_duration=0; data=; wrap_info=; warnings=;
                           auth=}
AppliedVaultAdminsPolicy : @{request_id=12c20d41-33c3-6761-7cda-9d76082d9522; lease_id=; renewable=False; lease_duration=0; data=; wrap_info=; warnings=;
                           auth=}
AppliedVaultUsersPolicy  : @{request_id=f80c28f8-d792-e4f3-127d-ef9ee8329743; lease_id=; renewable=False; lease_duration=0; data=; wrap_info=; warnings=;
                           auth=}
```

## Notes

* PSGallery: https://www.powershellgallery.com/packages/VaultServer
* There are **many** different ways to configure a Hashicorp Vault Server. The functions contained within this PowerShell Module represent **my** preferred configurations. Your organization should update as appropriate to meet your security/policy guidelines.
