#
# Module manifest for module 'VaultServer'
#
# Generated by: pldmgg
#
# Generated on: 7/18/2018
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'VaultServer.psm1'

# Version number of this module.
ModuleVersion = '1.0.0'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'e57ce926-8241-4b27-b946-7cd10f3e0085'

# Author of this module
Author = 'pldmgg'

# Company or vendor of this module
CompanyName = 'pldmgg'

# Copyright statement for this module
Copyright = '(c) 2018 pldmgg. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Create, configure, and interact with Hashicorp Vault Server to help manage secrets on your domain. GitHub: https://github.com/pldmgg/VaultServer'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @('ProgramManagement','NTFSSecurity')

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Add-CAPubKeyToSSHAndSSHDConfig','Add-PublicKeyToRemoteHost','Check-Cert',
                    'Configure-VaultServerForLDAPAuth','Configure-VaultServerForSSHManagement','Generate-AuthorizedPrincipalsFile',
                    'Generate-SSHUserDirFileInfo','Get-LDAPCert','Get-NativePath','Get-SSHClientAuthSanity',
                    'Get-SSHFileInfo','Get-VaultAccessorLookup','Get-VaultLogin','Get-VaultTokenAccessors',
                    'Get-VaultTokens','Manage-StoredCredentials','New-SSHCredentials','New-SSHKey',
                    'Revoke-VaultToken','Sign-SSHHostPublicKey','Sign-SSHUserPublicKey','Validate-SSHPrivateKey'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = 'VaultServer.psm1', 'VaultServer.psd1'

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        LicenseUri = 'http://www.apache.org/licenses/LICENSE-2.0'

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'http://pldmgg.github.io'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}
