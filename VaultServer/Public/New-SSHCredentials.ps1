<#
    .SYNOPSIS
        This function creates a new SSH User/Client key pair and has the Vault Server sign the Public Key,
        returning a '-cert.pub' file that can be used for Public Key Certificate SSH Authentication.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents a Uri referencing the location of the Vault Server
        on your network. Example: "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER DomainCredentialsWithAccessToVault
        This parameter is OPTIONAL, however, either -DomainCredentialsWithAccessToVault or -VaultAuthToken are REQUIRED.

        This parameter takes a PSCredential. Example:
        $Creds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Please enter the password for 'zero\zeroadmin'" -AsSecureString))

    .PARAMETER AuthorizedPrincipalString
        This parameter is OPTIONAL.

        This parameter takes a a string that represents the "Authorized Principal" that will be addedd to the user
        ssh certificate. This user account should be listed in the 'authorized_principals' file on the Remote Host(s) you
        would like to ssh to.

        The value for thhis parameter should be in format '<DomainUser>@<FullDomain>' or '<LocalUser>@<RemoteHostName>'

        If you do NOT use this parameter, then the user account provided with the -DomainCredentialsWithAccessToVault parameter
        will be used.

    .PARAMETER VaultAuthToken
        This parameter is OPTIONAL, however, either -DomainCredentialsWithAccessToVault or -VaultAuthToken are REQUIRED.

        This parameter takes a string that represents a Token for a Vault User that has (root) permission to
        lookup Tokens using the Vault Server REST API.

    .PARAMETER NewSSHKeyName
        This parameter is MANDATORY.

        This parameter takes a string that represents the file name that you would like to give to the new
        SSH User/Client Keys.

    .PARAMETER NewSSHKeyPurpose
        This parameter is OPTIONAL.

        This parameter takes a string that represents a very brief description of what the new SSH Keys
        will be used for. This description will be added to the Comment section when the new keys are
        created.

    .PARAMETER NewSSHKeyPwd
        This parameter is OPTIONAL.

        This parameter takes a SecureString that represents the password used to protect the new
        Private Key file that is created.

    .PARAMETER BlankSSHPrivateKeyPwd
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to ensure that the newly created Private Key is NOT password
        protected.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL, but recommended.

        This parameter is a switch. If used, the new SSH Key Pair will be added to the ssh-agent service.

    .PARAMETER RemovePrivateKey
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter is a switch. If used, the newly created Private Key will be added to the ssh-agent
        and deleted from the filesystem.

    .PARAMETER SSHAgentExpiry
        This parameter is OPTIONAL. This parameter should only be used in conjunction with the
        -AddtoSSHAgent switch.

        This parameter takes an integer that specifies the number of seconds that the ssh key identity will
        remain in the ssh-agent - at which point it will expire and be removed from the ssh-agent.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $NewSSHCredentialsSplatParams = @{
            VaultServerBaseUri      = $VaultServerBaseUri
            VaultAuthToken          = $VaultAuthToken
            NewSSHKeyName           = $NewSSHKeyName
            AddToSSHAgent           = $True
        }
        PS C:\Users\zeroadmin> $NewSSHCredsResult = New-SSHCredentials @NewSSHCredentialsSplatParams
        
#>
function New-SSHCredentials {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAccessToVault,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("[a-zA-Z0-9]+@[a-zA-Z0-9]+")]
        [string[]]$AuthorizedPrincipalString,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken,

        [Parameter(Mandatory=$True)]
        [string]$NewSSHKeyName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^\w*$")] # No spaces allowed
        [string]$NewSSHKeyPurpose,

        [Parameter(Mandatory=$False)]
        [System.Security.SecureString]$NewSSHKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$BlankSSHPrivateKeyPwd,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent,

        [Parameter(Mandatory=$False)]
        [switch]$RemovePrivateKey,

        [Parameter(Mandatory=$False)]
        [int]$SSHAgentExpiry
    )

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the $($MyInvocation.MyCommand.Name) function as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

        if (!$(GetElevation)) {
            Write-Error "The $($MyInvocation.MyCommand.Name) function must be run from an elevated PowerShell session! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                     = $VaultServerBaseUri
            DomainCredentialsWithAccessToVault     = $DomainCredentialsWithAccessToVault
            ErrorAction                            = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (!$DomainCredentialsWithAccessToVault -and !$AuthorizedPrincipalString) {
        $ErrMsg = "Either the -DomainCredentialsWithAccessToVault parameter or -AuthorizedPrincipalString parameter is required!`n" +
        "The value for -DomainCredentialsWithAccessToVault should be in format '<DomainRoot>\<DomainUser>'`n" +
        "The value for -AuthorizedPrincipalString should be in format '<DomainUser>@<FullDomain>' or '<LocalUser>@<RemoteHostName>'"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Generate an SSH key pair for zeroadmin
    $UserSSHDir = Join-Path $HOME .ssh
    if (!$(Test-Path $UserSSHDir)) {
        New-Item -ItemType Directory -Path $UserSSHDir
    }

    Push-Location $UserSSHDir

    $NewSSHKeySplatParams = @{
        NewSSHKeyName       = $NewSSHKeyName
        ErrorAction         = "Stop"
    }
    if ($NewSSHKeyPurpose) {
        $NewSSHKeySplatParams.Add("NewSSHKeyPurpose",$NewSSHKeyPurpose)
    }
    
    if ($NewSSHKeyPwd) {
        $KeyPwd = $NewSSHKeyPwd
    }
    if (!$BlankSSHPrivateKeyPwd -and !$NewSSHKeyPwd) {
        #$KeyPwd = Read-Host -Prompt "Please enter a password to protect the new SSH Private Key $NewSSHKeyName" -AsSecureString
        $BlankSSHPrivateKeyPwd = $True
    }
    if ($KeyPwd) {
        $NewSSHKeySplatParams.Add("NewSSHKeyPwd",$KeyPwd)
    }
    
    try {
        $NewSSHKeyResult = New-SSHKey @NewSSHKeySplatParams
        if (!$NewSSHKeyResult) {throw "There was a problem with the New-SSHKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Have Vault sign the User's New public key
    if (!$AuthorizedPrincipalString) {
        $AuthorizedPrincipalUserPrep = $DomainCredentialsWithAccessToVault.UserName -split "\\"
        $AuthorizedPrincipalString = $AuthorizedPrincipalUserPrep[-1] + "@" + $AuthorizedPrincipalUserPrep[0]
    }
    <#
    else {
        #$AuthorizedPrincipalString = $($(whoami) -split "\\")[-1] + "@" + $($(whoami) -split "\\")[0]
        $UserName = whoami
        if ($UserName -match '\\') {
            $DomainNameShort = $($UserName -split '\\')[0]
            $UserNameShort = $($UserName -split '\\')[-1]
            $AuthorizedPrincipalString = $UserNameShort + "@" + $DomainNameShort
        }
        else {
            $UserNameShort = $UserName
            if ($env:HOSTNAME) {
                $ActualHostName = if ($env:HOSTNAME -match '\.') {$($env:HOSTNAME -split '\.')[0]} else {$env:HOSTNAME}
            }
            else {
                $ActualHostName = if ($env:ComputerName -match '\.') {$($env:ComputerName -split '\.')[0]} else {$env:ComputerName}
            }
            $AuthorizedPrincipalString = $UserNameShort + "@" + $ActualHostName
        }
    }
    #>

    $SignSSHUserPubKeySplatParams = @{
        VaultSSHClientSigningUrl        = "$VaultServerBaseUri/ssh-client-signer/sign/clientrole"
        VaultAuthToken                  = $VaultAuthToken
        AuthorizedUserPrincipals        = @($AuthorizedPrincipalString)
        PathToSSHUserPublicKeyFile      = $NewSSHKeyResult.PublicKeyFilePath
        PathToSSHUserPrivateKeyFile     = $NewSSHKeyResult.PrivateKeyFilePath
        ErrorAction                     = "Stop"
    }
    if ($AddToSSHAgent) {
        $SignSSHUserPubKeySplatParams.Add("AddToSSHAgent",$True)
    }
    if ($SSHAgentExpiry) {
        $SignSSHUserPubKeySplatParams.Add("SSHAgentExpiry",$SSHAgentExpiry)
    }

    try {
        $SignSSHUserPublicKeyResult = Sign-SSHUserPublicKey @SignSSHUserPubKeySplatParams
        if (!$SignSSHUserPublicKeyResult) {throw "There was a problem with the Sign-SSHUserPublicKey function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($RemovePrivateKey -and $SignSSHUserPublicKeyResult.AddedToSSHAgent) {
        Remove-Item $NewSSHKeyResult.PrivateKeyFilePath -Force
    }

    # Next, pull the Vault Host Signing CA Public Key and Vault Client (User) Signing CA Public Key into the necessary config files
    # NOTE: The Add-CAPubKeyToSSHAndSSHDConfig function will NOT do anything if it doesn't need to
    $AddCAPubKeyToSSHAndSSHDConfigSplatParams = @{
        PublicKeyOfCAUsedToSignUserKeysVaultUrl     = "$VaultServerBaseUri/ssh-client-signer/public_key"
        PublicKeyOfCAUsedToSignHostKeysVaultUrl     = "$VaultServerBaseUri/ssh-host-signer/public_key"
        AuthorizedUserPrincipals                    = @($AuthorizedPrincipalString)
        ErrorAction                                 = "Stop"
    }

    try {
        $AddCAPubKeyResult = Add-CAPubKeyToSSHAndSSHDConfig @AddCAPubKeyToSSHAndSSHDConfigSplatParams
    }
    catch {
        Write-Warning "There was a problem with the Add-CAPubKeyToSSHAndSSHDConfig function! The problem is as follows:"
        Write-Warning "$($_ | Out-String)"
        Write-Warning "SSH Cert Authentication may still work..."
    }

    # Finally, figure out the most efficient ssh command to use to remote into the remote host.
    Write-Host "Determining the most efficient ssh command to use with your new credentials..."
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        Write-Warning "Please IGNORE any password prompts that may appear in STDOUT."
    }
    $Output = Get-SSHClientAuthSanity -SSHKeyFilePath $NewSSHKeyResult.PublicKeyFilePath -AuthMethod PublicKeyCertificate
    if (Test-Path $NewSSHKeyResult.PrivateKeyFilePath) {
        $Output | Add-Member -Type NoteProperty -Name PrivateKeyPath -Value $NewSSHKeyResult.PrivateKeyFilePath
    }
    if (Test-Path $NewSSHKeyResult.PublicKeyFilePath) {
        $Output | Add-Member -Type NoteProperty -Name PublicKeyPath -Value $NewSSHKeyResult.PublicKeyFilePath
    }
    if (Test-Path $SignSSHUserPublicKeyResult.SignedCertFile.FullName) {
        $Output | Add-Member -Type NoteProperty -Name PublicCertPath -Value $SignSSHUserPublicKeyResult.SignedCertFile.FullName
    }

    $Output

    Pop-Location

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUStv1JtqkthbwT6XKz7tKjyHI
# GL6gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFP0nGIQTiO/aBNYt
# vYic026d+POJMA0GCSqGSIb3DQEBAQUABIIBAHE7Cozdao5yWXv8K9NVCDGWJs/r
# eFDA1KyFgvQz5pUShCIbsWVoRbTYc1b29iOX8n8S0cYVnLNWLmF4eQ0VY4Rl4nog
# FKB+T5EfYTxM6gCOAIzHYGsfAb+HvXfDLduxfzBB8bj55JeJl9q4T4W+XUxuu8ZZ
# sigEwUq6OHvflGvG/T0hihQcqTCwzM+vOyn+mWND9TpsGU1dTg9ng4X+lol2P4qh
# 3LKAoKlDzl9ErbwziDkJx9HXmuLBSSlSW+3vpEluxM55t7pzhmHzp+Qm9levtZFo
# dgpSWKGPMXN2ynOR/X0VFCAIQiZe74cjWCf7DzL/y8/ECPmkgZUQAYrlRfc=
# SIG # End signature block
