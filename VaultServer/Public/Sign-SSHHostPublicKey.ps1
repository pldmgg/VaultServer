<#
    .SYNOPSIS
        This function (via teh Vault Server REST API) asks the Vault Server to sign the Local Host's
        SSH Host Key (i.e. 'C:\ProgramData\ssh\ssh_host_rsa_key.pub', resulting in output
        'C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub').

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultSSHHostSigningUrl
        This parameter is MANDATORY.

        This parameter takes a string that represents the Vault Server REST API endpoint responsible
        for signing Host/Machine SSH Keys. The Url should be something like:
            https://vaultserver.zero.lab:8200/v1/ssh-host-signer/sign/hostrole

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Vault Authentication Token that has
        permission to request SSH Host Key Signing via the Vault Server REST API.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Sign-SSHHostPublicKey -VaultSSHHostSigningUrl $VaultSSHHostSigningUrl -VaultAuthToken $ZeroAdminToken
        
#>
function Sign-SSHHostPublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultSSHHostSigningUrl, # Should be something like "http://192.168.2.12:8200/v1/ssh-host-signer/sign/hostrole"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'
    )

    #region >> Prep

    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin" -and $env:SudoPwdPrompt) {
        if (GetElevation) {
            Write-Error "You should not be running the VaultServer Module as root! Halting!"
            $global:FunctionResult = "1"
            return
        }
        RemoveMySudoPwd
        NewCronToAddSudoPwd
        $env:SudoPwdPrompt = $False
    }
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    }

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        # Make sure sshd service is installed and running. If it is, we shouldn't need to use
        # the New-SSHD server function
        if (![bool]$(Get-Service sshd -ErrorAction SilentlyContinue)) {
            if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
                $InstallWinSSHSplatParams = @{
                    GiveWinSSHBinariesPathPriority  = $True
                    ConfigureSSHDOnLocalHost        = $True
                    DefaultShell                    = "pwsh"
                    ErrorAction                     = "SilentlyContinue"
                    ErrorVariable                   = "IWSErr"
                }

                try {
                    $InstallWinSSHResults = Install-WinSSH @InstallWinSSHSplatParams -ErrorAction Stop
                    if (!$InstallWinSSHResults) {throw "There was a problem with the Install-WinSSH function! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors for the Install-WinSSH function are as follows:"
                    Write-Error $($IWSErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                $NewSSHDServerSplatParams = @{
                    ErrorAction         = "SilentlyContinue"
                    ErrorVariable       = "SSHDErr"
                    DefaultShell        = "powershell"
                }
                
                try {
                    $NewSSHDServerResult = New-SSHDServer @NewSSHDServerSplatParams
                    if (!$NewSSHDServerResult) {throw "There was a problem with the New-SSHDServer function! Halting!"}
                }
                catch {
                    Write-Error $_
                    Write-Host "Errors for the New-SSHDServer function are as follows:"
                    Write-Error $($SSHDErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if (Test-Path "$env:ProgramData\ssh") {
            $sshdir = "$env:ProgramData\ssh"
        }
        elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64") {
            $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        }
        if (!$sshdir) {
            Write-Error "Unable to find ssh directory at '$env:ProgramData\ssh' or '$env:ProgramFiles\OpenSSH-Win64'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $PathToSSHHostPublicKeyFile = "$sshdir\ssh_host_rsa_key.pub"
        $sshdConfigPath = "$sshdir\sshd_config"

        if (!$(Test-Path $PathToSSHHostPublicKeyFile)) {
            Write-Error "Unable to find the SSH RSA Host Key for $env:ComputerName at path '$PathToSSHHostPublicKeyFile'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $SignedPubKeyCertFilePath = $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"
    }
    elseif ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        $sshdir = "/etc/ssh"
        $sshdConfigPath = "$sshdir/sshd_config"
        $PathToSSHHostPublicKeyFile = "$sshdir/ssh_host_rsa_key.pub"

        if (!$(Test-Path $PathToSSHHostPublicKeyFile)) {
            Write-Error "Unable to find the SSH RSA Host Key for $env:HostName at path '$PathToSSHHostPublicKeyFile'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $SignedPubKeyCertFilePath = $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"
    }

    # Make sure $VaultSSHHostSigningUrl is a valid Url
    try {
        $UriObject = [uri]$VaultSSHHostSigningUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultSSHHostSigningUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultSSHHostSigningUrl ends in '/', remove it
    if ($VaultSSHHostSigningUrl[-1] -eq "/") {
        $VaultSSHHostSigningUrl = $VaultSSHHostSigningUrl.Substring(0,$VaultSSHHostSigningUrl.Length-1)
    }

    #endregion >> Prep

    #region >> Main

    # HTTP API Request
    # The below removes 'comment' text from the Host Public key because sometimes it can cause problems
    # with the below json
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        $PubKeyContent = $($(Get-Content $PathToSSHHostPublicKeyFile) -split "[\s]")[0..1] -join " "
    }
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        $SBAsString = @(
            'Write-Host "`nOutputStartsBelow`n"'
            'try {'
            '    $PubKeyContent = $($(Get-Content "{0}") -split "[\s]")[0..1] -join " "' -f $PathToSSHHostPublicKeyFile
            '    $PubKeyContent | ConvertTo-Json -Depth 3'
            '}'
            'catch {'
            '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
            '}'
        )
        $SBAsString = $SBAsString -join "`n"
        $SSHHostPubKeyPrep = SudoPwsh -CmdString $SBAsString

        if ($SSHHostPubKeyPrep.Output -match "ErrorMsg") {
            throw $SSHHostPubKeyPrep.Output[-1]
        }
        if ($SSHHostPubKeyPrep.OutputType -eq "Error") {
            if ($SSHHostPubKeyPrep.Output -match "ErrorMsg") {
                throw $SSHHostPubKeyPrep.Output[-1]
            }
            else {
                throw $SSHHostPubKeyPrep.Output
            }
        }

        $PubKeyContent = $SSHHostPubKeyPrep.Output
    }

    $jsonRequest = @"
{
    "cert_type": "host",
    "extension": {
      "permit-pty": "",
      "permit-agent-forwarding": ""
    },
    "public_key": "$PubKeyContent"
  }
"@
    $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json | ConvertTo-Json -Compress

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParams = @{
        Uri         = $VaultSSHHostSigningUrl
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }

    $SignedSSHClientPubKeyCertResponse = Invoke-WebRequest @IWRSplatParams
    $SignedPubKeyContent = $($SignedSSHClientPubKeyCertResponse.Content | ConvertFrom-Json).data.signed_key.Trim()

    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        Set-Content -Path $SignedPubKeyCertFilePath -Value $SignedPubKeyContent
    }
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        try {
            $SBAsString = @(
                'Write-Host "`nOutputStartsBelow`n"'
                'try {'
                $("    Set-Content -Path '{0}' -Value @'{1}'@" -f $SignedPubKeyCertFilePath,$("`n" + $($SignedPubKeyContent -join "`n") + "`n"))
                '    "Done" | ConvertTo-Json -Depth 3'
                '}'
                'catch {'
                '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                '}'
            )
            $SBAsString = $SBAsString -join "`n"
            $SignedSSHHostPubKeyPrep = SudoPwsh -CmdString $SBAsString

            if ($SignedSSHHostPubKeyPrep.Output -match "ErrorMsg") {
                throw $SignedSSHHostPubKeyPrep.Output[-1]
            }
            if ($SignedSSHHostPubKeyPrep.OutputType -eq "Error") {
                if ($SignedSSHHostPubKeyPrep.Output -match "ErrorMsg") {
                    throw $SignedSSHHostPubKeyPrep.Output[-1]
                }
                else {
                    throw $SignedSSHHostPubKeyPrep.Output
                }
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Make sure permissions on "$sshdir/ssh_host_rsa_key-cert.pub" are set properly
    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
        $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $args[0]
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        } -ArgumentList $SignedPubKeyCertFilePath
    }
    elseif ($PSVersionTable.PSEdition -eq "Desktop") {
        $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path $SignedPubKeyCertFilePath
        $null = $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $null = $SecurityDescriptor | Clear-NTFSAccess
        $null = $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $null = $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $null = $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\Authenticated Users" -AccessRights "ReadAndExecute, Synchronize" -AppliesTo ThisFolderSubfoldersAndFiles
        $null = $SecurityDescriptor | Set-NTFSSecurityDescriptor
    }
    elseif ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        try {
            $SBAsString = @(
                'Write-Host "`nOutputStartsBelow`n"'
                'try {'
                "    chmod 644 '$SignedPubKeyCertFilePath'"
                '    "Done" | ConvertTo-Json -Depth 3'
                '}'
                'catch {'
                '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                '}'
            )
            $SBAsString = $SBAsString -join "`n"
            $SignedSSHHostPermsPrep = SudoPwsh -CmdString $SBAsString

            if ($SignedSSHHostPermsPrep.Output -match "ErrorMsg") {
                throw $SignedSSHHostPermsPrep.Output[-1]
            }
            if ($SignedSSHHostPermsPrep.OutputType -eq "Error") {
                if ($SignedSSHHostPermsPrep.Output -match "ErrorMsg") {
                    throw $SignedSSHHostPermsPrep.Output[-1]
                }
                else {
                    throw $SignedSSHHostPermsPrep.Output
                }
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Update sshd_config
    if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
        [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
    }
    if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
        try {
            $SBAsString = @(
                'Write-Host "`nOutputStartsBelow`n"'
                'try {'
                "    Get-Content '$sshdConfigPath' | ConvertTo-Json -Depth 3"
                '}'
                'catch {'
                '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                '}'
            )
            $SBAsString = $SBAsString -join "`n"
            $GetSSHDContentPrep = SudoPwsh -CmdString $SBAsString

            if ($GetSSHDContentPrep.Output -match "ErrorMsg") {
                throw $GetSSHDContentPrep.Output[-1]
            }
            if ($GetSSHDContentPrep.OutputType -eq "Error") {
                if ($GetSSHDContentPrep.Output -match "ErrorMsg") {
                    throw $GetSSHDContentPrep.Output[-1]
                }
                else {
                    throw $GetSSHDContentPrep.Output
                }
            }

            [System.Collections.ArrayList]$sshdContent = $GetSSHDContentPrep.Output.value
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Determine if sshd_config already has the 'HostCertificate' option active
    $ExistingHostCertificateOption = $sshdContent -match "HostCertificate" | Where-Object {$_ -notmatch "#"}
    $HostCertificatePath =  $PathToSSHHostPublicKeyFile -replace "\.pub","-cert.pub"
    $HostCertificateOptionLine = "HostCertificate $HostCertificatePathWithForwardSlashes"
    
    if (!$ExistingHostCertificateOption) {
        $LineNumberToInsertOn = $sshdContent.IndexOf($($sshdContent -match "HostKey .*ssh_host_rsa_key$")) + 1
        [System.Collections.ArrayList]$sshdContent.Insert($LineNumberToInsertOn, $HostCertificateOptionLine)

        if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
            try {
                $SBAsString = @(
                    'Write-Host "`nOutputStartsBelow`n"'
                    'try {'
                    $("    Set-Content -Path '{0}' -Value @'{1}'@" -f $sshdConfigPath,$("`n" + $($sshdContent -join "`n") + "`n"))
                    "    Get-Content '$sshdConfigPath' | ConvertTo-Json -Depth 3"
                    '}'
                    'catch {'
                    '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                    '}'
                )
                $SBAsString = $SBAsString -join "`n"
                $GetSSHDContentPrep = SudoPwsh -CmdString $SBAsString

                if ($GetSSHDContentPrep.Output -match "ErrorMsg") {
                    throw $GetSSHDContentPrep.Output[-1]
                }
                if ($GetSSHDContentPrep.OutputType -eq "Error") {
                    if ($GetSSHDContentPrep.Output -match "ErrorMsg") {
                        throw $GetSSHDContentPrep.Output[-1]
                    }
                    else {
                        throw $GetSSHDContentPrep.Output
                    }
                }

                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = $GetSSHDContentPrep.Output.value
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            Set-Content -Path $sshdConfigPath -Value $sshdContent
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
    }
    else {
        if ($ExistingHostCertificateOption -ne $HostCertificateOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingHostCertificateOption),"$HostCertificateOptionLine"

            if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
                try {
                    $SBAsString = @(
                        'Write-Host "`nOutputStartsBelow`n"'
                        'try {'
                        $("    Set-Content -Path '{0}' -Value @'{1}'@" -f $sshdConfigPath,$("`n" + $($UpdatedSSHDConfig -join "`n") + "`n"))
                        "    Get-Content '$sshdConfigPath' | ConvertTo-Json -Depth 3"
                        '}'
                        'catch {'
                        '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                        '}'
                    )
                    $SBAsString = $SBAsString -join "`n"
                    $GetSSHDContentPrep = SudoPwsh -CmdString $SBAsString
        
                    if ($GetSSHDContentPrep.Output -match "ErrorMsg") {
                        throw $GetSSHDContentPrep.Output[-1]
                    }
                    if ($GetSSHDContentPrep.OutputType -eq "Error") {
                        if ($GetSSHDContentPrep.Output -match "ErrorMsg") {
                            throw $GetSSHDContentPrep.Output[-1]
                        }
                        else {
                            throw $GetSSHDContentPrep.Output
                        }
                    }
        
                    $SSHDConfigContentChanged = $True
                    [System.Collections.ArrayList]$sshdContent = $GetSSHDContentPrep.Output.value
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
                Set-Content -Path $sshdConfigPath -Value $UpdatedSSHDConfig
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
        }
        else {
            Write-Warning "The specified 'HostCertificate' option is already active in the the sshd_config file. No changes made."
        }
    }

    [pscustomobject]@{
        SignedPubKeyCertFile        = $SignedPubKeyCertFilePath
        SSHDConfigContentChanged    = if ($SSHDConfigContentChanged) {$True} else {$False}
        SSHDContentThatWasAdded     = if ($SSHDConfigContentChanged) {$HostCertificateOptionLine}
    }

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUAfabax4RO/6Ihbyh/klf+AL
# JASgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPIuEdgxKuRUXoV3
# tfgM1fJVKmmrMA0GCSqGSIb3DQEBAQUABIIBAEExtnWEZbfGGmtzrxl4fJlzRrRt
# b3pdwSOd5UGfULxiaUbCMiNwR8oKcG5HTpqg4WpV6+RFLw8D0xyT9/tB6BVR0TnW
# kWmImbQQOHWer1/TVf6dUwKIrBbXTAO4cT5VWnIEB8Tt5iD07uEKPMQ3Maxue2Eb
# vrF+rC6IZ9p93CSLkBTW8ukNgga5x71v8L58FBMh2lDdLE08bmCyXtkFTc3LS1a9
# mZ/iCVrXnJKR7HDa98gmwvE8lliA7SFE3+kycTZPmOqempmYs0ohl3A2NJrgY8n6
# hKCLOaAByRIgKwA7PkCtmWRD61feDnVIfVMJeVl5xcUe+GcX3DQ1fx6lYUk=
# SIG # End signature block
