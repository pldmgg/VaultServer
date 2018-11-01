<#
    .SYNOPSIS
        This function gets the TLS certificate used by the LDAP server on the specified Port.

        The function outputs a PSCustomObject with the following properties:
            - LDAPEndpointCertificateInfo
            - RootCACertificateInfo
            - CertChainInfo
        
        The 'LDAPEndpointCertificateInfo' property is itself a PSCustomObject with teh following content:
            X509CertFormat      = $X509Cert2Obj
            PemFormat           = $PublicCertInPemFormat

        The 'RootCACertificateInfo' property is itself a PSCustomObject with teh following content:
            X509CertFormat      = $RootCAX509Cert2Obj
            PemFormat           = $RootCACertInPemFormat

        The 'CertChainInfo' property is itself a PSCustomObject with the following content:
            X509ChainFormat     = $CertificateChain
            PemFormat           = $CertChainInPemFormat
        ...where $CertificateChain is a System.Security.Cryptography.X509Certificates.X509Chain object.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER LDAPServerHostNameOrIP
        This parameter is MANDATORY.

        This parameter takes a string that represents either the IP Address or DNS-Resolvable Name of the
        LDAP Server. If you're in a Windows environment, this is a Domain Controller's network location.

    .PARAMETER Port
        This parameter is MANDATORY.

        This parameter takes an integer that represents a port number that the LDAP Server is using that
        provides a TLS Certificate. Valid values are: 389, 636, 3268, 3269

    .PARAMETER AllowOpenSSLInstall
        This parameter is OPTIONAL.

        This parameter is a switch. If used, if openssl is necessary and not available or not at least version
        1.1.1, it will be installed/upgraded.
    
    .PARAMETER UseOpenSSL
        This parameter is OPTIONAL.

        This parameter is a switch. If you would like to use openssl in situations where you don't necessarily
        need to (i.e. when the LDAP -Port number is 636 or 3269), use this switch.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Fix-SSHPermissions
        
#>
function Get-LDAPCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$LDAPServerHostNameOrIP,

        [Parameter(Mandatory=$True)]
        [ValidateSet(389,636,3268,3269)]
        [int]$Port,

        [Parameter(Mandatory=$False)]
        [switch]$AllowOpenSSLInstall,

        [Parameter(Mandatory=$False)]
        [switch]$UseOpenSSL
    )

    #region >> Pre-Run Check

    try {
        $LDAPServerNetworkInfo = ResolveHost -HostNameOrIP $LDAPServerHostNameOrIP
        if (!$LDAPServerNetworkInfo) {throw "Unable to resolve $LDAPServerHostNameOrIP! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Pre-Run Check
    

    #region >> Main Body
    
    if ($Port -eq 389 -or $Port -eq 3268 -or $UseOpenSSL) {    
        # Check is openssl is already available
        if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            # Check to make sure the version is at least 1.1.1 (September 2018)
            $OpenSSLVersionPrep = $($(openssl version) | Select-String -Pattern "OpenSSL [0-9]").Line
            $OpenSSLVersionPrep = $($OpenSSLVersionPrep | Select-String -Pattern "[0-9]+\.[0-9]+\.[0-9]+").Matches.Value.Trim()
            $OpenSSLVersion = [version]$OpenSSLVersionPrep

            if ($OpenSSLVersion -lt [version]"1.1.1" -and !$AllowOpenSSLInstall) {
                $ErrMsg = "The version of openssl installed on this system (i.e. $($OpenSSLVersion.ToString()) is less than the required version of 1.1.1! " +
                "Please use the -AllowOpenSSLInstall switch and try again. Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }

            if ($OpenSSLVersion -lt [version]"1.1.1") {
                $InstallOpenSSL = $True
            }
        }
        else {
            if (!$AllowOpenSSLInstall) {
                $ErrMsg = "The $($MyInvocation.MyCommand.Name) function requires openssl if the LDAP port is 389 or 3268, or if you used the -UseOpenSSL switch. " +
                "Since openssl cannot be found on this system, you must use the -AllowOpenSSLInstall switch to allow for openssl installation! Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }
            else {
                $InstallOpenSSL = $True
            }
        }
    }

    if ($InstallOpenSSL) {
        if ($PSVersionTable.Platform -eq "Unix" -or $PSVersionTable.OS -match "Darwin") {
            if (!$(Get-Command tar -ErrorAction SilentlyContinue)) {
                $MissingCmd = "tar"
            }
            if ($MissingCmd) {
                $ErrMsg = "The $($MyInvocation.MyCommand.Name) function requires openssl version 1.1.1, but version $($OpenSSLVersion.ToString()) is installed. " +
                "Installing version 1.1.1 requires building from source, which requies '$MissingCmd', which cannot be found on $env:HOSTNAME! Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }

            if ($(Get-Command apt -ErrorAction SilentlyContinue)) {
                try {
                    $SBAsString = @(
                        'try {'
                        '    apt-get update'
                        '    apt-get -y install build-essential checkinstall zlib1g-dev libtemplate-perl'
                        '    if ($LASTEXITCODE -ne 0) {throw "apt failed!"}'
                        '    Write-Host "`nOutputStartsBelow`n"'
                        '    "Done" | ConvertTo-Json -Depth 3'
                        '}'
                        'catch {'
                        '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                        '}'
                    )
                    $SBAsString = $SBAsString -join "`n"
                    $AptResultPrep = SudoPwsh -CmdString $SBAsString

                    if ($AptResultPrep.Output -match "ErrorMsg") {
                        throw $AptResultPrep.Output[-1]
                    }
                    if ($AptResultPrep.OutputType -eq "Error") {
                        if ($AptResultPrep.Output -match "ErrorMsg") {
                            throw $AptResultPrep.Output[-1]
                        }
                        else {
                            throw $AptResultPrep.Output
                        }
                    }
                    $AptResult = $AptResultPrep.Output
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
            elseif ($(Get-Command yum -ErrorAction SilentlyContinue)) {
                try {
                    $SBAsString = @(
                        'try {'
                        "    yum -y group install 'Development Tools'"
                        '    if ($LASTEXITCODE -ne 0) {throw "yum failed!"}'
                        '    yum -y install perl-core libtemplate-perl zlib-devel'
                        '    if ($LASTEXITCODE -ne 0) {throw "yum failed!"}'
                        '    Write-Host "`nOutputStartsBelow`n"'
                        '    "Done" | ConvertTo-Json -Depth 3'
                        '}'
                        'catch {'
                        '    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3'
                        '}'
                    )
                    $SBAsString = $SBAsString -join "`n"
                    $YumResultPrep = SudoPwsh -CmdString $SBAsString

                    if ($YumResultPrep.Output -match "ErrorMsg") {
                        throw $YumResultPrep.Output[-1]
                    }
                    if ($YumResultPrep.OutputType -eq "Error") {
                        if ($YumResultPrep.Output -match "ErrorMsg") {
                            throw $YumResultPrep.Output[-1]
                        }
                        else {
                            throw $YumResultPrep.Output
                        }
                    }
                    $YumResult = $YumResultPrep.Output
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }

            $IWRResult = Invoke-WebRequest -Uri "https://github.com/openssl/openssl/releases"
            $DLUri = "https://github.com" + $($IWRResult.Links.href -match "\.tar\.gz")[0]
            $OutFileName = $DLUri | Split-Path -Leaf
            $OutFilePath = Join-Path $HOME $OutFileName
            $null = Invoke-WebRequest -Uri $DLUri -OutFile $OutFilePath
            Push-Location $HOME
            $null = tar -xzvf $OutFileName
            $ExpandedArchiveDir = $(Get-ChildItem -Directory | Sort-Object -Property CreationTime)[0].FullName
            Push-Location $ExpandedArchiveDir
            $null =  ./config
            $null = make
            $null = make test
            try {
                [System.Collections.Generic.List[string]]$SBAsString = @(
                    'try {'
                    "    Push-Location '$HOME/$ExpandedArchiveDir'"
                    '    make install'
                    '    if ($LASTEXITCODE -ne 0) {throw "`"make install failed!`""}'
                )
                if (Get-Command yum -ErrorAction SilentlyContinue) {
                    $null = $SBAsString.Add('    cp /usr/local/lib64/libssl.* /usr/lib64/')
                    $null = $SBAsString.Add('    cp /usr/local/lib64/libcrypto.* /usr/lib64/')
                }
                if (Get-Command apt -ErrorAction SilentlyContinue) {
                    $null = $SBAsString.Add('    bash -c "export LD_LIBRARY_PATH=/usr/local/lib"')
                    $null = $SBAsString.Add("    `$env:LD_LIBRARY_PATH = '/usr/local/lib'")
                }
                $null = $SBAsString.Add('    Write-Host "`nOutputStartsBelow`n"')
                $null = $SBAsString.Add('    "Done" | ConvertTo-Json -Depth 3')
                $null = $SBAsString.Add('}')
                $null = $SBAsString.Add('catch {')
                $null = $SBAsString.Add('    @("ErrorMsg",$_.Exception.Message) | ConvertTo-Json -Depth 3')
                $null = $SBAsString.Add('}')
                $SBAsString = $SBAsString -join "`n"
                $MakeResultPrep = SudoPwsh -CmdString $SBAsString
                
                if ($MakeResultPrep.Output -match "ErrorMsg") {
                    throw $MakeResultPrep.Output[-1]
                }
                if ($MakeResultPrep.OutputType -eq "Error") {
                    if ($MakeResultPrep.Output -match "ErrorMsg") {
                        throw $MakeResultPrep.Output[-1]
                    }
                    else {
                        throw $MakeResultPrep.Output
                    }
                }
                $MakeResult = $MakeResultPrep.Output
                Pop-Location
                Pop-Location

                bash -c "export LD_LIBRARY_PATH=/usr/local/lib"
                $env:LD_LIBRARY_PATH = '/usr/local/lib'
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                Pop-Location
                Pop-Location
                return
            }

            if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
                Write-Error "Problem finding setting openssl after install! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$PSVersionTable.Platform -or $PSVersionTable.Platform -eq "Win32NT") {
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            $OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
            $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl
            $LatestOpenSSLWinBinaryLinkObj = $($IWRResult.Links | Where-Object {$_.innerText -match "OpenSSL Binaries" -and $_.href -match "\.zip"})[0]
            $LatestOpenSSLWinBinaryUrl = $LatestOpenSSLWinBinaryLinkObj.href
            $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
            $OutputFilePath = "$HOME\Downloads\$OutputFileName"
            Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

            if (!$(Test-Path "$HOME\Downloads\$OutputFileName")) {
                Write-Error "Problem downloading the latest OpenSSL Windows Binary from $LatestOpenSSLWinBinaryUrl ! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputFileItem = Get-Item $OutputFilePath
            $ExpansionDirectory = $OutputFileItem.Directory.FullName + "\" + $OutputFileItem.BaseName
            if (!$(Test-Path $ExpansionDirectory)) {
                $null = New-Item -ItemType Directory -Path $ExpansionDirectory -Force
            }
            else {
                Remove-Item "$ExpansionDirectory\*" -Recurse -Force
            }

            $null = Expand-Archive -Path "$HOME\Downloads\$OutputFileName" -DestinationPath $ExpansionDirectory -Force

            # Add $ExpansionDirectory to $env:Path
            $CurrentEnvPathArray = $env:Path -split ";"
            if ($CurrentEnvPathArray -notcontains $ExpansionDirectory) {
                # Place $ExpansionDirectory at start so latest openssl.exe get priority
                $env:Path = "$ExpansionDirectory;$env:Path"
            }

            if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
                Write-Error "Problem finding setting openssl after install! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $OpenSSLVersionPrep = $($(openssl version) | Select-String -Pattern "OpenSSL [0-9]").Line
        $OpenSSLVersionPrep = $($OpenSSLVersionPrep | Select-String -Pattern "[0-9]+\.[0-9]+\.[0-9]+").Matches.Value.Trim()
        $OpenSSLVersion = [version]$OpenSSLVersionPrep

        if ($OpenSSLVersion -lt [version]"1.1.1") {
            Write-Error "The version of openssl currently available $($OpenSSLVersion.ToString()) is less than '1.1.1'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Port -eq 389 -or $Port -eq 3268) {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
        $ProcessInfo.FileName = $(Get-Command openssl).Source
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
        #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port -starttls ldap -showcerts"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        # Sometimes openssl hangs, so, we'll give it 5 seconds before killing
        # Below $FinishedInAlottedTime returns boolean true/false
        $FinishedInAlottedTime = $Process.WaitForExit(5000)
        if (!$FinishedInAlottedTime) {
            $Process.Kill()
        }
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $OpenSSLResult = $stdout + $stderr

        # Parse the output of openssl
        $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
        $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
        $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))

        if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
            Write-Error "Unable to find Certificate in openssl output! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

        # Get $X509Cert2Obj
        $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
        $byteArray = [System.Convert]::FromBase64String($PemString)
        $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
    }

    if ($Port -eq 636 -or $Port -eq 3269) {
        if ($UseOpenSSL) {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
            $ProcessInfo.FileName = $(Get-Command openssl).Source
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
            #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "s_client -connect $($LDAPServerNetworkInfo.FQDN):$Port"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Sometimes openssl hangs, so, we'll give it 5 seconds before killing
            # Below $FinishedInAlottedTime returns boolean true/false
            $FinishedInAlottedTime = $Process.WaitForExit(5000)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $OpenSSLResult = $stdout + $stderr

            # Parse the output of openssl
            $OpenSSLResultLineBreaks = $OpenSSLResult -split "`n"
            $IndexOfBeginCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "BEGIN CERTIFICATE"))
            $IndexOfEndCert = $OpenSSLResultLineBreaks.IndexOf($($OpenSSLResultLineBreaks -match "End CERTIFICATE"))
            
            if ($IndexOfBeginCert -eq "-1" -or $IndexOfEndCert -eq "-1") {
                Write-Error "Unable to find Certificate in openssl output! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $PublicCertInPemFormat = $OpenSSLResultLineBreaks[$IndexOfBeginCert..$IndexOfEndCert]

            # Get $X509Cert2Obj
            $PemString = $($PublicCertInPemFormat | Where-Object {$_ -notmatch "CERTIFICATE"}) -join "`n"
            $byteArray = [System.Convert]::FromBase64String($PemString)
            $X509Cert2Obj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($byteArray)
        }
        else {
            $X509Cert2Obj = Check-Cert -IPAddress $LDAPServerNetworkInfo.IPAddressList[0] -Port $Port
            $PublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
                [System.Convert]::ToBase64String($X509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
                "`n-----END CERTIFICATE-----"
            $PublicCertInPemFormat = $PublicCertInPemFormatPrep -split "`n"
        }
    }

    $CertificateChain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $null = $CertificateChain.Build($X509Cert2Obj)
    [System.Collections.ArrayList]$CertsInPemFormat = @()
    foreach ($Cert in $CertificateChain.ChainElements.Certificate) {
        $CertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
        [System.Convert]::ToBase64String($Cert.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
        "`n-----END CERTIFICATE-----"
        $CertInPemFormat = $CertInPemFormatPrep -split "`n"
        
        $null = $CertsInPemFormat.Add($CertInPemFormat)
    }
    $CertChainInPemFormat = $($CertsInPemFormat | Out-String).Trim()

    <#
    $RootCAX509Cert2Obj = $CertificateChain.ChainElements.Certificate | Where-Object {
        $($_.Issuer | Select-String -Pattern "^CN=[a-zA-Z0-9]+").Matches.Value -eq
        $($_.Subject | Select-String -Pattern "^CN=[a-zA-Z0-9]+").Matches.Value
    }
    #>
    $RootCAX509Cert2Obj = $CertificateChain.ChainElements.Certificate | Where-Object {$_.Issuer -eq $_.Subject}
    $RootCAPublicCertInPemFormatPrep = "-----BEGIN CERTIFICATE-----`n" + 
        [System.Convert]::ToBase64String($RootCAX509Cert2Obj.RawData, [System.Base64FormattingOptions]::InsertLineBreaks) + 
        "`n-----END CERTIFICATE-----"
    $RootCACertInPemFormat = $RootCAPublicCertInPemFormatPrep -split "`n"

    # Create Output

    $LDAPEndpointCertificateInfo = [pscustomobject]@{
        X509CertFormat      = $X509Cert2Obj
        PemFormat           = $PublicCertInPemFormat
    }

    $RootCACertificateInfo = [pscustomobject]@{
        X509CertFormat      = $RootCAX509Cert2Obj
        PemFormat           = $RootCACertInPemFormat
    }

    $CertChainInfo = [pscustomobject]@{
        X509ChainFormat     = $CertificateChain
        PemFormat           = $CertChainInPemFormat
    }

    [pscustomobject]@{
        LDAPEndpointCertificateInfo  = $LDAPEndpointCertificateInfo
        RootCACertificateInfo        = $RootCACertificateInfo
        CertChainInfo                = $CertChainInfo
    }
    
    #endregion >> Main Body
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUs8jD8RQv9mhR/whEqs2F36wn
# tVqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBVvPGae47sSiprs
# EPXr4OXDJX5oMA0GCSqGSIb3DQEBAQUABIIBACMcOjAOOG+6jk4oV+zNNpNIKjQx
# DT/Qcg0KQlyVQu7Mq4bRGXbejy8ThJQB7NOZy+8SX/caQKQFObbxNa+p7f7nAWso
# CTPKyE1hQWrV3/ZHcIbxqPLlVuYRAdAOsMGKsEnPyEvam649cn9PlUyHHx5orTMX
# exrzdQ3/SlDvAryVKQVjBP/B4puUDb8fMejNEYeJFYzA6qVn1YeWPYWokOY7PE/W
# f/HSOw24GPHwA+Kjw0smUpYVuVp7ar6v3Kw1hu++6AT4y4886M2zQnB+yt8v/NTP
# QFSoXaPdc9A6N2Z2hMHSX8D32CbQxA2ytfWRorO3Nkv0Oo56EhJWmgtMyzc=
# SIG # End signature block
