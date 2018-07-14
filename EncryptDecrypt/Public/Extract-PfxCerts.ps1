<#
    .SYNOPSIS
        This function uses openssl.exe to extract all public certificates and private key from a .pfx file. Each public certificate
        and the private key is written to its own separate file in the specified. OutputDirectory. If openssl.exe is not available
        on the current system, it is downloaded to the Current User's Downloads folder and added to $env:Path.

        NOTE: Nothing is installed.

    .DESCRIPTION
        See SYNOPSIS.

    .NOTES
        Depends on openssl.exe.

        NOTE: Nothing needs to be installed in order to use openssl.exe.

    .PARAMETER PFXFilePath
        Mandatory.

        This parameter takes a string that represents the full path to a .pfx file

    .PARAMETER PFXFilePwd
        Optional.

        This parameter takes a string (i.e. plain text password) or a secure string.

        If the private key in the .pfx file is password protected, use this parameter.

    .PARAMETER StripPrivateKeyPwd
        Optional.

        This parameter takes a boolean $true or $false.

        By default, this function writes the private key within the .pfx to a file in a protected format, i.e.
            -----BEGIN PRIVATE KEY-----
            -----END PRIVATE KEY-----

        If you set this parameter to $true, then this function will ALSO (in addition to writing out the above protected
        format to its own file) write the unprotected private key to its own file with format
            -----BEGIN RSA PRIVATE KEY----
            -----END RSA PRIVATE KEY----

        WARNING: This parameter is set to $true by default.

    .PARAMETER OutputDirectory
        Optional.

        This parameter takes a string that represents a file path to a *directory* that will contain all file outputs.

        If this parameter is not used, all file outputs are written to the same directory as the .pfx file.

    .PARAMETER DownloadAndAddOpenSSLToPath
        Optional.

        This parameter downloads openssl.exe from https://indy.fulgan.com/SSL/ to the current user's Downloads folder,
        and adds openssl.exe to $env:Path.

        WARNING: If openssl.exe is not already part of your $env:Path prior to running this function, this parameter
        becomes MANDATORY, or the function will fail.

    .EXAMPLE
        # If your private key is password protected...
        $PSSigningCertFile = "C:\Certs\Testing2\ZeroCode.pfx"
        $PFXSigningPwdAsSecureString = Read-Host -Prompt "Please enter the private key's password" -AsSecureString
        $OutDir = "C:\Certs\Testing2"

        Extract-PFXCerts -PFXFilePath $PSSigningCertFile `
        -PFXFilePwd $PFXSigningPwdAsSecureString `
        -StripPrivateKeyPwd $true `
        -OutputDirectory $OutDir

    .EXAMPLE
        # If your private key is NOT password protected...
        $PSSigningCertFile = "C:\Certs\Testing2\ZeroCode.pfx"
        $OutputDirectory = "C:\Certs\Testing2"

        Extract-PFXCerts -PFXFilePath $PSSigningCertFile `
        -StripPrivateKeyPwd $true `
        -OutputDirectory $OutDir
#>
function Extract-PfxCerts {
    [CmdletBinding(
        PositionalBinding=$true,
        ConfirmImpact='Medium'
    )]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PFXFilePath = $(Read-Host -Prompt "Please enter the full path to the .pfx file."),

        [Parameter(Mandatory=$False)]
        $PFXFilePwd, # This is only needed if the .pfx contains a password-protected private key, which should be the case 99% of the time

        [Parameter(Mandatory=$False)]
        [bool]$StripPrivateKeyPwd = $true,

        [Parameter(Mandatory=$False)]
        [string]$OutputDirectory, # If this parameter is left blank, all output files will be in the same directory as the original .pfx

        [Parameter(Mandatory=$False)]
        [switch]$DownloadAndAddOpenSSLToPath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Check for Win32 or Win64 OpenSSL Binary
    if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        if ($DownloadAndAddOpenSSLToPath) {
            Write-Host "Downloading openssl.exe from https://indy.fulgan.com/SSL/..."
            $LatestWin64OpenSSLVer = $($($(Invoke-WebRequest -Uri https://indy.fulgan.com/SSL/).Links | Where-Object {$_.href -like "*[a-z]-x64*"}).href | Sort-Object)[-1]
            Invoke-WebRequest -Uri "https://indy.fulgan.com/SSL/$LatestWin64OpenSSLVer" -OutFile "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer"
            $SSLDownloadUnzipDir = $(Get-ChildItem "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer").BaseName
            if (! $(Test-Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir")) {
                New-Item -Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir" -ItemType Directory
            }
            UnzipFile -PathToZip "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer" -TargetDir "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
            # Add OpenSSL to $env:Path
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
            }
            else {
                $env:Path = "$env:Path;$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
            }
        }
        else {
            Write-Error "The Extract-PFXCerts function requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # OpenSSL can't handle PowerShell SecureStrings, so need to convert it back into Plain Text
    if ($PFXFilePwd) {
        if ($PFXFilePwd.GetType().FullName -eq "System.Security.SecureString") {
            $PwdForPFXOpenSSL = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXFilePwd))
        }
        if ($PFXFilePwd.GetType().FullName -eq "System.String") {
            $PwdForPFXOpenSSL = $PFXFilePwd
        }
    }

    $privpos = $PFXFilePath.LastIndexOf("\")
    $PFXFileDir = $PFXFilePath.Substring(0, $privpos)
    $PFXFileName = $PFXFilePath.Substring($privpos+1)
    $PFXFileNameSansExt = $($PFXFileName.Split("."))[0]

    if (!$OutputDirectory) {
        $OutputDirectory = $PFXFileDir
    }

    $ProtectedPrivateKeyOut = "$PFXFileNameSansExt"+"_protected_private_key"+".pem"
    $UnProtectedPrivateKeyOut = "$PFXFileNameSansExt"+"_unprotected_private_key"+".pem"
    $AllPublicKeysInChainOut = "$PFXFileNameSansExt"+"_all_public_keys_in_chain"+".pem"
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Parameter Validation #####
    if (!$(Test-Path $PFXFilePath)) {
        Write-Error "The path $PFXFilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (! $(Test-Path $OutputDirectory)) {
        Write-Error "The path $OutputDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Parameter Validation #####


    ##### BEGIN Main Body #####
    # The .pfx File could (and most likely does) contain a private key
    # Extract Private Key and Keep It Password Protected
    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "openssl.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nocerts -out $OutputDirectory\$ProtectedPrivateKeyOut -nodes -password pass:$PwdForPFXOpenSSL"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr

        if ($AllOutput -match "error") {
            Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect. However, it may be that at this stage in the process, it is not protected with a password. Trying without password..."
            throw
        }
    }
    catch {
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "openssl.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nocerts -out $OutputDirectory\$ProtectedPrivateKeyOut -nodes -password pass:"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "error") {
                Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect."
                throw
            }
        }
        catch {
            $PFXFilePwdFailure = $true
        }
    }
    if ($PFXFilePwdFailure -eq $true) {
        Write-Verbose "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        Write-Error "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        $global:FunctionResult = "1"
        return
    }
    

    if ($StripPrivateKeyPwd) {
        # Strip Private Key of Password
        & openssl.exe rsa -in "$PFXFileDir\$ProtectedPrivateKeyOut" -out "$OutputDirectory\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
    }

    New-Variable -Name "$PFXFileNameSansExt`PrivateKeyInfo" -Value $(
        if ($StripPrivateKeyPwd) {
            [pscustomobject][ordered]@{
                ProtectedPrivateKeyFilePath     = "$OutputDirectory\$ProtectedPrivateKeyOut"
                UnProtectedPrivateKeyFilePath   = "$OutputDirectory\$UnProtectedPrivateKeyOut"
            }
        }
        else {
            [pscustomobject][ordered]@{
                ProtectedPrivateKeyFilePath     = "$OutputDirectory\$ProtectedPrivateKeyOut"
                UnProtectedPrivateKeyFilePath   = $null
            }
        }
    )
    

    # Setup $ArrayOfPubCertPSObjects for PSCustomObject Collection
    $ArrayOfPubCertPSObjects = @()
    # The .pfx File Also Contains ALL Public Certificates in Chain 
    # The below extracts ALL Public Certificates in Chain
    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "openssl.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nokeys -out $OutputDirectory\$AllPublicKeysInChainOut -password pass:$PwdForPFXOpenSSL"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr

        if ($AllOutput -match "error") {
            Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect. However, it may be that at this stage in the process, it is not protected with a password. Trying without password..."
            throw
        }
    }
    catch {
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "openssl.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nokeys -out $OutputDirectory\$AllPublicKeysInChainOut -password pass:"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "error") {
                Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect."
                throw
            }
        }
        catch {
            $PFXFilePwdFailure = $true
        }
    }
    if ($PFXFilePwdFailure -eq $true) {
        Write-Verbose "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        Write-Error "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        $global:FunctionResult = "1"
        return
    }
    New-Variable -Name "CertObj$PFXFileNameSansExt" -Scope Script -Value $(
        [pscustomobject][ordered]@{
            CertName                = "$PFXFileNameSansExt`AllPublicKCertsInChain"
            AllCertInfo             = Get-Content "$OutputDirectory\$AllPublicKeysInChainOut"
            FileLocation            = "$OutputDirectory\$AllPublicKeysInChainOut"
        }
    ) -Force

    $ArrayOfPubCertPSObjects +=, $(Get-Variable -Name "CertObj$PFXFileNameSansExt" -ValueOnly)


    # Parse the Public Certificate Chain File and and Write Each Public Certificate to a Separate File
    # These files should have the EXACT SAME CONTENT as the .cer counterparts
    $PublicKeySansChainPrep1 = $(Get-Content "$OutputDirectory\$AllPublicKeysInChainOut") -join "`n"
    $PublicKeySansChainPrep2 = $($PublicKeySansChainPrep1 -replace "-----END CERTIFICATE-----","-----END CERTIFICATE-----;;;").Split(";;;")
    $PublicKeySansChainPrep3 = foreach ($obj1 in $PublicKeySansChainPrep2) {
        if ($obj1 -like "*[\w]*") {
            $obj1.Trim()
        }
    }
    # Setup PSObject for Certs with CertName and CertValue
    foreach ($obj1 in $PublicKeySansChainPrep3) {
        $CertNamePrep = $($obj1).Split("`n") | foreach {if ($_ | Select-String "subject") {$_}}
        $CertName = $($CertNamePrep | Select-String "CN=([\w]|[\W]){1,1000}$").Matches.Value -replace "CN=",""
        $IndexNumberForBeginCert = $obj1.Split("`n") | foreach {
            if ($_ -match "-----BEGIN CERTIFICATE-----") {
                [array]::indexof($($obj1.Split("`n")),$_)
            }
        }
        $IndexNumberForEndCert = $obj1.Split("`n") | foreach {
            if ($_ -match "-----End CERTIFICATE-----") {
                [array]::indexof($($obj1.Split("`n")),$_)
            }
        }
        $CertValue = $($($obj1.Split("`n"))[$IndexNumberForBeginCert..$IndexNumberForEndCert] | Out-String).Trim()
        $AttribFriendlyNamePrep = $obj1.Split("`n") | Select-String "friendlyName"
        if ($AttribFriendlyNamePrep) {
            $AttribFriendlyName = $($AttribFriendlyNamePrep.Line).Split(":")[-1].Trim()
        }
        $tmpFile = [IO.Path]::GetTempFileName()
        $CertValue.Trim() | Out-File $tmpFile -Encoding Ascii

        $CertDumpContent = certutil -dump $tmpfile

        $SubjectTypePrep = $CertDumpContent | Select-String -Pattern "Subject Type="
        if ($SubjectTypePrep) {
            $SubjectType = $SubjectTypePrep.Line.Split("=")[-1]
        }
        $RootCertFlag = $CertDumpContent | Select-String -Pattern "Subject matches issuer"
        
        if ($SubjectType -eq "CA" -and $RootCertFlag) {
            $RootCACert = $True
        }
        else {
            $RootCACert = $False
        }
        if ($SubjectType -eq "CA" -and !$RootCertFlag) {
            $IntermediateCACert = $True
        }
        else {
            $IntermediateCACert = $False
        }
        if ($RootCACert -eq $False -and $IntermediateCACert -eq $False) {
            $EndPointCert = $True
        }
        else {
            $EndPointCert = $False
        }

        New-Variable -Name "CertObj$CertName" -Scope Script -Value $(
            [pscustomobject][ordered]@{
                CertName                = $CertName
                FriendlyName            = $AttribFriendlyName
                CertValue               = $CertValue.Trim()
                AllCertInfo             = $obj1.Trim()
                RootCACert              = $RootCACert
                IntermediateCACert      = $IntermediateCACert
                EndPointCert            = $EndPointCert
                FileLocation            = "$OutputDirectory\$($CertName)_Public_Cert.pem"
            }
        ) -Force

        $ArrayOfPubCertPSObjects +=, $(Get-Variable -Name "CertObj$CertName" -ValueOnly)

        Remove-Item -Path $tmpFile -Force
        Remove-Variable -Name "tmpFile" -Force
    }

    # Write each CertValue to Separate Files (i.e. writing all public keys in chain to separate files)
    foreach ($obj1 in $ArrayOfPubCertPSObjects) {
        if ($(Test-Path $obj1.FileLocation) -and !$Force) {
            Write-Verbose "The extracted Public cert $($obj1.CertName) was NOT written to $OutputDirectory because it already exists there!"
        }
        if (!$(Test-Path $obj1.FileLocation) -or $Force) {
            $obj1.CertValue | Out-File "$($obj1.FileLocation)" -Encoding Ascii
            Write-Verbose "Public certs have been extracted and written to $OutputDirectory"
        }
    }

    New-Variable -Name "PubAndPrivInfoOutput" -Scope Script -Value $(
        [pscustomobject][ordered]@{
            PublicKeysInfo      = $ArrayOfPubCertPSObjects
            PrivateKeyInfo      = $(Get-Variable -Name "$PFXFileNameSansExt`PrivateKeyInfo" -ValueOnly)
        }
    ) -Force

    $(Get-Variable -Name "PubAndPrivInfoOutput" -ValueOnly)
    
    $global:FunctionResult = "0"
    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkM55m9nYv3laVG2LV7+KzzKJ
# 9iCgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLWsTFgQpytV+wWF
# Jb7FmrJqjZW8MA0GCSqGSIb3DQEBAQUABIIBAIPtvFVYRxRfAV8m6MdPenAoWV9d
# AZFn67V59GSHBAuAFYA4oapY2cyGygAX/vQDS8cUTjQMILPTly9C+zvWNmkXdBRs
# t7Om2Bu+si9zXr6hTUlZE8bUingDYF/mtgIvqgOS+TOdSuMP2J9Mw33+yDV7jPCd
# MybIYdfgb/S5zxP28KJ4A/9GYK+Yeqz2ceD4ZU0rOH15n2opvNgMPnmowy5+OaLG
# SPhXOppUrnTNPU+A7cLwFaOj7Bki12Zi4iq0KN0FbI4mOD37XvaA0QVaA9Ngykrm
# i5CU5XCPXwJ/r2HStsjUjZ63Jug/KWcD6P6n/RNSYOFMp1A+e7E2lh38kzo=
# SIG # End signature block
