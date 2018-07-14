<#
    .SYNOPSIS
        If a System.Security.Cryptography.X509Certificates.X509Certificate2 object has properties...
            HasPrivateKey        : True
            PrivateKey           :
        ...and you would like to get the System.Security.Cryptography.RSACryptoServiceProvider object that should be in
        the PrivateKey property, use this function.

    .DESCRIPTION
        See SYNOPSIS

    .NOTES
        Depends on Extract-PfxCerts and therefore depends on openssl.exe.

        NOTE: Nothing needs to be installed in order to use openssl.exe.

        IMPORTANT NOTE REGARDING -CertObject PARAMETER:
        If you are getting the value for the -CertObject parameter from an already existing .pfx file (as opposed to the Cert Store),
        *DO NOT* use the Get-PFXCertificate cmdlet. The cmdlet does something strange that causes a misleading/incorrect error if the
        private key in the .pfx is password protected.

        Instead, use the following:
            $CertPwd = ConvertTo-SecureString -String 'RaNDompaSSwd123' -Force -AsPlainText
            $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        If you are getting the value for the -CertObject parameter from the Certificate Store, either of the following should be fine
            $CertObj = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
            $CertObj = Get-ChildItem Cert:\CurrentUser\My\<Thumbprint>

        WARNING: This function defaults to temporarily writing the unprotected private key to its own file in -TempOutputDirectory.
        The parameter -CleanupOpenSSLOutputs is set to $true by default, so the unprotected private key will only exist on the file
        system for a couple seconds.  If you would like to keep the unprotected private key on the file system, set the
        -CleanupOpenSSLOutputs parameter to $false.

    .PARAMETER CertObject
        Mandatory.

        Must be a System.Security.Cryptography.X509Certificates.X509Certificate2 object.

        If you are getting the value for the -CertObject parameter from an already existing .pfx file (as opposed to the Cert Store),
        *DO NOT* use the Get-PFXCertificate cmdlet. The cmdlet does something strange that causes a misleading/incorrect error if the
        private key in the .pfx is password protected.

        Instead, use the following:
            $CertPwd = ConvertTo-SecureString -String 'RaNDompaSSwd123' -Force -AsPlainText
            $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        If you are getting the value for the -CertObject parameter from the Certificate Store, either of the following should be fine
            $CertObj = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
            $CertObj = Get-ChildItem Cert:\CurrentUser\My\<Thumbprint>

    .PARAMETER TempOutputDirectory
        Mandatory.

        Must be a full path to a directory. Punlic certificates and the private key within the -CertObject will *temporarily*
        be written to this directory as a result of the helper function Extract-PfxCerts.

    .PARAMETER CertPwd
        Optional.

        This parameter must be a System.Security.SecureString.

        This parameter is Mandatory if the private key in the .pfx is password protected.

    .PARAMETER CleanupOpenSSLOutputs
        Optional.

        Must be Boolean.

        During this function, openssl.exe is used to extract all public certs and the private key from the -CertObject. Each of these
        certs and the key are written to separate files in -TempOutputDirectory. This parameter removes these file outputs at the
        conclusion of the function. This parameter is set to $true by default.

    .PARAMETER DownloadAndAddOpenSSLToPath
        Optional.

        If openssl.exe is not already on your localhost and part of your $env:Path, use this parameter to download
        openssl.exe / add it to your $env:Path

    .EXAMPLE
        # If the private key in the .pfx is password protected...
        PS C:\Users\zeroadmin> $CertPwd = Read-Host -Prompt "Please enter the Certificate's Private Key password" -AsSecureString
        Please enter the Certificate's Private Key password: ***************
        PS C:\Users\zeroadmin> $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout" -CertPwd $CertPwd

    .EXAMPLE
        # If the private key in the .pfx is NOT password protected...
        PS C:\Users\zeroadmin> $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout"

    .EXAMPLE
        # Getting -CertObject from the Certificate Store where private key is password protected...
        PS C:\Users\zeroadmin> $CertPwd = Read-Host -Prompt "Please enter the Certificate's Private Key password" -AsSecureString
        Please enter the Certificate's Private Key password: ***************
        PS C:\Users\zeroadmin> $CertObj = Get-ChildItem "Cert:\LocalMachine\My\5359DDD9CB88873DF86617EC28FAFADA17112AE6"
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout" -CertPwd $CertPwd

    .EXAMPLE
        # Getting -CertObject from the Certificate Store where private key is NOT password protected...
        PS C:\Users\zeroadmin> $CertObj = Get-ChildItem "Cert:\LocalMachine\My\5359DDD9CB88873DF86617EC28FAFADA17112AE6"
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout"
#>
function Get-PrivateKeyProperty {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertObject,

        [Parameter(Mandatory=$True)]
        $TempOutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"),

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [bool]$CleanupOpenSSLOutputs = $true,

        [Parameter(Mandatory=$False)]
        [switch]$DownloadAndAddOpenSSLToPath

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($CertObject.PrivateKey -eq $null -and $CertObject.HasPrivateKey -eq $false -or $CertObject.HasPrivateKey -ne $true) {
        Write-Error "There is no Private Key associated with this X509Certificate2 object! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        if (!$DownloadAndAddOpenSSLToPath) {
            Write-Error "The Helper Function Extract-PFXCerts requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $CertName = $($CertObject.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
    try {
        $pfxbytes = $CertObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        [System.IO.File]::WriteAllBytes("$TempOutputDirectory\$CertName.pfx", $pfxbytes)
    }
    catch {
        Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Trying to import `$CertObject to Cert:\LocalMachine\My Store..."
        # NOTE: The $CertObject.Export() method in the above try block has a second argument for PlainTextPassword, but it doesn't seem to work consistently
        
        # Check to see if it's already in the Cert:\LocalMachine\My Store
        if ($(Get-Childitem "Cert:\LocalMachine\My").Thumbprint -contains $CertObject.Thumbprint) {
            Write-Host "The certificate $CertName is already in the Cert:\LocalMachine\My Store."
        }
        else {
            Write-Host "Importing $CertName to Cert:\LocalMachine\My Store..."
            $X509Store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $X509Store.Add($CertObject)
        }

        Write-Host "Attempting to export `$CertObject from Cert:\LocalMachine\My Store to .pfx file..."

        if (!$CertPwd) {
            $CertPwd = Read-Host -Prompt "Please enter the password for the private key in the certificate $CertName" -AsSecureString
        }

        $CertItem = Get-Item "Cert:\LocalMachine\My\$($CertObject.Thumbprint)"
        [System.IO.File]::WriteAllBytes("$TempOutputDirectory\$CertName.pfx", $CertItem.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPwd))
        #Export-PfxCertificate -FilePath "$TempOutputDirectory\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($CertObject.Thumbprint)" -Password $CertPwd

    }

    # NOTE: If openssl.exe isn't already available, the Extract-PFXCerts function downloads it and adds it to $env:Path
    if ($CertPwd) {
        $global:PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -PFXFilePwd $CertPwd -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
    }
    else {
        $global:PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath -eq $null) {
        # Strip Private Key of Password
        $UnProtectedPrivateKeyOut = "$($(Get-ChildItem $PathToCertFile).BaseName)"+"_unprotected_private_key"+".pem"
        & openssl.exe rsa -in $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath -out "$HOME\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
        $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath = "$HOME\$UnProtectedPrivateKeyOut"
    }

    #Write-Host "Loading opensslkey.cs from https://github.com/sushihangover/SushiHangover-PowerShell/blob/master/modules/SushiHangover-RSACrypto/opensslkey.cs"
    #$opensslkeysource = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sushihangover/SushiHangover-PowerShell/master/modules/SushiHangover-RSACrypto/opensslkey.cs").Content
    try {
        Add-Type -TypeDefinition $opensslkeysource
    }
    catch {
        if ($_.Exception -match "already exists") {
            Write-Verbose "The JavaScience.Win32 assembly (i.e. opensslkey.cs) is already loaded. Continuing..."
        }
    }
    $PemText = [System.IO.File]::ReadAllText($global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath)
    $PemPrivateKey = [javascience.opensslkey]::DecodeOpenSSLPrivateKey($PemText)
    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = [javascience.opensslkey]::DecodeRSAPrivateKey($PemPrivateKey)
    $RSA

    # Cleanup
    if ($CleanupOpenSSLOutputs) {
        $ItemsToRemove = @(
            $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath
            $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath
        ) + $global:PubCertAndPrivKeyInfo.PublicKeysInfo.FileLocation

        foreach ($item in $ItemsToRemove) {
            Remove-Item $item
        }
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdSjN1oI1A+ivL4fwLgLI+zBu
# r26gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDPZn8jtSFh9EDfG
# 5AEsvIL/u2cpMA0GCSqGSIb3DQEBAQUABIIBAG6TlepJsC2Jk1LvSIl5q+zrMrsI
# Ja8PZVLiT1OO98m5sFWqwM+jFsOIikIhy8Zt+e0UdbaRsvgNPb1hzpnudR1DyFCQ
# JLElF5jjqOgNYN6EzWbplvnQ0EYsx2J3SgB/T5AikkVc5M4SytnvrXRn9wUGC3TE
# +OaXilVmA0dSmeyQJvV/9XWhBsC/CahXv56ZymupTAXtBBojb+EnXLkXNVI0aDqx
# 0R/KEH8Wkz6M073BCSqRw7NR2Ve1bY4b3+FU5BY91I3ev90l0tHd6hmWZ36phiTO
# xuFg/azWdZN/7lRj7ZBfkKOKrU62UhV0Azn7JHEkfIcY7DP9RcmFobwa8aI=
# SIG # End signature block
