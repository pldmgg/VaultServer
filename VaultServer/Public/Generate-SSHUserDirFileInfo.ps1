<#
    .SYNOPSIS
        This function generates:
            - An ArrayList of PSCustomObjects that describes the contents of each of the files within the
            "$HOME\.ssh" directory
            - An .xml file that can be ingested by the 'Import-CliXml' cmdlet to generate
            the aforementioned ArrayList of PSCustomObjects in future PowerShell sessions.
            
            Each PSCustomObject in the ArrayList contains information similar to:

                File     : C:\Users\zeroadmin\.ssh\PwdProtectedPrivKey
                FileType : RSAPrivateKey
                Contents : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
                Info     : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}

        By default, the .xml file is written to "$HOME\.ssh\SSHDirectoryFileInfo.xml"

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PathToHomeDotSSHDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to the User's .ssh directory. You should
        only use this parameter if the User's .ssh is NOT under "$HOME\.ssh" for some reason. 

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Generate-SSHUserDirFileInfo
        
#>
function Generate-SSHUserDirFileInfo {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PathToHomeDotSSHDirectory
    )

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

    # Make sure we have access to ssh binaries
    if (![bool]$(Get-Command ssh-keygen -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find 'ssh-keygen'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$PathToHomeDotSSHDirectory) {
        $PathToHomeDotSSHDirectory = Join-Path $HOME ".ssh"
    }

    # Get a list of all files under $HOME\.ssh
    [array]$SSHHomeFiles = Get-ChildItem -Path $PathToHomeDotSSHDirectory -File | Where-Object {$_.Name -ne "SSHDirectoryFileInfo.xml"}

    if ($SSHHomeFiles.Count -eq 0) {
        Write-Error "Unable to find any files under '$PathToHomeDotSSHDirectory'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    [System.Collections.ArrayList]$ArrayOfPSObjects = @()
    foreach ($File in $SSHHomeFiles.FullName) {
        #Write-Host "Analyzing file '$File' ..."
        try {
            $GetSSHFileInfoResult = Get-SSHFileInfo -PathToKeyFile $File -ErrorAction Stop -WarningAction SilentlyContinue
            if (!$GetSSHFileInfoResult) {
                #Write-Warning "'$File' is not a valid Public Key, Private Key, or Public Key Certificate!"
                #Write-Host "Ensuring '$File' is UTF8 encoded and trying again..." -ForegroundColor Yellow
                Set-Content -Path $File -Value $(Get-Content $File) -Encoding UTF8
            }

            $GetSSHFileInfoResult = Get-SSHFileInfo -PathToKeyFile $File -ErrorAction Stop -WarningAction SilentlyContinue
            if (!$GetSSHFileInfoResult) {
                Write-Verbose "'$File' is definitley not a valid Public Key, Private Key, or Public Key Certificate!"
            }

            # Sample Output:
            # NOTE: Possible values for the 'FileType' property are 'RSAPrivateKey','RSAPublicKey', and 'RSAPublicKeyCertificate'
            <#
                File     : C:\Users\zeroadmin\.ssh\PwdProtectedPrivKey
                FileType : RSAPrivateKey
                Contents : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
                Info     : {-----BEGIN RSA PRIVATE KEY-----, Proc-Type: 4,ENCRYPTED, DEK-Info: AES-128-CBC,27E137C044FC7857DAAC05C408472EF8, ...}
            #>

            $null = $ArrayOfPSObjects.Add($GetSSHFileInfoResult)
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $ArrayOfPSObjects
    $ArrayOfPSObjects | Export-CliXml "$PathToHomeDotSSHDirectory\SSHDirectoryFileInfo.xml"
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUq96s6BnJuRAQjcTUkEokf6Rh
# c4agggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBl4mj8NWmfVCEqG
# A7DOMbRSHKFlMA0GCSqGSIb3DQEBAQUABIIBALVNjVI7dMgl/b29dpjX2yCoIFLy
# DMTgSm9puKIsWGrQ0RPKpIO8r8FyBYB/yTPemJO8hJYG6hIU1KKdpdizR88MVyMp
# pj3LHwjWI4qHGW9BI0MpzVxKYA7+35dtmvXsgqnH+3qooZvyYRF1NRXU9FTdbZwu
# JbHQGHwOKIbWWDvaXbXsxFPfU9jBFVB8VCNN+ppafvi81+XcyF1baiyGjAYpaCCr
# EHoCkdyrrIRNXM1Tkvgi6D99ZDOyE5pvDEcaPgu/gA25RT1poJsqzW8lsYwsOzFu
# Z5NMPcmEaa4+erav/GBxr2rKkua7kQdsjnzfIEjXWfUftwD/R5lg1lfznEE=
# SIG # End signature block
