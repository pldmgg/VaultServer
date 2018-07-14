<#
    .SYNOPSIS 
    Decrypts a file using AES.

    .DESCRIPTION
    Decrypts a file using an AES key.

    .PARAMETER FileToDecrypt
    File(s) to be decrypted

    .PARAMETER Key
    AES key to be used for decryption.

    .EXAMPLE

    DecryptFile 'C:\file.ext.encrypted' $key

    This example decrypts C:\file.ext.encrypted with the key stored in the variable $key.

    .NOTES
    Author: Tyler Siegrist
    Date: 8/23/2016
    https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
Function DecryptFile {
    Param(
       [Parameter(Mandatory=$true, Position=1)]
       [System.IO.FileInfo[]]$FileToDecrypt,
       [Parameter(Mandatory=$true, Position=2)]
       [String]$Key,
       [Parameter(Mandatory=$false, Position=3)]
       [String]$Suffix
    )
 
    #Load dependencies
    try {
        if ($PSVersionTable.PSEdition -eq "Core") {
            $SystemCoreAssemblyPath = $($(Get-Command pwsh).Source | Split-Path -Parent) + '\System.Core.dll'
            if (!$(Test-Path $SystemCoreAssemblyPath)) {
                Write-Error "The path '$SystemCoreAssemblyPath' was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $null = Add-Type -Path $SystemCoreAssemblyPath
        }
        else {
            [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
        }
    }
    catch {
        Write-Error 'Could not load required assembly.'
        Return
    }

    #Configure AES
    try {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        $KeySize = $EncryptionKey.Length*8
        $AESProvider = New-Object 'System.Security.Cryptography.AesManaged'
        $AESProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AESProvider.BlockSize = 128
        $AESProvider.KeySize = $KeySize
        $AESProvider.Key = $EncryptionKey
    }
    catch {
        Write-Error 'Unable to configure AES, verify you are using a valid key.'
        Return
    }

    #Used to store successfully decrypted file names.
    $DecryptedFiles = @()
    $FailedToDecryptFiles = @()

    foreach ($File in $FileToDecrypt) {
        # Try to decrypt as long as the .decrypted file doesn't already exist
        $DestinationFile = "$($File.FullName).decrypted"

        if (!$(Test-Path $DestinationFile)) {
            #Open file to decrypt
            try {
                $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
            }
            catch {
                Write-Error "Unable to open $($File.FullName) for reading."
                Continue
            }
        
            #Create destination file
            try {
                $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
            }
            catch {
                $FileStreamReader.Close()
                $FileStreamWriter.Close()
                Remove-Item $DestinationFile -Force
                Write-Error "Unable to open $DestinationFile for writing."
                Continue
            }

            #Get IV
            try {
                [Byte[]]$LenIV = New-Object Byte[] 4
                $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
                $FileStreamReader.Read($LenIV,  0, 3) | Out-Null
                [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0)
                [Byte[]]$IV = New-Object Byte[] $LIV
                $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
                $FileStreamReader.Read($IV, 0, $LIV) | Out-Null
                $AESProvider.IV = $IV
            }
            catch {
                $FileStreamReader.Close()
                $FileStreamWriter.Close()
                Remove-Item $DestinationFile -Force
                $FailedToDecryptFiles += $File
                Write-Error "Unable to read IV from $($File.FullName), verify this file was made using the included EncryptFile function."
                Continue
            }

            Write-Verbose "Decrypting $($File.FullName) with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

            #Decrypt
            try {
                $Transform = $AESProvider.CreateDecryptor()
                [Int]$Count = 0
                [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
                [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
                $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
                Do
                {
                    $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                    $CryptoStream.Write($Data, 0, $Count)
                }
                While ($Count -gt 0)

                $CryptoStream.FlushFinalBlock()
                $CryptoStream.Close()
                $FileStreamWriter.Close()
                $FileStreamReader.Close()

                #Delete encrypted file
                Remove-Item $File.FullName
                Write-Verbose "Successfully decrypted $($File.FullName)"
                $DecryptedFiles += $DestinationFile
            }
            catch {
                Write-Error "Failed to decrypt $($File.FullName)."
                $CryptoStream.Close()
                $FileStreamWriter.Close()
                $FileStreamReader.Close()
                Remove-Item $DestinationFile
                $FailedToDecryptFiles += $File
            }
        }        
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Result | Add-Member -MemberType NoteProperty -Name AESKey -Value $Key
    $Result | Add-Member -MemberType NoteProperty -Name FilesDecryptedwAESKey -Value $DecryptedFiles
    $Result | Add-Member -MemberType NoteProperty -Name FilesFailedToDecrypt -Value $FailedToDecryptFiles
    return $Result
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+Qq9ZQVraxaAi3yRRRoZ2Tzj
# brygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAVKUt0aaWVeOO5F
# K0L1FXSaVv5JMA0GCSqGSIb3DQEBAQUABIIBAL7J3MAF2xCHrzHUDc1rpDKZutwZ
# ZP15297MUWskw1gwW8m5vUPsisercLEQKo8S6MwCLMyG3LFZ+hhF1Bx/XQUw+oq1
# pU+FcCzS1eqrF4NMsnB4gCivmHMGAZskxoiyEiesDiqMqZbxO8X78NhMsb0J6jyB
# 4Dxy2xbUvKRRmHjaQnAlFMQwglvIeQuJfVWMNEVaTCDUCCqr0oy68IarFv0+COPn
# ng6YCriLOYWgoLHYEJCe39lxtmVH/WoYB8RtzRw/0ByMAf+aCiADXDXapD2PEqDT
# 5DkK3aup1VaMj8s5uE8vZ2x9hwOu7mdVPnZ7cC6KOum44dxZEVp+U5BfkKI=
# SIG # End signature block
