<#
    .SYNOPSIS
        Edits /etc/sudoers to allow the current user to run 'sudo pwsh' without needing to enter a sudo password.

    .DESCRIPTION
        See SYNOPSIS

    .EXAMPLE
        # Launch pwsh and...

        Remove-SudoPwd
        
#>
function RemoveMySudoPwd {
    [CmdletBinding()]
    Param()

    #region >> Prep

    if ($PSVersionTable.Platform -ne "Unix") {
        Write-Error "This function is meant for use on Linux! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    # 'Get-SudoStatus' cannnot be run as root...
    if (GetElevation) {
        $GetElevationAsString = ${Function:GetElevation}.Ast.Extent.Text
        $GetMySudoStatusAsString = ${Function:GetMySudoStatus}.Ast.Extent.Text
        $FinalScript = $GetElevationAsString + "`n" + $GetMySudoStatusAsString + "`n" + "GetMySudoStatus"
        $PwshScriptBytes = [System.Text.Encoding]::Unicode.GetBytes($FinalScript)
        $EncodedCommand = [Convert]::ToBase64String($PwshScriptBytes)
        $GetSudoStatusResult = su $env:SUDO_USER -c "pwsh -EncodedCommand $EncodedCommand" | ConvertFrom-Json
    }
    else {
        $GetSudoStatusResult = GetMySudoStatus | ConvertFrom-Json
    }
    
    if (!$GetSudoStatusResult.HasSudoPrivileges) {
        Write-Error "The user does not appear to have sudo privileges on $env:HOSTNAME! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $DomainName = $GetSudoStatusResult.DomainInfo.DomainName
    $DomainNameShort = $GetSudoStatusResult.DomainInfo.DomainNameShort
    $UserNameShort = $GetSudoStatusResult.DomainInfo.UserNameShort

    $SudoConfPath = "/etc/sudoers.d/pwsh-nosudo.conf"
    if (!$GetSudoStatusResult.PasswordPrompt) {
        # Check /etc/sudoers to make sure the desired entry is actually there and we're not just within 10 minutes of having entered the sudo pwd previously
        if ($DomainNameShort) {
            $SudoersCheckScript = "ls $SudoConfPath > /dev/null && cat $SudoConfPath | grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && echo present"
        }
        else {
            $SudoersCheckScript = "ls $SudoConfPath > /dev/null && cat $SudoConfPath | grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > /dev/null && echo present"
        }
        $SudoersCheck = sudo bash -c "$SudoersCheckScript"

        if ($SudoersCheck -eq "present") {
            Write-Verbose "The account '$(whoami)' is already allowed to run 'sudo pwsh' without being prompted for a password! No changes made."
            return
        }
    }

    #endregion >> Prep

    #region >> Main

    $PwshLocation = $(Get-Command pwsh).Source
    if ($DomainNameShort) {
        $AddUserString = "%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH"
        $RegexDefinition = "`$UserStringRegex = [regex]::Escape(`"%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH`")"
    } else {
        $AddUserString = "$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH"
        $RegexDefinition = "`$UserStringRegex = [regex]::Escape(`"$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH`")"
    }
    $EditSudoersdFilePrep = @(
        $RegexDefinition    
        '[System.Collections.Generic.List[PSObject]]$UpdateSudoersContent = @('
        "    'Cmnd_Alias SUDO_PWSH = $PwshLocation'"
        "    'Defaults!SUDO_PWSH !requiretty'"
        "    '$AddUserString'"
        ')'
        'if (!$(Test-Path "/etc/sudoers.d")) {'
        '    $null = New-Item -ItemType Directory -Path "/etc/sudoers.d" -Force'
        '    sudo chmod 750 /etc/sudoers.d'
        '}'
        "if (!`$(Test-Path '$SudoConfPath')) {"
        "    Set-Content -Path '$SudoConfPath' -Force -Value `$UpdateSudoersContent"
        "    sudo chmod 440 '$SudoConfPath'"
        '    "sudoConfigUpdated"'
        '}'
        'else {'
        "    [System.Collections.ArrayList][array]`$PwshSudoConfContent = @(Get-Content '$SudoConfPath')"
        '    $MatchingLine = $PwshSudoConfContent -match $UserStringRegex'
        '    if ($MatchingLine) {'
        '        "sudoConfigAlreadyPresent"'
        '    }'
        '    else {'
        '        foreach ($Line in $UpdateSudoersContent) {'
        '            if (![bool]$($PwshSudoConfContent -match [regex]::Escape($Line))) {'
        "                Add-Content -Path '$SudoConfPath' -Value `$Line"
        '            }'
        '        }'
        '        "sudoConfigUpdated"'
        '    }'
        '}'
    )
    $EditSudoersdFile = $EditSudoersdFilePrep -join "`n"

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($EditSudoersdFile)
    $EncodedCommand = [Convert]::ToBase64String($Bytes)
    $Result = sudo pwsh -EncodedCommand $EncodedCommand

    if (!$Result) {
        Write-Error "There was an issue checking/updating '/etc/sudoers.d/pwsh-nosudo.conf'! Please review. Halting!"
        $global:FunctionResult = "1"
        return
    }

    $Result

    <#
    # cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH = /bin/pwsh' > /dev/null && echo present || echo absent
    [System.Collections.Generic.List[PSObject]]$UpdateSudoersScriptPrep = @(
        'pscorepath=$(command -v pwsh)'
        "cat /etc/sudoers | grep -Eic 'Cmnd_Alias SUDO_PWSH =' > /dev/null && echo present || echo 'Cmnd_Alias SUDO_PWSH = '`"`$pscorepath`" | sudo EDITOR='tee -a' visudo"
        "cat /etc/sudoers | grep -Eic 'Defaults!SUDO_PWSH !requiretty' > /dev/null && echo present || echo 'Defaults!SUDO_PWSH !requiretty' | sudo EDITOR='tee -a' visudo"
    )
    if ($DomainNameShort) {
        $AddUserString = "cat /etc/sudoers | grep -Eic '\%$DomainNameShort..$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && echo present || echo '%$DomainNameShort\\$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
    }
    else {
        $AddUserString = "cat /etc/sudoers | grep -Eic '$UserNameShort ALL=\(ALL\) NOPASSWD: SUDO_PWSH' > " +
        "/dev/null && echo present || echo '$UserNameShort ALL=(ALL) NOPASSWD: SUDO_PWSH' | sudo EDITOR='tee -a' visudo"
    }
    $UpdateSudoersScriptPrep.Add($AddUserString)
    $UpdateSudoersScript = $UpdateSudoersScriptPrep -join '; '

    $null = sudo bash -c "$UpdateSudoersScript"
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "There was an issue updating /etc/sudoers! Please review. Halting!"
        $global:FunctionResult = "1"
        return
    }
    #>

    #endregion >> Main
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUU9UG/ZlayR8hdEZhVxrtNqv1
# cXygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKP5NBGHtssENxJL
# U81XqwMOm6OdMA0GCSqGSIb3DQEBAQUABIIBALgiNwqCy9cWNVZpDNsSIDY/sj2g
# MZ3Xglqfq0kH5b1B9neI4IvDSnVsxHXYXz0qv346+4N/wo7gIbiXHcI0fociI5pT
# 8Yon8Ss6+wXFRwgArvXS3VEYRIokxtEQ6G2VL5qnk6O6dinBysCfswxgKAbsBQoU
# WMMN+8/QalemWDlrpQ3mYo6V0y+510WMLN2qwl+ayFz3IJiZrNqxeY5+A0RR2YA1
# r5WeG+lSbLtWPCCdWJiRrN/m7gT+9ZKbOtFw+utjHNZuln5k79PUbmREgy9Z8FuO
# jzSRCV0Mo40WmlituyuElmj3jNbD8IENWxvrTYJF8EQYNOCUMY5nwgDVIfo=
# SIG # End signature block
