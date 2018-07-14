[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions


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


<#
    .SYNOPSIS
        This function decrypts a String, an Array of Strings, a File, or Files in a Directory that were encrypted using the
        New-EncryptedFile function.

    .DESCRIPTION
        See SYNOPSIS.

    .NOTES
        IMPORTANT NOTES:
        This function identifies a file as RSA encrypted or AES encrypted according to the file's extension. For example,
        a file with an extension ".rsaencrypted" is identified as encrypted via RSA. A file with an extension ".aesencrypted"
        is identified as encrypted via AES. If the file(s) you intend to decrypt do not have either of these file extensions,
        or if you are decrypting a String or ArrayOfStrings in an interactive PowerShell Session, then you can use the
        -TypeOfEncryptionUsed parameter and specify either "RSA" or "AES".

        If the -TypeOfEncryptionUsed parameter is NOT used and -SourceType is "String" or "ArrayOfStrings", RSA decryption
        will be used.
        If the -TypeOfEncryptionUsed parameter is NOT used and -SourceType is "File", AES decryption will be used.
        If the -TypeOfEncryptionUsed parameter is NOT used and -SourceType is "Directory", both RSA and AES decryption will be
        attempted on each file.

    .PARAMETER SourceType
        Mandatory.

        This parameter takes a string with one of the following values:
            String
            ArrayOfStrings
            File
            Directory

        If -ContentToEncrypt is a string, -SourceType should be "String".
        If -ContentToEncrypt is an array of strings, -SourceType should be "ArrayOfStrings".
        If -ContentToEncrypt is a string that represents a full path to a file, -SourceType should be "File".
        If -ContentToEncrypt is a string that represents a full path to a directory, -SourceType should be "Directory".

    .PARAMETER ContentToDecrypt
        Mandatory.

        This parameter takes a string that is either:
            - A string
            - An array of strings
            - A string that represents a full path to a file
            - A string that represents a full path to a directory

    .PARAMETER Recurse
        Optional.

        This parameter is a switch. It should only be used if -SourceType is "Directory". The function will fail
        immediately if this parameter is used and -SourceType is NOT "Directory".

        If this switch is NOT used, only files immediately under the directory specified by -ContentToEncrypt are
        decrypted.

        If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
        all files within subdirectories under the directory specified by -ContentToEncrypt are decrypted.

    .PARAMETER FileToOutput
        Optional.

        This parameter specifies a full path to a NEW file that will contain decrypted information. This parameter should
        ONLY be used if -SourceType is "String" or "ArrayOfStrings". If this parameter is used and -SourceType is NOT
        "String" or "ArrayOfStrings", the function will immediately fail.

    .PARAMETER PathToPfxFile
        Optional. (However, either -PathToPfxFile or -CNOfCertInStore are required.)

        This parameter takes a string that represents the full path to a .pfx file that was used for encryption. The
        private key in the .pfx file will be used for decryption.

        NOTE: RSA decryption is ALWAYS used by this function, either to decrypt the information directly or to decrypt the
        AES Key that was used to encrypt the information originally so that it can be used in AES Decryption.

    .PARAMETER CNOfCertInStore
        Optional. (However, either -PathToPfxFile or -CNOfCertInStore are required.)

        This parameter takes a string that represents the Common Name (CN) of the certificate that was used for RSA
        encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My). The
        private key in the certificate will be used for decryption.

        NOTE: RSA decryption is ALWAYS used by this function, either to decrypt the information directly or to decrypt the
        AES Key that was used to encrypt the information originally so that it can be used in AES Decryption.

    .PARAMETER CertPwd
        Optional. (However, this parameter is mandatory if the certificate is password protected).

        This parameter takes a System.Security.SecureString that represents the password for the certificate.

        Use this parameter if the certificate is password protected.

    .PARAMETER TypeOfEncryptionUsed
        Optional.

        This parameter takes a string with value of either "RSA" or "AES".

        If you want to force this function to use a particular type of decryption, use this parameter.

        If this parameter is NOT used and -SourceType is "String" or "ArrayOfStrings", RSA decryption will be used.
        If this parameter is NOT used and -SourceType is "File", AES decryption will be used.
        If this parameter is NOT used and -SourceType is "Directory", both RSA and AES decryption will be attempted
        on each file.

    .PARAMETER AESKey
        Optional.

        This parameter takes a Base64 string that represents the AES Key used for AES Encryption. This same key will be used
        for AES Decryption.

    .PARAMETER AESKeyLocation
        Optional.

        This parameter takes a string that represents a full file path to a file that contains the AES Key originally used
        for encryption. 

        If the file extension ends with ".rsaencrypted", this function will use the specified Certificate
        (i.e. the certificate specified via -PathToPfxFile or -CNOfCertInStore parameters, specifically the private key
        contained therein) to decrypt the file, revealing the base64 string that represents the AES Key used for AES Encryption.

        If the file extension does NOT end with ".rsaencrypted", the function will assume that the the file contains the
        Base64 string that represents the AES key originally used for AES Encryption.

    .PARAMETER NoFileOutput
        Optional.

        This parameter is a switch. If you do NOT want decrypted information written to a file, use this parameter. The
        decrypted info will ONLY be written to console as part of the DecryptedContent Property of the PSCustomObject output.

    .PARAMETER TryRSADecryption
        Optional.

        This parameter is a switch. Use it to try RSA Decryption even if you provide -AESKey or -AESKeyLocation.

    .EXAMPLE
        # Decrypting an Encrypted String without File Outputs
        PS C:\Users\zeroadmin> $EncryptedStringTest = Get-Content C:\Users\zeroadmin\other\MySecret.txt.rsaencrypted
        PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType String -ContentToDecrypt $EncryptedStringTest -PathToPfxFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput

        Doing RSA Decryption

        DecryptedFiles                     :
        FailedToDecryptFiles               : {}
        CertUsedDuringDecryption           : [Subject]
                                            CN=ArrayOfStrings

                                            [Issuer]
                                            CN=ArrayOfStrings

                                            [Serial Number]
                                            32E38D18591854874EC467B73332EA76

                                            [Not Before]
                                            6/1/2017 4:13:36 PM

                                            [Not After]
                                            6/1/2018 4:33:36 PM

                                            [Thumbprint]
                                            C8CC2B8B03E33821A69B35F10B04D74E40A557B2

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\ArrayOfStrings.pfx
        LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
        UnprotectedAESKey                  :
        LocationOfAESKey                   :
        AllFileOutputs                     :
        DecryptedContent                   : THisISmYPWD321!

    .EXAMPLE
        # Decrypting an Array Of Strings without File Outputs
        PS C:\Users\zeroadmin> $enctext0 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt0.rsaencrypted
        PS C:\Users\zeroadmin> $enctext1 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt1.rsaencrypted
        PS C:\Users\zeroadmin> $enctext2 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt2.rsaencrypted
        PS C:\Users\zeroadmin> $enctextarray = @($enctext0,$enctext1,$enctext2)
        PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType ArrayOfStrings -ContentToDecrypt $enctextarray -PathToPfxFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput
        Doing RSA Decryption


        DecryptedFiles                     :
        FailedToDecryptFiles               : {}
        CertUsedDuringDecryption           : [Subject]
                                            CN=ArrayOfStrings

                                            [Issuer]
                                            CN=ArrayOfStrings

                                            [Serial Number]
                                            32E38D18591854874EC467B73332EA76

                                            [Not Before]
                                            6/1/2017 4:13:36 PM

                                            [Not After]
                                            6/1/2018 4:33:36 PM

                                            [Thumbprint]
                                            C8CC2B8B03E33821A69B35F10B04D74E40A557B2

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\ArrayOfStrings.pfx
        LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
        UnprotectedAESKey                  :
        LocationOfAESKey                   :
        AllFileOutputs                     :
        DecryptedContent                   : {fruit, vegetables, meat}

    .EXAMPLE
        # Decrypting a File
        PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType File -ContentToDecrypt C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        Doing AES Decryption


        DecryptedFiles                     : C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted
        FailedToDecryptFiles               : {}
        CertUsedDuringDecryption           : [Subject]
                                            CN=TempDirEncryption

                                            [Issuer]
                                            CN=TempDirEncryption

                                            [Serial Number]
                                            52711274E381F592437E8C18C7A3241C

                                            [Not Before]
                                            6/2/2017 10:57:26 AM

                                            [Not After]
                                            6/2/2018 11:17:26 AM

                                            [Thumbprint]
                                            F2EFEBB37C37844A230961447C7C91C1DE13F1A5

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\tempdir\PrivateKeyExtractionTempDir\TempDirEncryption.pfx
        LocationOfCertUsedDuringDecryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
        LocationOfAESKey                   : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\PrivateKeyExtractionTempDir\TempDirEncryption.pfx}
        DecryptedContent                   : {1914 translation by H. Rackham, , "But I must explain to you how all this mistaken idea of denouncing pleasure and
                                            praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the
                                            great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself,
                                            because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that
                                            are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is
                                            pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a
                                            trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But
                                            who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who
                                            avoids a pain that produces no resultant pleasure?", ...}

    .EXAMPLE
        # Decrypting All Files in a Directory
        PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType Directory -ContentToDecrypt C:\Users\zeroadmin\tempdir -Recurse -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        Doing AES Decryption
        WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\dolor.txt.original, verify this file was made using the included EncryptFile function.
        WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\dolor.txt.original failed...Will try RSA Decryption...
        WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted, verify this file was made using the included EncryptFile function.
        WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted failed...Will try RSA Decryption...
        WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original, verify this file was made using the included EncryptFile function.
        WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original failed...Will try RSA Decryption...


        DecryptedFiles                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted.decrypted}
        FailedToDecryptFiles               : {C:\Users\zeroadmin\tempdir\dolor.txt.original, C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original}
        CertUsedDuringDecryption           : [Subject]
                                            CN=TempDirEncryption

                                            [Issuer]
                                            CN=TempDirEncryption

                                            [Serial Number]
                                            52711274E381F592437E8C18C7A3241C

                                            [Not Before]
                                            6/2/2017 10:57:26 AM

                                            [Not After]
                                            6/2/2018 11:17:26 AM

                                            [Thumbprint]
                                            F2EFEBB37C37844A230961447C7C91C1DE13F1A5

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\TempDirEncryption.pfx
        LocationOfCertUsedDuringDecryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
        LocationOfAESKey                   : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted.decrypted,
                                            C:\Users\zeroadmin\PrivateKeyExtractionTempDir\TempDirEncryption.pfx}
        DecryptedContent                   : {1914 translation by H. Rackham, , "But I must explain to you how all this mistaken idea of denouncing pleasure and
                                            praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the
                                            great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself,
                                            because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that
                                            are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is
                                            pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a
                                            trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But
                                            who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who
                                            avoids a pain that produces no resultant pleasure?", ...}
#>
function Get-DecryptedContent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        [string]$SourceType,

        [Parameter(Mandatory=$True)]
        [string[]]$ContentToDecrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        [string]$FileToOutput,
        
        [Parameter(Mandatory=$False)]
        [ValidatePattern("\.pfx$")]
        [string]$PathToPfxFile,

        [Parameter(Mandatory=$False)]
        [string]$CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AES","RSA")]
        [string]$TypeOfEncryptionUsed,

        [Parameter(Mandatory=$False)]
        [string]$AESKey,

        [Parameter(Mandatory=$False)]
        [string]$AESKeyLocation,

        [Parameter(Mandatory=$False)]
        [switch]$NoFileOutput,

        [Parameter(Mandatory=$False)]
        [switch]$TryRSADecryption
    )

    ##### BEGIN Parameter Validation #####

    if ($SourceType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        $NewFileName = NewUniqueString -PossibleNewUniqueString "DecryptedOutput" -ArrayOfStrings $(Get-ChildItem $(Get-Location).Path -File).BaseName
        $FileToOutput = $(Get-Location).Path + '\' + $NewFileName + ".decrypted"
    }
    if ($SourceType -eq "File" -and $FileToOutput) {
        $ErrMsg = "The parameter -FileToOutput should NOT be used when -SourceType is 'File' or 'Directory'. "
        "Simply use '-SourceType File' or '-SourceType Directory' and the naming convention for the output file "
        " will be handled automatically by the $($MyInvocation.MyCommand.Name) function. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $SourceType -ne "Directory") {
        Write-Error "The -Recurse switch should only be used when -SourceType is 'Directory'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
    $RegexFilePath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'
    # NOTE: The below Linux Regex representations are simply commonly used naming conventions - they are not
    # strict definitions of Linux File or Directory Path formats
    $LinuxRegexFilePath = '^((~)|(\/[\w^ ]+))+\/?([\w.])+[^.]$'
    $LinuxRegexDirectoryPath = '^((~)|(\/[\w^ ]+))+\/?$'
    if ($SourceType -eq "File" -and $ContentToDecrypt -notmatch $RegexFilePath -and
    $ContentToDecrypt -notmatch $LinuxRegexFilePath
    ) {
        $ErrMsg = "The -SourceType specified was 'File' but '$ContentToDecrypt' does not appear to " +
        "be a valid file path. This is either because a full path was not provided or because the file does " +
        "not have a file extenstion. Please correct and try again. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory" -and $ContentToDecrypt -notmatch $RegexDirectoryPath -and
    $ContentToDecrypt -notmatch $LinuxRegexDirectoryPath
    ) {
        $ErrMsg = "The -SourceType specified was 'Directory' but '$ContentToDecrypt' does not appear to be " +
        "a valid directory path. This is either because a full path was not provided or because the directory " +
        "name ends with something that appears to be a file extension. Please correct and try again. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($SourceType -eq "File" -and !$(Test-Path $ContentToDecrypt)) {
        Write-Error "The path '$ContentToDecrypt' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory" -and !$(Test-Path $ContentToDecrypt)) {
        Write-Error "The path '$ContentToDecrypt' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Path $ContentToDecrypt -Recurse -File
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Path $ContentToDecrypt -File
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Error "No files were found in the directory '$ContentToDecrypt'. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($FileToOutput) {
        $FileToOutputDirectory = $FileToOutput | Split-Path -Parent
        $FileToOutputFile = $FileToOutput | Split-Path -Leaf
        $FileToOutputFileSansExt = $($FileToOutputFile.Split("."))[0]
        if (!$(Test-Path $FileToOutputDirectory)) {
            Write-Error "The directory $FileToOutputDirectory does not exist. Please check the path. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Gather the Cert Used For RSA Decryption and the AES Key (if necessary)
    if ($PathToPfxFile -and $CNofCertInStore) {
        $ErrMsg = "Please use *either* -PathToPfxFile *or* -CNOfCertInStore. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if (!$PathToPfxFile -and !$CNofCertInStore) {
        Write-Error "You must use either the -PathToPfxFile or the -CNofCertInStore parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Validate PathToPfxFile
    if ($PathToPfxFile) { 
        if (!$(Test-Path $PathToPfxFile)) {
            Write-Error "The path '$PathToPfxFile'was not found at the path specified. Halting."
            $global:FunctionResult = "1"
            return
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToPfxFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Warning "Either the Private Key in '$PathToPfxFile' is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate. If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToPfxFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                $ErrMsg = "Either the password supplied for the Private Key in $PathToPfxFile' is " +
                "incorrect or it is not marked as Exportable! Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }
        }
    }
    
    # Validate CNofCertInStore {
    if ($CNofCertInStore) {
        [array]$Cert1 = @(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore,"})

        if ($Cert1.Count -gt 1) {
            Write-Warning "Multiple certificates under 'Cert:\LocalMachine\My' with a CommonName '$CNofCertInStore' have been identified! They are as follows:"
            for ($i=0; $i -lt $Cert1.Count; $i++) {
                Write-Host "$i) " + "Subject: " + $Cert1[$i].Subject + ' | Thumbprint: ' + $Cert1[$i].Thumbprint
            }
            $ValidChoiceNumbers = 0..$($Cert1.Count-1)
            $CertChoicePrompt = "Please enter the number that corresponds to the Certificate that you " +
            "would like to use. [0..$($Cert1.Count-1)]"
            $CertChoice = Read-Host -Prompt $CertChoicePrompt
            while ($ValidChoiceNumbers -notcontains $CertChoice) {
                Write-Host "'$CertChoice' is not a valid choice number! Valid choice numbers are $($ValidChoiceNumbers -join ",")"
                $CertChoice = Read-Host -Prompt $CertChoicePrompt
            }
            
            $Cert1 = $Cert1[$CertChoice]
        }
        if ($Cert1.Count -lt 1) {
            Write-Error "Unable to find a a certificate matching CN=$CNofCertInStore in 'Cert:\LocalMachine\My'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($Cert1.Count -eq 1) {
            $Cert1 = $Cert1[0]
        }
    }

    # Make sure we have the Private Key
    if ($Cert1.PrivateKey -eq $null -and $Cert1.HasPrivateKey -eq $True) {
        try {
            $ContentToDecryptParentDirTest = $ContentToDecrypt | Split-Path -Parent
            $TempOutputDirPrep = $(Resolve-Path $ContentToDecryptParentDirTest -ErrorAction SilentlyContinue).Path
            if (!$TempOutputDirPrep) {
                throw
            }
        }
        catch {
            if ($NoFileOutput) {
                $TempOutputDirPrep = $(Get-Location).Path
            }
            else {
                $TempOutputDirPrep = $FileToOutput | Split-Path -Parent
            }
        }

        $PrivKeyTempDirName = NewUniqueString -PossibleNewUniqueString "PrivateKeyExtractionTempDir" -ArrayOfStrings $(Get-ChildItem -Path $TempOutputDirPrep -Directory).BaseName
        $TempOutputDir = "$TempOutputDirPrep\$PrivKeyTempDirName"
        $null = New-Item -Type Directory -Path $TempOutputDir
        
        if ($CertPwd) {
            $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert1 -TempOutputDirectory $TempOutputDir -CertPwd $CertPwd -DownloadAndAddOpenSSLToPath
        }
        else {
            $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert1 -TempOutputDirectory $TempOutputDir -DownloadAndAddOpenSSLToPath
        }
        
        if ($PrivateKeyInfo.KeySize -eq $null) {
            Write-Error "Failed to get Private Key Info from $($Cert1.Subject) ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($Cert1.PrivateKey -eq $null -and $Cert1.HasPrivateKey -eq $False) {
        Write-Error "There is no private key available for the certificate $($Cert1.Subject)! We need the private key to decrypt the file! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Figure out if we need an AES key. If so, get it.
    if ($($TypeOfEncryptionUsed -eq "AES" -or $ContentToDecrypt -match "\.aesencrypted" -or $AESKey -or $AESKeyLocation) -or
    $($SourceType -eq "Directory" -and $TypeOfEncryptionUsed -ne "RSA" -and !$TryRSADecryption)
    ) {
        $NeedAES = $True
    }
    else {
        $NeedAES = $False
    }
    
    if ($NeedAES) {
        if (!$AESKey -and !$AESKeyLocation) {
            $ErrMsg = "The $($MyInvocation.MyCommand.Name) function has determined that either the -AESKey " +
            "parameter or the -AESKeyLocation parameter is needed in order to decrypt the specified content! Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
        if ($AESKeyLocation) {
            if (!$(Test-Path $AESKeyLocation)) {
                Write-Verbose "The path $AESKeyLocation was not found! Halting!"
                Write-Error "The path $AESKeyLocation was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($(Get-ChildItem $AESKeyLocation).Extension -eq ".rsaencrypted") {
                $EncryptedBase64String = Get-Content $AESKeyLocation
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedBase64String)
                #$EncryptedBytes2 = [System.IO.File]::ReadAllBytes($AESKeyLocation)
                try {
                    if ($PrivateKeyInfo) {
                        #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    else {
                        #$DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                }
                catch {
                    try {
                        if ($PrivateKeyInfo) {
                            #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                            $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                        }
                        else {
                            #$DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, $true)
                            $DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                        }
                    }
                    catch {
                        Write-Error "Problem decrypting the file that contains the AES Key (i.e. '$AESKeyLocation')! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                
                if ($PSVersionTable.PSEdition -eq "Core") {
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                }
                else {
                    $DecryptedContent2 = [system.text.encoding]::Unicode.GetString($DecryptedBytes2)
                }

                # Need to write $DecryptedContent2 to tempfile to strip BOM if present
                $tmpFile = [IO.Path]::GetTempFileName()
                $null = [System.IO.File]::WriteAllLines($tmpFile, $DecryptedContent2.Trim())
                $AESKey = Get-Content $tmpFile
                $null = Remove-Item $tmpFile -Force
            }
            # If the $AESKeyLocation file extension is not .rsaencrypted, assume it's the unprotected AESKey
            if ($(Get-ChildItem $AESKeyLocation).Extension -ne ".rsaencrypted"){
                $AESKey = Get-Content $AESKeyLocation
            }
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####

    [System.Collections.ArrayList]$DecryptedFiles = @()
    [System.Collections.ArrayList]$FailedToDecryptFiles = @()
    # Do RSA Decryption on $ContentToDecrypt
    if ($TypeOfEncryptionUsed -ne "AES" -or $TryRSADecryption) {
        #Write-Host "Doing RSA Decryption"
        if ($SourceType -eq "String" -or $SourceType -eq "File") {
            if ($SourceType -eq "String") {
                $EncryptedString2 = $ContentToDecrypt
                $OutputFile = if ($FileToOutput -match "\.decrypted$") {
                    $FileToOutput
                }
                else {
                    "$FileToOutput.decrypted"
                }
            }
            if ($SourceType -eq "File") {
                $EncryptedString2 = Get-Content $ContentToDecrypt
                $OutputFile = if ($ContentToDecrypt -match "\.decrypted$") {
                    $ContentToDecrypt
                }
                else {
                    "$ContentToDecrypt.decrypted"
                }
            }

            try {
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                if ($PrivateKeyInfo) {
                    #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                    $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                }
                else {
                    #$DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    $DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                }
                $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                $DecryptedContent2 = $DecryptedContent2.Trim()
                # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                $null = [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                $null = $DecryptedFiles.Add($OutputFile)
            }
            catch {
                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                    if ($PrivateKeyInfo) {
                        #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                    }
                    else {
                        #$DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                    }
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    $null = [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $null = $DecryptedFiles.Add($OutputFile)
                }
                catch {
                    #Write-Error $_
                    $null = $FailedToDecryptFiles.Add($OutputFile)
                }
            }
        }
        if ($SourceType -eq "ArrayOfStrings") {
            $ArrayOfEncryptedStrings = $ContentToDecrypt

            for ($i=0; $i -lt $ArrayOfEncryptedStrings.Count; $i++) {
                $OutputFile = if ($FileToOutput -match "\.decrypted$") {
                    $FileToOutput -replace "\.decrypted$","$i.decrypted"
                }
                else {
                    "$FileToOutput$i.decrypted"
                }

                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($ArrayOfEncryptedStrings[$i])
                    if ($PrivateKeyInfo) {
                        #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    else {
                        #$DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    $null = [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $null = $DecryptedFiles.Add($OutputFile)
                }
                catch {
                    try {
                        $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                        if ($PrivateKeyInfo) {
                            #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                            $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                        }
                        else {
                            #$DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, $true)
                            $DecryptedBytes2 = $Cert1.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                        }
                        $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                        $DecryptedContent2 = $DecryptedContent2.Trim()
                        # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                        $null = [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)
    
                        $null = $DecryptedFiles.Add($OutputFile)
                    }
                    catch {
                        #Write-Error $_
                        $null = $FailedToDecryptFiles.Add($OutputFile)
                    }
                }
            }
        }
        if ($SourceType -eq "Directory") {
            if ($Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Path $ContentToDecrypt -Recurse -File | Where-Object {
                    $_.FullName -notmatch [regex]::Escape($(Get-Item $PathToPfxFile).BaseName) -and
                    $_.FullName -notmatch "\.aeskey" -and
                    $_.FullName -notmatch "\.decrypted$"
                }).FullName
            }
            if (!$Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Path $ContentToDecrypt -File | Where-Object {
                    $_.FullName -notmatch [regex]::Escape($(Get-Item $PathToPfxFile).BaseName) -and
                    $_.FullName -notmatch "\.aeskey" -and
                    $_.FullName -notmatch "\.decrypted$"
                }).FullName
            }

            foreach ($file in $DecryptionCandidates) {
                try {
                    $FileExtenstion = $(Get-Item $file -ErrorAction Stop).Extension
                }
                catch {
                    continue
                }

                try {
                    $GetDecryptSplatParams = @{
                        SourceType          = "File"
                        ContentToDecrypt    = $file
                        PathToPfxFile       = $PathToPfxFile
                        TryRSADecryption    = $True
                        ErrorAction         = "Stop"
                    }
                    $DecryptInfo = Get-DecryptedContent @GetDecryptSplatParams
                    $OutputFile = $DecryptInfo.DecryptedFiles

                    if ($OutputFile) {
                        $null = $DecryptedFiles.Add($OutputFile)
                        $null = Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    #Write-Error $_
                    $null = $FailedToDecryptFiles.Add($file)
                }
            }
        }
    }

    # Do AES Decryption on $ContentToDecrypt
    if ($TypeOfEncryptionUsed -eq "AES" -or $NeedAES) {
        #Write-Host "Doing AES Decryption"
        if ($SourceType -eq "String" -or $SourceType -eq "File") {
            if ($SourceType -eq "String") {
                # Temporarily write the string to a file
                $tmpFile = [IO.Path]::GetTempFileName()
                $tmpFileRenamed = "$tmpFile.aesencrypted"
                $null = [System.IO.File]::WriteAllLines($tmpfileRenamed, $ContentToDecrypt)

                try {
                    $FileDecryptionInfo = DecryptFile $tmpFileRenamed -Key $AESKey -ErrorAction Stop
                    # Now we're left with a file $tmpFile containing decrypted info. Move it to $FileToOutput
                    $null = Move-Item -Path $tmpFile -Destination $FileToOutput

                    $null = $DecryptedFiles.Add($FileToOutput)
                }
                catch {
                    #Write-Error $_
                    $null = $FailedToDecryptFiles.Add($FileToOutput)
                }
            }
            if ($SourceType -eq "File") {
                try {
                    $FileDecryptionInfo = DecryptFile $ContentToDecrypt -Key $AESKey -ErrorAction Stop
                    $null = $DecryptedFiles.Add("$ContentToDecrypt.decrypted")
                }
                catch {
                    #Write-Error $_
                    $null = $FailedToDecryptFiles.Add($ContentToDecrypt)
                }
                
            }
        }
        if ($SourceType -eq "ArrayOfStrings") {
            $ArrayOfEncryptedStrings = $ContentToDecrypt

            for ($i=0; $i -lt $ArrayOfEncryptedStrings.Count; $i++) {
                $OutputFile = "$FileToOutput$i"

                # Temporarily write the string to a file
                $tmpFile = [IO.Path]::GetTempFileName()
                $tmpFileRenamed = "$tmpFile.aesencrypted"
                $null = [System.IO.File]::WriteAllLines($tmpfileRenamed, $ArrayOfEncryptedStrings[$i])

                try {
                    $FileDecryptionInfo = DecryptFile $tmpFileRenamed -Key $AESKey -ErrorAction Stop
                    # Now we're left with a file $tmpFile containing decrypted info. Copy it to $FileToOutput
                    Move-Item -Path $tmpFile -Destination $OutputFile

                    $null = $DecryptedFiles.Add($OutputFile)
                }
                catch {
                    #Write-Error $_
                    $null = $FailedToDecryptFiles.Add($OutputFile)
                }
            }
        }
        if ($SourceType -eq "Directory") {
            if ($Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Path $ContentToDecrypt -Recurse -File | Where-Object {
                    $_.FullName -notmatch [regex]::Escape($(Get-Item $PathToPfxFile).BaseName) -and
                    $_.FullName -notmatch "\.aeskey" -and
                    $_.FullName -notmatch "\.decrypted$"

                }).FullName
            }
            if (!$Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Path $ContentToDecrypt -File | Where-Object {
                    $_.FullName -notmatch [regex]::Escape($(Get-Item $PathToPfxFile).BaseName) -and
                    $_.FullName -notmatch "\.aeskey" -and
                    $_.FullName -notmatch "\.decrypted$"
                }).FullName
            }

            foreach ($file in $DecryptionCandidates) {
                try {
                    $FileExtenstion = $(Get-Item $file -ErrorAction Stop).Extension
                }
                catch {
                    continue
                }
                
                try {
                    $GetDecryptSplatParams = @{
                        SourceType          = "File"
                        ContentToDecrypt    = $file
                        PathToPfxFile       = $PathToPfxFile
                        AESKey              = $AESKey
                        TryRSADecryption    = $True
                        ErrorAction         = "Stop"
                    }
                    $DecryptInfo = Get-DecryptedContent @GetDecryptSplatParams
                    $OutputFile = $DecryptInfo.DecryptedFiles

                    if ($OutputFile) {
                        $null = $DecryptedFiles.Add($OutputFile)
                    }
                }
                catch {
                    #Write-Error $_
                    $null = $FailedToDecryptFiles.Add($OutputFile)
                }
            }
        }
    }

    # Output
    if ($PrivateKeyInfo) {
        $CertName = $($Cert1.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        $PFXCertUsedForPrivateKeyExtraction = "$TempOutputDir\$CertName.pfx"
    }

    $AllFileOutputsPrep = $DecryptedFiles,$PFXCertUsedForPrivateKeyExtraction
    $AllFileOutputs = foreach ($element in $AllFileOutputsPrep) {if ($element -ne $null) {$element}}

    $FinalFailedToDecryptFiles = foreach ($FullPath in $FailedToDecryptFiles) {
        if ($DecryptedFiles -notcontains "$FullPath.decrypted") {
            $FullPath
        }
    }

    [pscustomobject]@{
        DecryptedFiles                          = $(if ($NoFileOutput) {$null} else {$DecryptedFiles})
        FailedToDecryptFiles                    = $FinalFailedToDecryptFiles
        CertUsedDuringDecryption                = $Cert1
        PFXCertUsedForPrivateKeyExtraction      = $PFXCertUsedForPrivateKeyExtraction
        LocationOfCertUsedDuringDecryption      = $(if ($PathToPfxFile) {$PathToPfxFile} else {"Cert:\LocalMachine\My"})
        UnprotectedAESKey                       = $AESKey
        LocationOfAESKey                        = $AESKeyLocation
        AllFileOutputs                          = $(if ($NoFileOutput) {$null} else {$AllFileOutputs})
        DecryptedContent                        = $(foreach ($file in $DecryptedFiles) {Get-Content $file})
    }

    # Cleanup
    if ($NoFileOutput) {
        foreach ($item in $DecryptedFiles) {
            $null = Remove-Item $item -Force
        }
        if ($TempOutputDir) {
            $null = Remove-Item -Recurse $TempOutputDir -Force
        }
    }

    ##### END Main Body #####
    $global:FunctionResult = "0"
}


<#
    .SYNOPSIS
        This function creates a New Self-Signed Certificate meant to be used for DSC secret encryption and exports it to the
        specified directory.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER CommonName
        This parameter is MANDATORY.

        This parameter takes a string that represents the desired Common Name for the Self-Signed Certificate.

    .PARAMETER ExportDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to a directory that will contain the new Self-Signed Certificate.

    .EXAMPLE
        # Import the MiniLab Module and -

        PS C:\Users\zeroadmin> Get-EncryptionCert -CommonName "EncryptionCert" -ExportDirectory "$HOME\EncryptionCerts"

#>
function Get-EncryptionCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$CommonName,

        [Parameter(Mandatory=$True)]
        [string]$ExportDirectory
    )

    if (!$(Test-Path $ExportDirectory)) {
        Write-Error "The path '$ExportDirectory' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CertificateFriendlyName = $CommonName
    $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.FriendlyName -eq $CertificateFriendlyName
    } | Select-Object -First 1

    if (!$Cert) {
        $NewSelfSignedCertExSplatParams = @{
            Subject             = "CN=$CommonName"
            EKU                 = @('1.3.6.1.4.1.311.80.1','1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            KeyUsage            = 'DigitalSignature, KeyEncipherment, DataEncipherment'
            SAN                 = $CommonName
            FriendlyName        = $CertificateFriendlyName
            Exportable          = $True
            StoreLocation       = 'LocalMachine'
            StoreName           = 'My'
            KeyLength           = 2048
            ProviderName        = 'Microsoft Enhanced Cryptographic Provider v1.0'
            AlgorithmName       = "RSA"
            SignatureAlgorithm  = "SHA256"
        }

        New-SelfsignedCertificateEx @NewSelfSignedCertExSplatParams

        # There is a slight delay before new cert shows up in Cert:
        # So wait for it to show.
        while (!$Cert) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}
        }
    }

    #$null = Export-Certificate -Type CERT -Cert $Cert -FilePath "$ExportDirectory\$CommonName.cer"
    [System.IO.File]::WriteAllBytes("$ExportDirectory\$CommonName.cer", $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    [pscustomobject]@{
        CertFile        = Get-Item "$ExportDirectory\$CommonName.cer"
        CertInfo        = $Cert
    }
}


<#
    .SYNOPSIS
        Adds -Password parameter to the existing Get-PFXCertificate cmdlet in order to avoid prompt in the event
        that a password is needed.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER FilePath
        This parameter is MANDATORY.

    .PARAMETER LiteralPath
        This parameter is MANDATORY.

    .PARAMETER Password
        This parameter is OPTIONAL.

    .PARAMETER x509KeyStorageFlag
        This parameter is OPTIONAL (however, it has a default value of 'DefaultKeySet')

    .EXAMPLE
        # Import the MiniLab Module and -

        PS C:\Users\zeroadmin> Get-PfxCertificateBetter -Password "PlainTextPwd" -FilePath "$HOME\test.pfx"

#>
function Get-PfxCertificateBetter {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Position=0, Mandatory=$true, ParameterSetName='ByPath')]
        [string[]]$FilePath,

        [Parameter(Mandatory=$true, ParameterSetName='ByLiteralPath')]
        [string[]]$LiteralPath,

        [Parameter(Position=1, ParameterSetName='ByPath')] 
        [Parameter(Position=1, ParameterSetName='ByLiteralPath')]
        [string]$Password,

        [Parameter(Position=2, ParameterSetName='ByPath')]
        [Parameter(Position=2, ParameterSetName='ByLiteralPath')] 
        [ValidateSet('DefaultKeySet','Exportable','MachineKeySet','PersistKeySet','UserKeySet','UserProtected')]
        [string]$x509KeyStorageFlag = 'DefaultKeySet'
    )

    if($PsCmdlet.ParameterSetName -eq 'ByPath'){
        $literalPath = Resolve-Path $filePath 
    }

    if(!$Password){
        # if the password parameter isn't present, just use the original cmdlet
        $cert = Get-PfxCertificate -LiteralPath $literalPath
    } else {
        # otherwise use the .NET implementation
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($literalPath, $Password, $X509KeyStorageFlag)
    }

    return $cert
}


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


<#
    .SYNOPSIS
        This function can encrypt a String, Array of Strings, File, or Files in a Directory. Strings and Arrays of Strings passed
        to the -ContentToEncrypt parameter are written to their own separate encrypted files on the file system. Encrypting one or
        more Files creates a NEW encrypted version of the original File(s). It DOES NOT TOUCH the original unencrypted File(s).

    .DESCRIPTION
        See SYNOPSIS.

    .NOTES
        Please use this function responsibly.

        IMPORTANT NOTE #1:
        The Certificate used for RSA Encryption is written out (in .pfx format) to the same directory as the encrypted
        file outputs. If AES encryption is needed for larger Files, the RSA-encrypted AES Key is written to the same directory
        as the encrypted file outputs.

        You will ALWAYS need a private key from your Certificate's public/private pair in order to decrypt content
        encrypted via this function. You will be able to get this private key from the .pfx file that you provide
        to the -PathToPfxFile parameter, or from the Certificate in the Cert:\LocalMachine\My store that you provide
        to the -CNofCertInStore parameter of this function.

        You will SOMETIMES need the AES Key to decrypt larger files that were encrypted using AES encryption.

        IMPORTANT NOTE #2:
        It is up to you to store the public/private key pair and the RSA-encrypted AES Key appropriately.

        Note that the public/private key pair will be found EITHER in a .pfx file in the same directory as encrypted
        file outputs OR in Cert:\LocalMachine\My OR in BOTH locations. Note that the RSA-encrypted AES Key will be
        found in a file in the same directory as encrypted file outputs.

    .PARAMETER SourceType
        Optional, but HIGHLY recommended.

        This parameter takes a string with one of the following values:
            String
            ArrayOfStrings
            File
            Directory

        If -ContentToEncrypt is a string, -SourceType should be "String".
        If -ContentToEncrypt is an array of strings, -SourceType should be "ArrayOfStrings".
        If -ContentToEncrypt is a string that represents a full path to a file, -SourceType should be "File".
        If -ContentToEncrypt is a string that represents a full path to a directory, -SourceType should be "Directory".

    .PARAMETER ContentToEncrypt
        Mandatory.

        This parameter takes a string that is either:
            - A string
            - An array of strings
            - A string that represents a full path to a file
            - A string that represents a full path to a directory

    .PARAMETER Recurse
        Optional.

        This parameter is a switch. It should only be used if -SourceType is "Directory". The function will fail
        immediately if this parameter is used and -SourceType is NOT "Directory".

        If this switch is NOT used, only files immediately under the directory specified by -ContentToEncrypt are
        encrypted.

        If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
        all files within subdirectories under the directory specified by -ContentToEncrypt are encrypted.

    .PARAMETER FileToOutput
        Optional.

        This parameter specifies a full path to a NEW file that will contain encrypted information. This parameter should
        ONLY be used if -SourceType is "String" or "ArrayOfStrings". If this parameter is used and -SourceType is NOT
        "String" or "ArrayOfStrings", the function will immediately fail.

    .PARAMETER PathToPfxFile
        Optional.

        This parameter takes a string that represents the full path to a .pfx file. The public certificate in
        the .pfx file will be used for RSA encryption.

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CNOfCertInStore
        Optional.

        This parameter takes a string that represents the Common Name (CN) of the public certificate used for RSA
        encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My).

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CNOfNewCert
        Optional.

        This parameter takes a string that represents the desired Common Name (CN) for the new Self-Signed
        Certificate.

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CertPwd
        Optional. (However, this parameter is mandatory if the certificate is password protected).

        This parameter takes a System.Security.SecureString that represents the password for the certificate.

        Use this parameter if the certificate is password protected.

    .PARAMETER RemoveOriginalFile
        Optional.

        This parameter is a switch. By default, original unencrypted files are not touched. Use this switch to remove
        the original unencrypted files.

    .EXAMPLE
        # String Encryption Example
        # NOTE: If neither -PathToPfxFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
        # created and added to Cert:\LocalMachine\My

        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType String -ContentToEncrypt "MyPLaInTeXTPwd321!" -FileToOutput $HOME\MyPwd.txt

        FileEncryptedViaRSA                : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted
        FileEncryptedViaAES                :
        OriginalFile                       :
        CertficateUsedForRSAEncryption     : [Subject]
                                            CN=MyPwd

                                            [Issuer]
                                            CN=MyPwd

                                            [Serial Number]
                                            6BD1BF9FACE6F0BB4EFFC31597E9B970

                                            [Not Before]
                                            6/2/2017 10:39:31 AM

                                            [Not After]
                                            6/2/2018 10:59:31 AM

                                            [Thumbprint]
                                            34F3526E85C04CEDC79F26C2B086E52CF75F91C3

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\34F3526E85C04CEDC79F26C2B086E52CF75F91C3
        UnprotectedAESKey                  :
        RSAEncryptedAESKey                 :
        RSAEncryptedAESKeyLocation         :
        AllFileOutputs                     : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted 

    .EXAMPLE
        # ArrayOfStrings Encryption Example
        PS C:\Users\zeroadmin> $foodarray = @("fruit","vegetables","meat")
        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType ArrayOfStrings -ContentToEncrypt $foodarray -PathToPfxFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -FileToOutput $HOME\Food.txt

        FilesEncryptedViaRSA               : {C:\Users\zeroadmin\Food.txt0.rsaencrypted, C:\Users\zeroadmin\Food.txt1.rsaencrypted,
                                            C:\Users\zeroadmin\Food.txt2.rsaencrypted}
        FilesEncryptedViaAES               :
        OriginalFiles                      :
        CertficateUsedForRSAEncryption     : [Subject]
                                            CN=ArrayOfStrings

                                            [Issuer]
                                            CN=ArrayOfStrings

                                            [Serial Number]
                                            32E38D18591854874EC467B73332EA76

                                            [Not Before]
                                            6/1/2017 4:13:36 PM

                                            [Not After]
                                            6/1/2018 4:33:36 PM

                                            [Thumbprint]
                                            C8CC2B8B03E33821A69B35F10B04D74E40A557B2

        LocationOfCertUsedForRSAEncryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
        UnprotectedAESKey                  :
        RSAEncryptedAESKey                 :
        RSAEncryptedAESKeyLocation         :
        AllFileOutputs                     : {C:\Users\zeroadmin\Food.txt0.rsaencrypted, C:\Users\zeroadmin\Food.txt1.rsaencrypted,
                                            C:\Users\zeroadmin\Food.txt2.rsaencrypted}

    .EXAMPLE
        # File Encryption Example
        PS C:\Users\zeroadmin> $ZeroTestPwd = Read-Host -Prompt "Enter password for ZeroTest Cert" -AsSecureString
        Enter password for ZeroTest Cert: ***********************
        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType File -ContentToEncrypt C:\Users\zeroadmin\tempdir\lorumipsum.txt -CNofCertInStore "ZeroTest" -CertPwd $ZeroTestPwd

        FileEncryptedViaRSA                :
        FileEncryptedViaAES                : C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted
        OriginalFile                       : C:\Users\zeroadmin\tempdir\lorumipsum.txt.original
        CertficateUsedForRSAEncryption     : [Subject]
                                            CN=ZeroTesting.zero.lab

                                            [Issuer]
                                            <redacted>

                                            [Serial Number]
                                            <redacted>

                                            [Not Before]
                                            <redacted>

                                            [Not After]
                                            <redacted>

                                            [Thumbprint]
                                            34F3526E85C04CEDC79F26C2B086E52CF75F91C3

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\34F3526E85C04CEDC79F26C2B086E52CF75F91C3
        UnprotectedAESKey                  : E0588dE3siWEOAyM7A5+6LKqC5tG1egxXTfsUUE5sNM=
        RSAEncryptedAESKey                 : NkKjOwd8T45u1Hpn0CL9m5zD/97PG9GNnJCShh0vOUTn+m+E2nLFxuW7ChKiHCVtP1vD2z+ckW3kk1va3PAfjw3/hfm9zi2qn4Xu7kPdWL1owDdQyvBuUPTc35
                                            FSqaIJxxdsqWLnUHo1PINY+2usIPT5tf57TbTKbAg5q/RXOzCeUS+QQ+nOKMgQGnadlUVyyIYo2JRdzzKaTSHRwK4QFdDk/PUy39ei2FVOIlwitiAkWTyjFAb6
                                            x+kMCgOVDuALGOyVVBdNe+BDrrWgqnfRSCHSZoQKfnkA0dj0tuE2coYNwGQ6SVUmiDrdklBrnKl69cIFf8lkTSsUqGdq9bbaag==
        RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\lorumipsum.txt.original,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted}

    .EXAMPLE
        # Directory Encryption Example
        # NOTE: If neither -PathToPfxFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
        # created and added to Cert:\LocalMachine\My

        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType Directory -ContentToEncrypt C:\Users\zeroadmin\tempdir
        Please enter the desired CN for the new Self-Signed Certificate: TempDirEncryption


        FilesEncryptedViaRSA               :
        FilesEncryptedViaAES               : {C:\Users\zeroadmin\tempdir\agricola.txt.aesencrypted, C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted}
        OriginalFiles                      : {C:\Users\zeroadmin\tempdir\agricola.txt.original, C:\Users\zeroadmin\tempdir\dolor.txt.original,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.txt.original}
        CertficateUsedForRSAEncryption     : [Subject]
                                            CN=TempDirEncryption

                                            [Issuer]
                                            CN=TempDirEncryption

                                            [Serial Number]
                                            52711274E381F592437E8C18C7A3241C

                                            [Not Before]
                                            6/2/2017 10:57:26 AM

                                            [Not After]
                                            6/2/2018 11:17:26 AM

                                            [Thumbprint]
                                            F2EFEBB37C37844A230961447C7C91C1DE13F1A5

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\F2EFEBB37C37844A230961447C7C91C1DE13F1A5
        UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
        RSAEncryptedAESKey                 : sUshzhMfrbO5FgOGw1Nsx9g5hrnsdUHsJdx8SltK8UeNcCWq8Rsk6dxC12NjrxUSHTSrPYdn5UycBqXB+PNltMebAj80I3Zsh5xRsSbVRSS+fzgGJTUw7ya98J
                                            7vKISUaurBTK4C4Czh1D2bgT7LNADO7qAUgbnv+xdqxgIexlOeNsEkzG10Tl+DxkUVgcpJYbznoTXPUVnj9AZkcczRd2EWPcV/WZnTZwmtH+Ill7wbXSG3R95d
                                            dbQLZfO0eOoBB/DAYWcPkifxJf+20s25xA8MKl7pNpDUbVhGhp61VCaaEqr6QlgihtluqWZeRgHEY3xSzz/UVHhzjCc6Rs9aPw==
        RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\agricola.txt.aesencrypted, C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\agricola.txt.original...}
#>
function New-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        [string]$SourceType,

        [Parameter(Mandatory=$True)]
        [string[]]$ContentToEncrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        [string]$FileToOutput,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\.pfx$")]
        [string]$PathToPfxFile,

        [Parameter(Mandatory=$False)]
        [string]$CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [string]$CNOfNewCert,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveOriginalFile
    )

    ##### BEGIN Parameter Validation #####

    if ($SourceType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        $FileToOutput = Read-Host -Prompt "Please enter the full path to the new Encrypted File you would like to generate."
    }
    if ($SourceType -eq "File" -or $SourceType -eq "Directory" -and $FileToOutput) {
        $ErrMsg = "The -FileToOutput should NOT be used when -SourceType is 'File' or 'Directory'. " +
        "Simply use '-SourceType File' or '-SourceType Directory' and output naming convention will be " +
        "handled automatically by the New-EncryptedFile function. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $SourceType -ne "Directory") {
        Write-Verbose "The -Recurse switch should only be used when -SourceType is 'Directory'! Halting!"
        Write-Error "The -Recurse switch should only be used when -SourceType is 'Directory'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($RemoveOriginalFile -and $SourceType -notmatch "File|Directory") {
        Write-Error "The -RemoveOriginalFile parameter should only be used when -SourceType is 'File' or 'Directory'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
    $RegexFilePath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'
    # NOTE: The below Linux Regex representations are simply commonly used naming conventions - they are not
    # strict definitions of Linux File or Directory Path formats
    $LinuxRegexFilePath = '^((~)|(\/[\w^ ]+))+\/?([\w.])+[^.]$'
    $LinuxRegexDirectoryPath = '^((~)|(\/[\w^ ]+))+\/?$'
    if ($SourceType -eq "File" -and $ContentToEncrypt -notmatch $RegexFilePath -and
    $ContentToDecrypt -notmatch $LinuxRegexFilePath
    ) {
        $ErrMsg = "The -SourceType specified was 'File' but '$ContentToEncrypt' does not appear to " +
        "be a valid file path. This is either because a full path was not provided or because the file does " +
        "not have a file extenstion. Please correct and try again. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory" -and $ContentToEncrypt -notmatch $RegexDirectoryPath -and
    $ContentToDecrypt -notmatch $LinuxRegexDirectoryPath
    ) {
        $ErrMsg = "The -SourceType specified was 'Directory' but '$ContentToEncrypt' does not appear to be " +
        "a valid directory path. This is either because a full path was not provided or because the directory " +
        "name ends with something that appears to be a file extension. Please correct and try again. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    
    if ($SourceType -eq "File" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Error "The path '$ContentToEncrypt' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Error "The path '$ContentToEncrypt' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Path $ContentToEncrypt -File -Recurse
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Path $ContentToEncrypt -File
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Error "No files were found in the directory '$ContentToEncrypt'. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($FileToOutput) {
        $FileToOutputDirectory = $FileToOutput | Split-Path -Parent
        $FileToOutputFile = $FileToOutput | Split-Path -Leaf
        $FileToOutputFileSansExt = $($FileToOutputFile.Split("."))[0]
        if (! $(Test-Path $FileToOutputDirectory)) {
            Write-Error "The directory '$FileToOutputDirectory' does not exist. Please check the path. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PathToPfxFile -and $CNofCertInStore) {
        $ErrMsg = "Please use *either* -PathToPfxFile *or* -CNOfCertInStore. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    # Validate PathToPfxFile
    if ($PathToPfxFile) { 
        if (!$(Test-Path $PathToPfxFile)) {
            Write-Error "The path '$PathToPfxFile'was not found at the path specified. Halting."
            $global:FunctionResult = "1"
            return
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToPfxFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Warning "Either the Private Key in '$PathToPfxFile' is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate. If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToPfxFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                $ErrMsg = "Either the password supplied for the Private Key in $PathToPfxFile' is " +
                "incorrect or it is not marked as Exportable! Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Validate CNofCertInStore
    if ($CNofCertInStore) {
        [array]$Cert1 = @(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore,"})

        if ($Cert1.Count -gt 1) {
            Write-Warning "Multiple certificates under 'Cert:\LocalMachine\My' with a CommonName '$CNofCertInStore' have been identified! They are as follows:"
            for ($i=0; $i -lt $Cert1.Count; $i++) {
                Write-Host "$i) " + "Subject: " + $Cert1[$i].Subject + ' | Thumbprint: ' + $Cert1[$i].Thumbprint
            }
            $ValidChoiceNumbers = 0..$($Cert1.Count-1)
            $CertChoicePrompt = "Please enter the number that corresponds to the Certificate that you " +
            "would like to use. [0..$($Cert1.Count-1)]"
            $CertChoice = Read-Host -Prompt $CertChoicePrompt
            while ($ValidChoiceNumbers -notcontains $CertChoice) {
                Write-Host "'$CertChoice' is not a valid choice number! Valid choice numbers are $($ValidChoiceNumbers -join ",")"
                $CertChoice = Read-Host -Prompt $CertChoicePrompt
            }
            
            $Cert1 = $Cert1[$CertChoice]
        }
        if ($Cert1.Count -lt 1) {
            Write-Error "Unable to find a a certificate matching CN=$CNofCertInStore in 'Cert:\LocalMachine\My'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($Cert1.Count -eq 1) {
            $Cert1 = $Cert1[0]
        }
    }

    if ($(-not $PSBoundParameters['PathToPfxFile']) -and $(-not $PSBoundParameters['CNofCertInStore'])) {
        if (!$FileToOutput -and !$CNOfNewCert) {
            $CNOfNewCert = Read-Host -Prompt "Please enter the desired CN for the new Self-Signed Certificate"
        }
        if ($FileToOutput -and !$CNofNewCert) {
            $CNOfNewCert = $FileToOutputFileSansExt
        }

        # Create the Self-Signed Cert and add it to the Personal Local Machine Store
        # Check to see if a Certificate with CN=$FileToOutputFileSansExt exists in the Local Machine Store already
        [array]$LocalMachineCerts = @(Get-ChildItem Cert:\LocalMachine\My)
        [array]$FoundMatchingExistingCert = @($LocalMachineCerts | Where-Object {$_.Subject -match "CN=$CNOfNewCert"})

        if ($FoundMatchingExistingCert.Count -gt 1) {
            Write-Warning "Multiple certificates under 'Cert:\LocalMachine\My' with a CommonName '$CNofCertInStore' have been identified!"

            $UseExistingCert = Read-Host -Prompt "Would you like to use and existing certificate? [Yes\No]"
            while (![bool]$($UseExistingCert -match "^yes$|^y$|^no$|^n$")) {
                Write-Host "'$UseExistingCert' is not a valid choice. Please enter either 'Yes' or 'No'"
                $UseExistingCert = Read-Host -Prompt "Would you like to use and existing certificate? [Yes\No]"
            }

            if ($UseExistingCert) {
                for ($i=0; $i -lt $Cert1.Count; $i++) {
                    Write-Host "$i) " + "Subject: " + $Cert1[$i].Subject + ' | Thumbprint: ' + $Cert1[$i].Thumbprint
                }
                $ValidChoiceNumbers = 0..$($Cert1.Count-1)
                $CertChoicePrompt = "Please enter the number that corresponds to the Certificate that you " +
                "would like to use. [0..$($Cert1.Count-1)]"
                $CertChoice = Read-Host -Prompt $CertChoicePrompt
                while ($ValidChoiceNumbers -notcontains $CertChoice) {
                    Write-Host "'$CertChoice' is not a valid choice number! Valid choice numbers are $($ValidChoiceNumbers -join ",")"
                    $CertChoice = Read-Host -Prompt $CertChoicePrompt
                }
                
                $Cert1 = $Cert1[$CertChoice]
            }
            else {
                if ($FileToOutput) {
                    $PfxOutputDir = $FileToOutput | Split-Path -Parent
                }
                if (!$FileToOutput -and $SourceType -eq "File") {
                    if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                        $PfxOutputDir = $ContentToEncrypt[0] | Split-Path -Parent
                    }
                    else {
                        $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
                    }
                }
                if (!$FileToOutput -and $SourceType -eq "Directory") {
                    if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                        $PfxOutputDir = $ContentToEncrypt[0]
                    }
                    else {
                        $PfxOutputDir = $ContentToEncrypt
                    }
                }

                $Cert1Prep = Get-EncryptionCert -CommonName $CNOfNewCert -ExportDirectory $PfxOutputDir
                $Cert1 = $Cert1Prep.CertInfo
            }
        }
        if ($FoundMatchingExistingCert.Count -eq 1) {
            $Cert1 = $FoundMatchingExistingCert[0]
        }
        if ($FoundMatchingExistingCert.Count -lt 1) {
            #$Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$FileToOutputFileSansExt" -KeyExportPolicy "Exportable"
            if ($FileToOutput) {
                $PfxOutputDir = $FileToOutput | Split-Path -Parent
            }
            if (!$FileToOutput -and $SourceType -eq "File") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0] | Split-Path -Parent
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
                }
            }
            if (!$FileToOutput -and $SourceType -eq "Directory") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0]
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt
                }
            }

            $Cert1Prep = Get-EncryptionCert -CommonName $CNOfNewCert -ExportDirectory $PfxOutputDir
            $Cert1 = $Cert1Prep.CertInfo
        }
    }

    # Now we have $Cert1 (which is an X509Certificate2 object)

    # If user did not explicitly use $PathToPfxFile, export the $Cert1 to a .pfx file in the same directory as $FileToOutput
    # so that it's abundantly clear that it was used for encryption, even if it's already in the Cert:\LocalMachine\My Store
    if (!$PSBoundParameters['PathToPfxFile']) {
        $CertName = $($Cert1.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        try {
            if ($FileToOutput) {
                $PfxOutputDir = $FileToOutput | Split-Path -Parent
            }
            if (!$FileToOutput -and $SourceType -eq "File") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0] | Split-Path -Parent
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
                }
            }
            if (!$FileToOutput -and $SourceType -eq "Directory") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0]
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt
                }
            }
            
            $pfxbytes = $Cert1.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            [System.IO.File]::WriteAllBytes("$PfxOutputDir\$CertName.pfx", $pfxbytes)
        }
        catch {
            Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Asking for password to try and generate new .pfx file..."
            # NOTE: The $Cert1.Export() method in the above try block has a second argument for PlainTextPassword, but it doesn't seem to work consistently
            
            # Check to see if it's already in the Cert:\LocalMachine\My Store
            if ($(Get-Childitem "Cert:\LocalMachine\My").Thumbprint -contains $Cert1.Thumbprint) {
                Write-Verbose "The certificate $CertName is already in the Cert:\LocalMachine\My Store."
            }
            else {
                # IMPORTANT NOTE: For some reason, eventhough we have the X509Certificate2 object ($Cert1), it may not
                # have the Property 'PrivateKey' until we import it to the Cert:\LocalMachine\My and then export it.
                # This could be why why the above export in the ty block failed...
                Write-Host "Importing $CertName to Cert:\LocalMachine\My Store..."
                $X509Store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $X509Store.Add($Cert1)
            }

            Write-Host "Attempting to export $CertName from Cert:\LocalMachine\My Store to .pfx file..."

            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the private key in the certificate $CertName" -AsSecureString
            }

            try {
                $Cert1 = Get-Item "Cert:\LocalMachine\My\$($Cert1.Thumbprint)"
                [System.IO.File]::WriteAllBytes("$PfxOutputDir\$CertName.pfx", $Cert1.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPwd))
                #Export-PfxCertificate -FilePath "$PfxOutputDir\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($Cert1.Thumbprint)" -Password $CertPwd
                $ExportPfxCertificateSuccessful = $true
            }
            catch {
                Write-Warning "Creating a .pfx file containing the public certificate used for encryption failed, but this is not strictly necessary and is only attempted for convenience. Continuing..."
                $ExportPfxCertificateSuccessful = $false
            }
        }
    }

    # If $Cert1 does NOT have a PrivateKey, ask the user if they're ABSOLUTELY POSITIVE they have the private key
    # before proceeding with encryption
    if ($Cert1.PrivateKey -eq $null -and $Cert1.HasPrivateKey -ne $True) {
        Write-Warning "Windows reports that there is NO Private Key associated with this X509Certificate2 object!"
        $ShouldWeContinue = Read-Host -Prompt "Are you ABSOLUTELY SURE you have the private key somewhere and want to proceed with encryption? [Yes\No]"
        if (![bool]$($ShouldWeContinue -match "^yes$|^y$")) {
            Write-Verbose "User specified halt! Halting!"
            Write-Error "User specified halt! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####
    $MaxNumberOfBytesThatCanBeEncryptedViaRSA = ((2048 - 384) / 8) + 37
    if ($SourceType -eq "String") {
        $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt)

        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            Write-Error "The string `$ContentToEncrypt is to large to encrypt via this method. Try writing it to a file first and then using this function to encrypt that file."
            $global:FunctionResult = "1"
            return
        }

        #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        <#
        try {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        }
        catch {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        }
        #>
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$FileToOutput.rsaencrypted"

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }

        [pscustomobject]@{
            FileEncryptedViaRSA                 = "$FileToOutput.rsaencrypted"
            FileEncryptedViaAES                 = $null
            OriginalFile                        = $null
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $null
            RSAEncryptedAESKey                  = $null
            RSAEncryptedAESKeyLocation          = $null
            AllFileOutputs                      = $(if ($PathToPfxFile) {"$FileToOutput.rsaencrypted"} else {"$FileToOutput.rsaencrypted","$PfxOutputDir\$CertName.pfx"})
        }
    }
    if ($SourceType -eq "ArrayOfStrings") {
        $RSAEncryptedFiles = @()
        for ($i=0; $i -lt $ContentToEncrypt.Count; $i++) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt[$i])

            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                Write-Warning "The string in index $i of the `$ContentToEncrypt array is to large to encrypt via this method. Skipping..."
                continue
            }

            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $FileOutputPathSplit = $FileToOutput -split "\."
            $FileToOutputUpdated = $FileOutputPathSplit[0] + "_$i." + $FileOutputPathSplit[-1] + ".rsaencrypted"
            $EncryptedString1 | Out-File $FileToOutputUpdated

            $RSAEncryptedFiles += $FileToOutputUpdated
        }

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }

        [pscustomobject]@{
            FilesEncryptedViaRSA                = $RSAEncryptedFiles
            FilesEncryptedViaAES                = $null
            OriginalFiles                       = $null
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $null
            RSAEncryptedAESKey                  = $null
            RSAEncryptedAESKeyLocation          = $null
            AllFileOutputs                      = $(if ($PathToPfxFile) {$RSAEncryptedFiles} else {$RSAEncryptedFiles,"$PfxOutputDir\$CertName.pfx"})
        }
    }
    if ($SourceType -eq "File") {
        $OriginalFileItem = Get-Item $ContentToEncrypt
        $OriginalFile = $OriginalFileItem.FullName
        $OriginalFileName = $OriginalFileItem.Name
        $OriginalDirectory = $OriginalFileItem.Directory

        # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
        #$EncodedBytes1 = Get-Content $ContentToEncrypt -Encoding Byte -ReadCount 0
        $EncodedBytes1 = [System.IO.File]::ReadAllBytes($ContentToEncrypt)

        # If the file content is small enough, encrypt via RSA
        if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$OriginalDirectory\$OriginalFileName.rsaencrypted"
        }
        # If the file content is too large, encrypt via AES and then Encrypt the AES Key via RSA
        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            $AESKeyDir = $ContentToEncrypt | Split-Path -Parent
            $AESKeyFileNameSansExt = $(Get-ChildItem $ContentToEncrypt).BaseName

            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $ContentToEncrypt -Destination "$OriginalFile.original"

            $AESKey = NewCryptographyKey -AsPlainText
            $FileEncryptionInfo = EncryptFile $ContentToEncrypt $AESKey

            # Save $AESKey for later use in the same directory as $ContentToEncrypt
            # $bytes = [System.Convert]::FromBase64String($AESKey)
            # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileNameSansExt.aeskey",$bytes)
            $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"

            # Encrypt the AESKey File using RSA asymetric encryption
            # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
            #$EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileNameSansExt.aeskey" -Encoding Byte -ReadCount 0
            $EncodedBytes1 = [System.IO.File]::ReadAllBytes("$AESKeyDir\$AESKeyFileNameSansExt.aeskey")
            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"
            Remove-Item "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"
        }

        $FileEncryptedViaRSA = if (!$AESKey) {"$OriginalFile.rsaencrypted"}
        $FileEncryptedViaAES = if ($AESKey) {$FileEncryptionInfo.FilesEncryptedwAESKey}
        $RSAEncryptedAESKeyLocation = if ($AESKey) {"$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"}
        $RSAEncryptedFileName = if ($FileEncryptedViaRSA) {$FileEncryptedViaRSA}
        $AESEncryptedFileName = if ($FileEncryptedViaAES) {$FileEncryptedViaAES}

        $AllFileOutputsPrep = $RSAEncryptedFileName,$AESEncryptedFileName,"$OriginalFile.original",$RSAEncryptedAESKeyLocation
        $AllFileOutputs = $AllFileOutputsPrep | foreach {if ($_ -ne $null) {$_}}
        if (!$PathToPfxFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }
        
        $RenameItemSplatParams = @{
            Path        = "$OriginalFile.original"
            NewName     = $OriginalFile
            PassThru    = $True
            ErrorAction = "SilentlyContinue"
        }
        $FinalOriginalFileItem = Rename-Item @RenameItemSplatParams
        if ($RemoveOriginalFile) {
            Remove-Item -Path $FinalOriginalFileItem.FullName -Force -ErrorAction SilentlyContinue
        }
        

        [pscustomobject]@{
            FileEncryptedViaRSA                 = $FileEncryptedViaRSA
            FileEncryptedViaAES                 = $FileEncryptedViaAES
            OriginalFile                        = $FinalOriginalFileItem.FullName
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $(if ($AESKey) {$FileEncryptionInfo.AESKey})
            RSAEncryptedAESKey                  = $(if ($AESKey) {$EncryptedString1})
            RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
            AllFileOutputs                      = $AllFileOutputs
        }
    }
    if ($SourceType -eq "Directory") {
        if (!$Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem -Path $ContentToEncrypt -File).FullName
        }
        if ($Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem -Path $ContentToEncrypt -Recurse -File).FullName
        }
        
        [array]$FilesToEncryptViaRSA = @()
        [array]$FilesToEncryptViaAES = @()
        foreach ($file in $FilesToEncryptPrep) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            #$EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0
            $EncodedBytes1 = [System.IO.File]::ReadAllBytes($file)

            # If the file content is small enough, encrypt via RSA
            if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                $FilesToEncryptViaRSA += $file
            }
            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                $FilesToEncryptViaAES += $file
            }
        }
        foreach ($file in $FilesToEncryptViaAES) {
            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $file -Destination "$file.original"
        }

        # Start Doing the Encryption
        foreach ($file in $FilesToEncryptViaRSA) {
            #$EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0
            $EncodedBytes1 = [System.IO.File]::ReadAllBytes($file)
            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$file.rsaencrypted"
        }

        $AESKeyDir = $ContentToEncrypt
        $AESKeyFileName = "$($AESKeyDir | Split-Path -Leaf).aeskey"
        $AESKey = NewCryptographyKey -AsPlainText
        $FileEncryptionInfo = EncryptFile $FilesToEncryptViaAES $AESKey

        # Save $AESKey for later use in the same directory as $file
        # $bytes = [System.Convert]::FromBase64String($AESKey)
        # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileName.aeskey",$bytes)
        $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileName"

        # Encrypt the AESKey File using RSA asymetric encryption
        # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
        #$EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileName" -Encoding Byte -ReadCount 0
        $EncodedBytes1 = [System.IO.File]::ReadAllBytes("$AESKeyDir\$AESKeyFileName")
        #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        <#
        try {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        }
        catch {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        }
        #>
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileName.rsaencrypted"
        Remove-Item "$AESKeyDir\$AESKeyFileName"

        $RSAEncryptedAESKeyLocation = if ($FilesToEncryptViaAES.Count -ge 1) {"$AESKeyDir\$AESKeyFileName.rsaencrypted"}
        $OriginalFilesPrep = $FilesToEncryptViaRSA + $FilesToEncryptViaAES
        $OriginalFiles = foreach ($file in $OriginalFilesPrep) {"$file.original"}
        $RSAEncryptedFileNames = foreach ($file in $FilesToEncryptViaRSA) {
            "$file.rsaencrypted"
        }
        $AESEncryptedFileNames = foreach ($file in $FilesToEncryptViaAES) {
            "$file.aesencrypted"
        }

        $AllFileOutputsPrep = $RSAEncryptedFileNames,$AESEncryptedFileNames,$OriginalFiles,$RSAEncryptedAESKeyLocation
        $AllFileOutputs = foreach ($element in $AllFileOutputsPrep) {if ($element -ne $null) {$element}}
        if (!$PathToPfxFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }

        [System.Collections.ArrayList]$FinalOriginalFileItems = @()
        foreach ($FullFilePath in $OriginalFiles) {
            $RenameItemSplatParams = @{
                Path        = $FullFilePath
                NewName     = $($FullFilePath -replace "\.original","")
                PassThru    = $True
                ErrorAction = "SilentlyContinue"
            }
            $FinalOriginalFileItem = Rename-Item @RenameItemSplatParams
            $null = $FinalOriginalFileItems.Add($FinalOriginalFileItem)
            if ($RemoveOriginalFile) {
                Remove-Item -Path $FullFilePath -Force -ErrorAction SilentlyContinue
            }
        }

        [pscustomobject]@{
            FilesEncryptedViaRSA                = $RSAEncryptedFileNames
            FilesEncryptedViaAES                = $AESEncryptedFileNames
            OriginalFiles                       = $FinalOriginalFileItems.FullName
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $FileEncryptionInfo.AESKey
            RSAEncryptedAESKey                  = $EncryptedString1
            RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
            AllFileOutputs                      = $AllFileOutputs
        }
    }

    ##### END Main Body #####
}


<#
    .Synopsis
        This cmdlet generates a self-signed certificate.
    .Description
        This cmdlet generates a self-signed certificate with the required data.
    .NOTES
        New-SelfSignedCertificateEx.ps1
        Version 1.0
        
        Creates self-signed certificate. This tool is a base replacement
        for deprecated makecert.exe
        
        Vadims Podans (c) 2013
        http://en-us.sysadmins.lv/

    .Parameter Subject
        Specifies the certificate subject in a X500 distinguished name format.
        Example: CN=Test Cert, OU=Sandbox
    .Parameter NotBefore
        Specifies the date and time when the certificate become valid. By default previous day
        date is used.
    .Parameter NotAfter
        Specifies the date and time when the certificate expires. By default, the certificate is
        valid for 1 year.
    .Parameter SerialNumber
        Specifies the desired serial number in a hex format.
        Example: 01a4ff2
    .Parameter ProviderName
        Specifies the Cryptography Service Provider (CSP) name. You can use either legacy CSP
        and Key Storage Providers (KSP). By default "Microsoft Enhanced Cryptographic Provider v1.0"
        CSP is used.
    .Parameter AlgorithmName
        Specifies the public key algorithm. By default RSA algorithm is used. RSA is the only
        algorithm supported by legacy CSPs. With key storage providers (KSP) you can use CNG
        algorithms, like ECDH. For CNG algorithms you must use full name:
        ECDH_P256
        ECDH_P384
        ECDH_P521
        
        In addition, KeyLength parameter must be specified explicitly when non-RSA algorithm is used.
    .Parameter KeyLength
        Specifies the key length to generate. By default 2048-bit key is generated.
    .Parameter KeySpec
        Specifies the public key operations type. The possible values are: Exchange and Signature.
        Default value is Exchange.
    .Parameter EnhancedKeyUsage
        Specifies the intended uses of the public key contained in a certificate. You can
        specify either, EKU friendly name (for example 'Server Authentication') or
        object identifier (OID) value (for example '1.3.6.1.5.5.7.3.1').
    .Parameter KeyUsage
        Specifies restrictions on the operations that can be performed by the public key contained in the certificate.
        Possible values (and their respective integer values to make bitwise operations) are:
        EncipherOnly
        CrlSign
        KeyCertSign
        KeyAgreement
        DataEncipherment
        KeyEncipherment
        NonRepudiation
        DigitalSignature
        DecipherOnly
        
        you can combine key usages values by using bitwise OR operation. when combining multiple
        flags, they must be enclosed in quotes and separated by a comma character. For example,
        to combine KeyEncipherment and DigitalSignature flags you should type:
        "KeyEncipherment, DigitalSignature".
        
        If the certificate is CA certificate (see IsCA parameter), key usages extension is generated
        automatically with the following key usages: Certificate Signing, Off-line CRL Signing, CRL Signing.
    .Parameter SubjectAlternativeName
        Specifies alternative names for the subject. Unlike Subject field, this extension
        allows to specify more than one name. Also, multiple types of alternative names
        are supported. The cmdlet supports the following SAN types:
        RFC822 Name
        IP address (both, IPv4 and IPv6)
        Guid
        Directory name
        DNS name
    .Parameter IsCA
        Specifies whether the certificate is CA (IsCA = $true) or end entity (IsCA = $false)
        certificate. If this parameter is set to $false, PathLength parameter is ignored.
        Basic Constraints extension is marked as critical.
    .Parameter PathLength
        Specifies the number of additional CA certificates in the chain under this certificate. If
        PathLength parameter is set to zero, then no additional (subordinate) CA certificates are
        permitted under this CA.
    .Parameter CustomExtension
        Specifies the custom extension to include to a self-signed certificate. This parameter
        must not be used to specify the extension that is supported via other parameters. In order
        to use this parameter, the extension must be formed in a collection of initialized
        System.Security.Cryptography.X509Certificates.X509Extension objects.
    .Parameter SignatureAlgorithm
        Specifies signature algorithm used to sign the certificate. By default 'SHA1'
        algorithm is used.
    .Parameter FriendlyName
        Specifies friendly name for the certificate.
    .Parameter StoreLocation
        Specifies the store location to store self-signed certificate. Possible values are:
        'CurrentUser' and 'LocalMachine'. 'CurrentUser' store is intended for user certificates
        and computer (as well as CA) certificates must be stored in 'LocalMachine' store.
    .Parameter StoreName
        Specifies the container name in the certificate store. Possible container names are:
        AddressBook
        AuthRoot
        CertificateAuthority
        Disallowed
        My
        Root
        TrustedPeople
        TrustedPublisher
    .Parameter Path
        Specifies the path to a PFX file to export a self-signed certificate.
    .Parameter Password
        Specifies the password for PFX file.
    .Parameter AllowSMIME
        Enables Secure/Multipurpose Internet Mail Extensions for the certificate.
    .Parameter Exportable
        Marks private key as exportable. Smart card providers usually do not allow
        exportable keys.
 .Example
  # Creates a self-signed certificate intended for code signing and which is valid for 5 years. Certificate
  # is saved in the Personal store of the current user account.
  
        New-SelfsignedCertificateEx -Subject "CN=Test Code Signing" -EKU "Code Signing" -KeySpec "Signature" `
        -KeyUsage "DigitalSignature" -FriendlyName "Test code signing" -NotAfter [datetime]::now.AddYears(5)
        
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. The certificate
  # includes SMIME capabilities.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -AllowSMIME -Path C:\test\ssl.pfx -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Exportable `
        -StoreLocation "LocalMachine"
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. Certificate uses
        # Ellyptic Curve Cryptography (ECC) key algorithm ECDH with 256-bit key. The certificate is signed by using
  # SHA256 algorithm.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -StoreLocation "LocalMachine" -ProviderName "Microsoft Software Key Storae Provider" -AlgorithmName ecdh_256 `
  -KeyLength 256 -SignatureAlgorithm sha256
  
    .Example
  # Creates self-signed root CA certificate.

  New-SelfsignedCertificateEx -Subject "CN=Test Root CA, OU=Sandbox" -IsCA $true -ProviderName `
  "Microsoft Software Key Storage Provider" -Exportable
  
#>
function New-SelfSignedCertificateEx {
    [CmdletBinding(DefaultParameterSetName = '__store')]
 param (
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Subject,
  [Parameter(Position = 1)]
  [datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
  [Parameter(Position = 2)]
  [datetime]$NotAfter = $NotBefore.AddDays(365),
  [string]$SerialNumber,
  [Alias('CSP')]
  [string]$ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0",
  [string]$AlgorithmName = "RSA",
  [int]$KeyLength = 2048,
  [validateSet("Exchange","Signature")]
  [string]$KeySpec = "Exchange",
  [Alias('EKU')]
  [Security.Cryptography.Oid[]]$EnhancedKeyUsage,
  [Alias('KU')]
  [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage,
  [Alias('SAN')]
  [String[]]$SubjectAlternativeName,
  [bool]$IsCA,
  [int]$PathLength = -1,
  [Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
  [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
  [string]$SignatureAlgorithm = "SHA1",
  [string]$FriendlyName,
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreName]$StoreName = "My",
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Alias('OutFile','OutPath','Out')]
  [IO.FileInfo]$Path,
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Security.SecureString]$Password,
  [switch]$AllowSMIME,
  [switch]$Exportable
 )

 $ErrorActionPreference = "Stop"
 if ([Environment]::OSVersion.Version.Major -lt 6) {
  $NotSupported = New-Object NotSupportedException -ArgumentList "Windows XP and Windows Server 2003 are not supported!"
  throw $NotSupported
 }
 $ExtensionsToAdd = @()

    #region >> Constants
 # contexts
 New-Variable -Name UserContext -Value 0x1 -Option Constant
 New-Variable -Name MachineContext -Value 0x2 -Option Constant
 # encoding
 New-Variable -Name Base64Header -Value 0x0 -Option Constant
 New-Variable -Name Base64 -Value 0x1 -Option Constant
 New-Variable -Name Binary -Value 0x3 -Option Constant
 New-Variable -Name Base64RequestHeader -Value 0x4 -Option Constant
 # SANs
 New-Variable -Name OtherName -Value 0x1 -Option Constant
 New-Variable -Name RFC822Name -Value 0x2 -Option Constant
 New-Variable -Name DNSName -Value 0x3 -Option Constant
 New-Variable -Name DirectoryName -Value 0x5 -Option Constant
 New-Variable -Name URL -Value 0x7 -Option Constant
 New-Variable -Name IPAddress -Value 0x8 -Option Constant
 New-Variable -Name RegisteredID -Value 0x9 -Option Constant
 New-Variable -Name Guid -Value 0xa -Option Constant
 New-Variable -Name UPN -Value 0xb -Option Constant
 # installation options
 New-Variable -Name AllowNone -Value 0x0 -Option Constant
 New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option Constant
 New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option Constant
 New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option Constant
 # PFX export options
 New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant
 New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option Constant
 New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option Constant
    #endregion >> Constants
 
    #region >> Subject Processing
 # http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
 $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
 $SubjectDN.Encode($Subject, 0x0)
    #endregion >> Subject Processing

    #region >> Extensions

    #region >> Enhanced Key Usages Processing
 if ($EnhancedKeyUsage) {
  $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
  $EnhancedKeyUsage | %{
   $OID = New-Object -ComObject X509Enrollment.CObjectID
   $OID.InitializeFromValue($_.Value)
   # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
   $OIDs.Add($OID)
  }
  # http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
  $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
  $EKU.InitializeEncode($OIDs)
  $ExtensionsToAdd += "EKU"
 }
    #endregion >> Enhanced Key Usages Processing

    #region >> Key Usages Processing
 if ($KeyUsage -ne $null) {
  $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
  $KU.InitializeEncode([int]$KeyUsage)
  $KU.Critical = $true
  $ExtensionsToAdd += "KU"
 }
    #endregion >> Key Usages Processing

    #region >> Basic Constraints Processing
 if ($PSBoundParameters.Keys.Contains("IsCA")) {
  # http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
  $BasicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
  if (!$IsCA) {$PathLength = -1}
  $BasicConstraints.InitializeEncode($IsCA,$PathLength)
  $BasicConstraints.Critical = $IsCA
  $ExtensionsToAdd += "BasicConstraints"
 }
    #endregion >> Basic Constraints Processing

    #region >> SAN Processing
 if ($SubjectAlternativeName) {
  $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
  $Names = New-Object -ComObject X509Enrollment.CAlternativeNames
  foreach ($altname in $SubjectAlternativeName) {
   $Name = New-Object -ComObject X509Enrollment.CAlternativeName
   if ($altname.Contains("@")) {
    $Name.InitializeFromString($RFC822Name,$altname)
   } else {
    try {
     $Bytes = [Net.IPAddress]::Parse($altname).GetAddressBytes()
     $Name.InitializeFromRawData($IPAddress,$Base64,[Convert]::ToBase64String($Bytes))
    } catch {
     try {
      $Bytes = [Guid]::Parse($altname).ToByteArray()
      $Name.InitializeFromRawData($Guid,$Base64,[Convert]::ToBase64String($Bytes))
     } catch {
      try {
       $Bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altname).RawData
       $Name.InitializeFromRawData($DirectoryName,$Base64,[Convert]::ToBase64String($Bytes))
      } catch {$Name.InitializeFromString($DNSName,$altname)}
     }
    }
   }
   $Names.Add($Name)
  }
  $SAN.InitializeEncode($Names)
  $ExtensionsToAdd += "SAN"
 }
    #endregion >> SAN Processing

    #region >> Custom Extensions
 if ($CustomExtension) {
  $count = 0
  foreach ($ext in $CustomExtension) {
   # http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
   $Extension = New-Object -ComObject X509Enrollment.CX509Extension
   $EOID = New-Object -ComObject X509Enrollment.CObjectId
   $EOID.InitializeFromValue($ext.Oid.Value)
   $EValue = [Convert]::ToBase64String($ext.RawData)
   $Extension.Initialize($EOID,$Base64,$EValue)
   $Extension.Critical = $ext.Critical
   New-Variable -Name ("ext" + $count) -Value $Extension
   $ExtensionsToAdd += ("ext" + $count)
   $count++
  }
 }
    #endregion >> Custom Extensions

    #endregion >> Extensions

    #region >> Private Key
 # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
 $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
 $PrivateKey.ProviderName = $ProviderName
 $AlgID = New-Object -ComObject X509Enrollment.CObjectId
 $AlgID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)
 $PrivateKey.Algorithm = $AlgID
 # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
 $PrivateKey.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
 $PrivateKey.Length = $KeyLength
 # key will be stored in current user certificate store
 switch ($PSCmdlet.ParameterSetName) {
  '__store' {
   $PrivateKey.MachineContext = if ($StoreLocation -eq "LocalMachine") {$true} else {$false}
  }
  '__file' {
   $PrivateKey.MachineContext = $false
  }
 }
 $PrivateKey.ExportPolicy = if ($Exportable) {1} else {0}
 $PrivateKey.Create()
    #endregion >> Private Key

 # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
 $Cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
 if ($PrivateKey.MachineContext) {
  $Cert.InitializeFromPrivateKey($MachineContext,$PrivateKey,"")
 } else {
  $Cert.InitializeFromPrivateKey($UserContext,$PrivateKey,"")
 }
 $Cert.Subject = $SubjectDN
 $Cert.Issuer = $Cert.Subject
 $Cert.NotBefore = $NotBefore
 $Cert.NotAfter = $NotAfter
 foreach ($item in $ExtensionsToAdd) {$Cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))}
 if (![string]::IsNullOrEmpty($SerialNumber)) {
  if ($SerialNumber -match "[^0-9a-fA-F]") {throw "Invalid serial number specified."}
  if ($SerialNumber.Length % 2) {$SerialNumber = "0" + $SerialNumber}
  $Bytes = $SerialNumber -split "(.{2})" | ?{$_} | %{[Convert]::ToByte($_,16)}
  $ByteString = [Convert]::ToBase64String($Bytes)
  $Cert.SerialNumber.InvokeSet($ByteString,1)
 }
 if ($AllowSMIME) {$Cert.SmimeCapabilities = $true}
 $SigOID = New-Object -ComObject X509Enrollment.CObjectId
 $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
 $Cert.SignatureInformation.HashAlgorithm = $SigOID
 # completing certificate request template building
 $Cert.Encode()
 
 # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
 $Request = New-Object -ComObject X509Enrollment.CX509enrollment
 $Request.InitializeFromRequest($Cert)
 $Request.CertificateFriendlyName = $FriendlyName
 $endCert = $Request.CreateRequest($Base64)
 $Request.InstallResponse($AllowUntrustedCertificate,$endCert,$Base64,"")
 switch ($PSCmdlet.ParameterSetName) {
  '__file' {
   $PFXString = $Request.CreatePFX(
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
    $PFXExportEEOnly,
    $Base64
   )
   #Set-Content -Path $Path -Value ([Convert]::FromBase64String($PFXString)) -Encoding Byte
   [System.IO.File]::WriteAllBytes($Path, $([Convert]::FromBase64String($PFXString)))
  }
 }
}


[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:NewCryptographyKey}.Ast.Extent.Text 
    ${Function:DecryptFile}.Ast.Extent.Text
    ${Function:EncryptFile}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Get-DecryptedContent}.Ast.Extent.Text
    ${Function:Extract-PfxCerts}.Ast.Extent.Text
    ${Function:Get-EncryptionCert}.Ast.Extent.Text
    ${Function:Get-PfxCertificateBetter}.Ast.Extent.Text
    ${Function:Get-PrivatekeyProperty}.Ast.Extent.Text
    ${Function:New-EncryptedFile}.Ast.Extent.Text
    ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
)

# Below $opensslkeysource from http://www.jensign.com/opensslkey/index.html
$opensslkeysource = @'

//**********************************************************************************
//
// OpenSSLKey
// .NET 2.0  OpenSSL Public & Private Key Parser
//
// Copyright (c) 2008  JavaScience Consulting,  Michel Gallant
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//***********************************************************************************
//
//  opensslkey.cs
//
//  Reads and parses:
//    (1) OpenSSL PEM or DER public keys
//    (2) OpenSSL PEM or DER traditional SSLeay private keys (encrypted and unencrypted)
//    (3) PKCS #8 PEM or DER encoded private keys (encrypted and unencrypted)
//  Keys in PEM format must have headers/footers .
//  Encrypted Private Key in SSLEay format not supported in DER
//  Removes header/footer lines.
//  For traditional SSLEAY PEM private keys, checks for encrypted format and
//  uses PBE to extract 3DES key.
//  For SSLEAY format, only supports encryption format: DES-EDE3-CBC
//  For PKCS #8, only supports PKCS#5 v2.0  3des.
//  Parses private and public key components and returns .NET RSA object.
//  Creates dummy unsigned certificate linked to private keypair and
//  optionally exports to pkcs #12
//
// See also: 
//  http://www.openssl.org/docs/crypto/pem.html#PEM_ENCRYPTION_FORMAT 
//**************************************************************************************

using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;
using System.ComponentModel;


namespace JavaScience {

    public class Win32 {
        [DllImport("crypt32.dll", SetLastError=true)]
            public static extern IntPtr CertCreateSelfSignCertificate(
                IntPtr hProv,
                ref CERT_NAME_BLOB pSubjectIssuerBlob,
                uint dwFlagsm,
                ref CRYPT_KEY_PROV_INFO pKeyProvInfo,
                IntPtr pSignatureAlgorithm,
                IntPtr pStartTime,
                IntPtr pEndTime,
                IntPtr other) ;
         [DllImport("crypt32.dll", SetLastError=true)]
            public static extern bool CertStrToName(
                uint dwCertEncodingType,
                String pszX500,
                uint dwStrType,
                IntPtr pvReserved,
                [In, Out] byte[] pbEncoded,
                ref uint pcbEncoded,
                IntPtr other);
         [DllImport("crypt32.dll", SetLastError=true)]
            public static extern bool CertFreeCertificateContext(
                IntPtr hCertStore);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_KEY_PROV_INFO {
        [MarshalAs(UnmanagedType.LPWStr)]  public String pwszContainerName;  
        [MarshalAs(UnmanagedType.LPWStr)]  public String pwszProvName;  
        public uint dwProvType;  
        public uint dwFlags;  
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_NAME_BLOB {
        public int cbData;
        public IntPtr pbData;
    }

public class opensslkey {
    const  String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----" ;
    const  String pemprivfooter   = "-----END RSA PRIVATE KEY-----" ;
    const  String pempubheader = "-----BEGIN PUBLIC KEY-----" ;
    const  String pempubfooter   = "-----END PUBLIC KEY-----" ;
    const  String pemp8header = "-----BEGIN PRIVATE KEY-----" ;
    const  String pemp8footer   = "-----END PRIVATE KEY-----" ;
    const  String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ;
    const  String pemp8encfooter   = "-----END ENCRYPTED PRIVATE KEY-----" ;

    // static byte[] pempublickey;
    // static byte[] pemprivatekey;
    // static byte[] pkcs8privatekey;
    // static byte[] pkcs8encprivatekey;

    static bool verbose = false;

    public static void Main(String[] args) {
  
        if(args.Length == 1)
            if(args[0].ToUpper() == "V")
                verbose = true;

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write("\nRSA public, private or PKCS #8  key file to decode: ");
        String filename = Console.ReadLine().Trim();
        if (filename == "")  //exit while(true) loop
            return;
        if (!File.Exists(filename)) {
            Console.WriteLine("File \"{0}\" does not exist!\n", filename);
            return; 
        }

        StreamReader sr = File.OpenText(filename);
        String pemstr = sr.ReadToEnd().Trim();
        sr.Close();
        if(pemstr.StartsWith("-----BEGIN"))
            DecodePEMKey(pemstr);
        else
            DecodeDERKey(filename);
    }

    // ------- Decode PEM pubic, private or pkcs8 key ----------------
    public static void DecodePEMKey(String pemstr) {
        byte[] pempublickey;
        byte[] pemprivatekey;
        byte[] pkcs8privatekey;
        byte[] pkcs8encprivatekey;

        if(pemstr.StartsWith(pempubheader) && pemstr.EndsWith(pempubfooter)) {
            Console.WriteLine("Trying to decode and parse a PEM public key ..");
            pempublickey = DecodeOpenSSLPublicKey(pemstr);
            if(pempublickey != null)
            {
                if(verbose)
                  showBytes("\nRSA public key", pempublickey) ;
                //PutFileBytes("rsapubkey.pem", pempublickey, pempublickey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeX509PublicKey(pempublickey);
                Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                String xmlpublickey =rsa.ToXmlString(false) ;
                Console.WriteLine("\nXML RSA public key:  {0} bits\n{1}\n", rsa.KeySize, xmlpublickey) ;
            }       
        }
        else if(pemstr.StartsWith(pemprivheader) && pemstr.EndsWith(pemprivfooter)) {
            Console.WriteLine("Trying to decrypt and parse a PEM private key ..");
            pemprivatekey = DecodeOpenSSLPrivateKey(pemstr);
            if(pemprivatekey != null)
            {
                if(verbose)
                  showBytes("\nRSA private key", pemprivatekey) ;
                //PutFileBytes("rsaprivkey.pem", pemprivatekey, pemprivatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeRSAPrivateKey(pemprivatekey);
                Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                String xmlprivatekey =rsa.ToXmlString(true) ;
                Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                ProcessRSA(rsa);
            }
        }
        else if(pemstr.StartsWith(pemp8header) && pemstr.EndsWith(pemp8footer)) {
            Console.WriteLine("Trying to decode and parse as PEM PKCS #8 PrivateKeyInfo ..");
            pkcs8privatekey = DecodePkcs8PrivateKey(pemstr);
            if(pkcs8privatekey != null)
            {
                if(verbose)
                  showBytes("\nPKCS #8 PrivateKeyInfo", pkcs8privatekey) ;
                //PutFileBytes("PrivateKeyInfo", pkcs8privatekey, pkcs8privatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodePrivateKeyInfo(pkcs8privatekey);
                if(rsa !=null) 
                {
                 Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                 String xmlprivatekey =rsa.ToXmlString(true) ;
                 Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                 ProcessRSA(rsa) ; 
                }
                else
                Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
            }       
        }
        else if(pemstr.StartsWith(pemp8encheader) && pemstr.EndsWith(pemp8encfooter)) {
            Console.WriteLine("Trying to decode and parse as PEM PKCS #8 EncryptedPrivateKeyInfo ..");
            pkcs8encprivatekey = DecodePkcs8EncPrivateKey(pemstr);
            if(pkcs8encprivatekey != null) {
                if(verbose)
                  showBytes("\nPKCS #8 EncryptedPrivateKeyInfo", pkcs8encprivatekey) ;
                //PutFileBytes("EncryptedPrivateKeyInfo", pkcs8encprivatekey, pkcs8encprivatekey.Length) ;
                RSACryptoServiceProvider rsa =  DecodeEncryptedPrivateKeyInfo(pkcs8encprivatekey);
                if(rsa !=null) 
                {
                 Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
                 String xmlprivatekey =rsa.ToXmlString(true) ;
                 Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
                  ProcessRSA(rsa) ;
                }
                else
                Console.WriteLine("\nFailed to create an RSACryptoServiceProvider");
            }       
        }
        else {
            Console.WriteLine("Not a PEM public, private key or a PKCS #8");
            return;
        }
    }

    // ------- Decode PEM pubic, private or pkcs8 key ----------------
    public static void DecodeDERKey(String filename) {
        RSACryptoServiceProvider rsa = null ;
        byte[] keyblob = GetFileBytes(filename);
        if(keyblob == null)
            return;

        rsa =  DecodeX509PublicKey(keyblob);
        if (rsa !=null) {
            Console.WriteLine("\nA valid SubjectPublicKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlpublickey =rsa.ToXmlString(false) ;
            Console.WriteLine("\nXML RSA public key:  {0} bits\n{1}\n", rsa.KeySize, xmlpublickey) ;
            return;
        }       

        rsa =  DecodeRSAPrivateKey(keyblob);
        if (rsa != null) {
            Console.WriteLine("\nA valid RSAPrivateKey\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa) ;
            return;
        }

        rsa =  DecodePrivateKeyInfo(keyblob);   //PKCS #8 unencrypted
        if(rsa !=null) {
            Console.WriteLine("\nA valid PKCS #8 PrivateKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa);
            return;
        }

        rsa =  DecodeEncryptedPrivateKeyInfo(keyblob);  //PKCS #8 encrypted
        if(rsa !=null) {
            Console.WriteLine("\nA valid PKCS #8 EncryptedPrivateKeyInfo\n") ;
            Console.WriteLine("\nCreated an RSACryptoServiceProvider instance\n") ;
            String xmlprivatekey =rsa.ToXmlString(true) ;
            Console.WriteLine("\nXML RSA private key:  {0} bits\n{1}\n", rsa.KeySize, xmlprivatekey) ;
            ProcessRSA(rsa);
            return;
        }
        Console.WriteLine("Not a binary DER public, private or PKCS #8 key");
        return;
    }

    public static void ProcessRSA(RSACryptoServiceProvider rsa) {
        if(verbose)
            showRSAProps(rsa);
        Console.Write("\n\nExport RSA private key to PKCS #12 file?  (Y or N) ");
        String resp = Console.ReadLine().ToUpper() ;
        if (resp == "Y"  || resp == "YES")
            RSAtoPKCS12(rsa) ;
    }

    //--------  Generate pkcs #12 from an RSACryptoServiceProvider  ---------
    public static void RSAtoPKCS12(RSACryptoServiceProvider rsa) {
        CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
        String keycontainer = keyInfo.KeyContainerName;
        uint keyspec    = (uint) keyInfo.KeyNumber;
        String provider = keyInfo.ProviderName;
        uint cspflags = 0;  //CryptoAPI Current User store;   LM would be CRYPT_MACHINE_KEYSET  = 0x00000020
        String fname = keycontainer + ".p12" ;
        //---- need to pass in rsa since underlying keycontainer is not persisted and might be deleted too quickly ---
        byte[] pkcs12 = GetPkcs12(rsa, keycontainer, provider, keyspec , cspflags) ;
        if ( (pkcs12 !=null)  && verbose)
            showBytes("\npkcs #12", pkcs12);
        if(pkcs12 !=null){
            PutFileBytes(fname, pkcs12, pkcs12.Length) ;
            Console.WriteLine("\nWrote pkc #12 file '{0}'\n",  fname) ;
            }
        else
            Console.WriteLine("\nProblem getting pkcs#12") ;
    }

    //--------   Get the binary PKCS #8 PRIVATE key   --------
    public static byte[] DecodePkcs8PrivateKey(String instr) {
        const  String pemp8header = "-----BEGIN PRIVATE KEY-----" ;
        const  String pemp8footer   = "-----END PRIVATE KEY-----" ;
        String pemstr = instr.Trim() ;
        byte[] binkey;
        if(!pemstr.StartsWith(pemp8header) || !pemstr.EndsWith(pemp8footer))
            return null;
        StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pemp8header, "") ;  //remove headers/footers, if present
        sb.Replace(pemp8footer, "") ;

        String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

        try {  
            binkey = Convert.FromBase64String(pubstr) ;
        } catch(System.FormatException) {       //if can't b64 decode, data is not valid
            return null;
        }
        return binkey;
     }

//------- Parses binary asn.1 PKCS #8 PrivateKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodePrivateKeyInfo(byte[] pkcs8)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
 // this byte[] includes the sequence byte and terminal encoded null 
   byte[] SeqOID = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00} ;
   byte[] seq = new byte[15];
 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(pkcs8) ;
  int lenstream = (int) mem.Length;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;


bt = binr.ReadByte();
if(bt != 0x02)
    return null;

twobytes = binr.ReadUInt16();

if(twobytes != 0x0001)
    return null;

seq = binr.ReadBytes(15);       //read the Sequence OID
if(!CompareBytearrays(seq, SeqOID)) //make sure Sequence for OID is correct
    return null;

bt = binr.ReadByte();
if(bt != 0x04)  //expect an Octet string 
    return null;

bt = binr.ReadByte();       //read next byte, or next 2 bytes is  0x81 or 0x82; otherwise bt is the byte count
if(bt == 0x81)
    binr.ReadByte();
else
 if(bt == 0x82)
    binr.ReadUInt16();
//------ at this stage, the remaining sequence should be the RSA private key

  byte[] rsaprivkey = binr.ReadBytes((int)(lenstream -mem.Position)) ;
    RSACryptoServiceProvider rsacsp = DecodeRSAPrivateKey(rsaprivkey);
  return rsacsp;
}

 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }

 }

//--------   Get the binary PKCS #8 Encrypted PRIVATE key   --------
public static byte[] DecodePkcs8EncPrivateKey(String instr) 
  {
 const  String pemp8encheader = "-----BEGIN ENCRYPTED PRIVATE KEY-----" ;
 const  String pemp8encfooter   = "-----END ENCRYPTED PRIVATE KEY-----" ;
  String pemstr = instr.Trim() ;
  byte[] binkey;
       if(!pemstr.StartsWith(pemp8encheader) || !pemstr.EndsWith(pemp8encfooter))
    return null;
       StringBuilder sb = new StringBuilder(pemstr) ;
       sb.Replace(pemp8encheader, "") ;  //remove headers/footers, if present
       sb.Replace(pemp8encfooter, "") ;

String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

   try{  
     binkey = Convert.FromBase64String(pubstr) ;
    }
   catch(System.FormatException) {      //if can't b64 decode, data is not valid
    return null;
    }
  return binkey;
 }


//------- Parses binary asn.1 EncryptedPrivateKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodeEncryptedPrivateKeyInfo(byte[] encpkcs8)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
 // this byte[] includes the sequence byte and terminal encoded null 
   byte[] OIDpkcs5PBES2 = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05,  0x0D } ;
   byte[] OIDpkcs5PBKDF2  = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05,  0x0C } ;
   byte[] OIDdesEDE3CBC = {0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07} ;
   byte[] seqdes = new byte[10] ;
   byte[] seq = new byte[11];
   byte[] salt ;
   byte[] IV;
   byte[] encryptedpkcs8;
   byte[] pkcs8;

   int saltsize, ivsize, encblobsize;
   int iterations;

 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(encpkcs8) ;
  int lenstream = (int) mem.Length;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

twobytes = binr.ReadUInt16();   //inner sequence
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();


seq = binr.ReadBytes(11);       //read the Sequence OID
if(!CompareBytearrays(seq, OIDpkcs5PBES2))  //is it a OIDpkcs5PBES2 ?
    return null;

twobytes = binr.ReadUInt16();   //inner sequence for pswd salt
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

twobytes = binr.ReadUInt16();   //inner sequence for pswd salt
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

seq = binr.ReadBytes(11);       //read the Sequence OID
if(!CompareBytearrays(seq, OIDpkcs5PBKDF2)) //is it a OIDpkcs5PBKDF2 ?
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();

bt = binr.ReadByte();
if(bt != 0x04)      //expect octet string for salt
    return null;
saltsize = binr.ReadByte();
salt = binr.ReadBytes(saltsize);

if(verbose)
    showBytes("Salt for pbkd", salt);
bt=binr.ReadByte();
if (bt != 0x02)     //expect an integer for PBKF2 interation count
    return null;

int itbytes = binr.ReadByte();  //PBKD2 iterations should fit in 2 bytes.
if(itbytes ==1)
    iterations = binr.ReadByte();
else if(itbytes == 2)
    iterations = 256*binr.ReadByte() + binr.ReadByte();
else
    return null;
if(verbose)
    Console.WriteLine("PBKD2 iterations {0}", iterations);

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)
    binr.ReadByte();
else if(twobytes == 0x8230)
    binr.ReadInt16();


seqdes = binr.ReadBytes(10);        //read the Sequence OID
if(!CompareBytearrays(seqdes, OIDdesEDE3CBC))   //is it a OIDdes-EDE3-CBC ?
    return null;

bt = binr.ReadByte();
if(bt != 0x04)      //expect octet string for IV
    return null;
ivsize = binr.ReadByte();   // IV byte size should fit in one byte (24 expected for 3DES)
IV= binr.ReadBytes(ivsize);
if(verbose)
    showBytes("IV for des-EDE3-CBC", IV);

bt=binr.ReadByte();
if(bt != 0x04)      // expect octet string for encrypted PKCS8 data
    return null;


bt = binr.ReadByte();

if(bt == 0x81)
    encblobsize = binr.ReadByte();  // data size in next byte
else if(bt == 0x82)
    encblobsize = 256*binr.ReadByte() + binr.ReadByte() ;
else
    encblobsize = bt;       // we already have the data size


encryptedpkcs8 = binr.ReadBytes(encblobsize) ;
//if(verbose)
//  showBytes("Encrypted PKCS8 blob", encryptedpkcs8) ;


SecureString secpswd = GetSecPswd("Enter password for Encrypted PKCS #8 ==>") ;
pkcs8 = DecryptPBDK2(encryptedpkcs8, salt, IV, secpswd, iterations) ;
if(pkcs8 == null)   // probably a bad pswd entered.
    return null;

//if(verbose)
//  showBytes("Decrypted PKCS #8", pkcs8) ;
 //----- With a decrypted pkcs #8 PrivateKeyInfo blob, decode it to an RSA ---
  RSACryptoServiceProvider rsa =  DecodePrivateKeyInfo(pkcs8) ;
  return rsa;
}

 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }


 }

    //  ------  Uses PBKD2 to derive a 3DES key and decrypts data --------
    public static byte[] DecryptPBDK2(byte[] edata, byte[] salt, byte[]IV, SecureString secpswd, int iterations)
    {
        CryptoStream decrypt = null;

        IntPtr unmanagedPswd = IntPtr.Zero;
        byte[] psbytes = new byte[secpswd.Length] ;
        unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
        Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length) ;
        Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

      try
        {
        Rfc2898DeriveBytes kd = new Rfc2898DeriveBytes(psbytes, salt, iterations);
        TripleDES decAlg = TripleDES.Create();
        decAlg.Key = kd.GetBytes(24);
        decAlg.IV = IV;
        MemoryStream memstr = new MemoryStream();
        decrypt = new CryptoStream(memstr,decAlg.CreateDecryptor(), CryptoStreamMode.Write);
        decrypt.Write(edata, 0, edata.Length);
        decrypt.Flush();
        decrypt.Close() ;   // this is REQUIRED.
        byte[] cleartext = memstr.ToArray();
        return cleartext;
        }
       catch (Exception e)
        { 
         Console.WriteLine("Problem decrypting: {0}", e.Message) ;
         return null;
        }
    }

    //--------   Get the binary RSA PUBLIC key   --------
    public static byte[] DecodeOpenSSLPublicKey(String instr) {
        const  String pempubheader = "-----BEGIN PUBLIC KEY-----" ;
        const  String pempubfooter   = "-----END PUBLIC KEY-----" ;
        String pemstr = instr.Trim() ;
        byte[] binkey;
        if (!pemstr.StartsWith(pempubheader) || !pemstr.EndsWith(pempubfooter))
            return null;
        StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pempubheader, "") ;  //remove headers/footers, if present
        sb.Replace(pempubfooter, "") ;

        String pubstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

        try {
            binkey = Convert.FromBase64String(pubstr) ;
        }
        catch(System.FormatException) {     //if can't b64 decode, data is not valid
            return null;
        }
        return binkey;
    }

//------- Parses binary asn.1 X509 SubjectPublicKeyInfo; returns RSACryptoServiceProvider ---
public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
 {
 // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
   byte[] SeqOID = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00} ;
   byte[] seq = new byte[15];
 // ---------  Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob  ------
  MemoryStream  mem = new MemoryStream(x509key) ;
  BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
  byte bt = 0;
  ushort twobytes = 0;

try{

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

seq = binr.ReadBytes(15);       //read the Sequence OID
if(!CompareBytearrays(seq, SeqOID)) //make sure Sequence for OID is correct
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8103)  //data read as little endian order (actual data order for Bit String is 03 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8203)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

bt = binr.ReadByte();
if(bt != 0x00)      //expect null byte next
    return null;

twobytes = binr.ReadUInt16();
if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
    binr.ReadByte();    //advance 1 byte
else if(twobytes == 0x8230)
    binr.ReadInt16();   //advance 2 bytes
else
    return null;

twobytes = binr.ReadUInt16();
byte lowbyte = 0x00;
byte highbyte = 0x00;

if(twobytes == 0x8102)  //data read as little endian order (actual data order for Integer is 02 81)
    lowbyte = binr.ReadByte();  // read next bytes which is bytes in modulus
else if(twobytes == 0x8202) {
    highbyte = binr.ReadByte(); //advance 2 bytes
    lowbyte = binr.ReadByte();
    }
else
    return null;
 byte[] modint = {lowbyte, highbyte, 0x00, 0x00} ;   //reverse byte order since asn.1 key uses big endian order
 int modsize = BitConverter.ToInt32(modint, 0) ;

byte firstbyte = binr.ReadByte();
binr.BaseStream.Seek(-1, SeekOrigin.Current);

 if(firstbyte == 0x00)  {   //if first byte (highest order) of modulus is zero, don't include it
    binr.ReadByte();    //skip this null byte
    modsize -=1  ;  //reduce modulus buffer size by 1
    }

  byte[] modulus = binr.ReadBytes(modsize); //read the modulus bytes

  if(binr.ReadByte() != 0x02)           //expect an Integer for the exponent data
    return null;
  int expbytes = (int) binr.ReadByte() ;        // should only need one byte for actual exponent data (for all useful values)
  byte[] exponent = binr.ReadBytes(expbytes);


  showBytes("\nExponent", exponent);
  showBytes("\nModulus", modulus) ;    

 // ------- create RSACryptoServiceProvider instance and initialize with public key -----
  RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
  RSAParameters RSAKeyInfo = new RSAParameters();
  RSAKeyInfo.Modulus = modulus;
  RSAKeyInfo.Exponent = exponent;
  RSA.ImportParameters(RSAKeyInfo);
  return RSA;
 }
 catch(Exception){
    return null; 
  }

 finally { binr.Close(); }

}

    //------- Parses binary ans.1 RSA private key; returns RSACryptoServiceProvider  ---
    public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey) {
        byte[] MODULUS, E, D, P, Q, DP, DQ, IQ ;

        // ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
        MemoryStream  mem = new MemoryStream(privkey) ;
        BinaryReader binr = new BinaryReader(mem) ;    //wrap Memory Stream with BinaryReader for easy reading
        byte bt = 0;
        ushort twobytes = 0;
        int elems = 0;
        try {
            twobytes = binr.ReadUInt16();
            if(twobytes == 0x8130)  //data read as little endian order (actual data order for Sequence is 30 81)
                binr.ReadByte();    //advance 1 byte
            else if(twobytes == 0x8230)
                binr.ReadInt16();   //advance 2 bytes
            else
                return null;

            twobytes = binr.ReadUInt16();
            if(twobytes != 0x0102)  //version number
                return null;
            bt = binr.ReadByte();
            if(bt !=0x00)
                return null;

            //------  all private key components are Integer sequences ----
            elems = GetIntegerSize(binr);
            MODULUS = binr.ReadBytes(elems);

            elems = GetIntegerSize(binr);
            E = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            D = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            P = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            Q = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            DP = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            DQ = binr.ReadBytes(elems) ;

            elems = GetIntegerSize(binr);
            IQ = binr.ReadBytes(elems) ;

            if(verbose) {
                showBytes("\nModulus", MODULUS) ;    
                showBytes("\nExponent", E);
                showBytes("\nD", D);
                showBytes("\nP", P);
                showBytes("\nQ", Q);
                showBytes("\nDP", DP);
                showBytes("\nDQ", DQ);
                showBytes("\nIQ", IQ);
            }

            // ------- create RSACryptoServiceProvider instance and initialize with public key -----
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            RSAParameters RSAparams = new RSAParameters();
            RSAparams.Modulus =MODULUS;
            RSAparams.Exponent = E;
            RSAparams.D = D;
            RSAparams.P = P;
            RSAparams.Q = Q;
            RSAparams.DP = DP;
            RSAparams.DQ = DQ;
            RSAparams.InverseQ = IQ;
            RSA.ImportParameters(RSAparams);
            return RSA;
        } catch(Exception){
            return null; 
        } finally { 
            binr.Close(); 
        }
    }

private static int GetIntegerSize(BinaryReader binr) {
  byte bt = 0;
  byte lowbyte = 0x00;
  byte highbyte = 0x00;
  int count = 0;
 bt = binr.ReadByte();
if(bt != 0x02)      //expect integer
    return 0;
bt = binr.ReadByte();

if(bt == 0x81)
    count = binr.ReadByte();    // data size in next byte
else
if(bt == 0x82) {
    highbyte = binr.ReadByte(); // data size in next 2 bytes
    lowbyte = binr.ReadByte();
    byte[] modint = {lowbyte, highbyte, 0x00, 0x00} ;
    count = BitConverter.ToInt32(modint, 0) ;
    }
else {
    count = bt;     // we already have the data size
}



 while(binr.ReadByte() == 0x00) {   //remove high order zeros in data
    count -=1;
    }
 binr.BaseStream.Seek(-1, SeekOrigin.Current);      //last ReadByte wasn't a removed zero, so back up a byte
 return count;
}




//-----  Get the binary RSA PRIVATE key, decrypting if necessary ----
public static byte[] DecodeOpenSSLPrivateKey(String instr) 
  {
  const  String pemprivheader = "-----BEGIN RSA PRIVATE KEY-----" ;
  const  String pemprivfooter   = "-----END RSA PRIVATE KEY-----" ;
  String pemstr = instr.Trim() ;
  byte[] binkey;
       if(!pemstr.StartsWith(pemprivheader) || !pemstr.EndsWith(pemprivfooter))
    return null;

       StringBuilder sb = new StringBuilder(pemstr) ;
        sb.Replace(pemprivheader, "") ;  //remove headers/footers, if present
        sb.Replace(pemprivfooter, "") ;

String pvkstr = sb.ToString().Trim();   //get string after removing leading/trailing whitespace

   try{        // if there are no PEM encryption info lines, this is an UNencrypted PEM private key
    binkey = Convert.FromBase64String(pvkstr) ;
    return binkey;
    }
   catch(System.FormatException) {      //if can't b64 decode, it must be an encrypted private key
    //Console.WriteLine("Not an unencrypted OpenSSL PEM private key");  
    }

 StringReader str = new StringReader(pvkstr);

//-------- read PEM encryption info. lines and extract salt -----
 if(!str.ReadLine().StartsWith("Proc-Type: 4,ENCRYPTED")) 
    return null;
 String saltline = str.ReadLine();
 if(!saltline.StartsWith("DEK-Info: DES-EDE3-CBC,") )
    return null;
 String saltstr =  saltline.Substring(saltline.IndexOf(",") + 1).Trim() ;
 byte[] salt = new byte[saltstr.Length/2]; 
 for (int i=0; i <salt.Length; i++)  
    salt[i] = Convert.ToByte(saltstr.Substring (i*2, 2), 16); 
 if(! (str.ReadLine() == ""))
    return null;

//------ remaining b64 data is encrypted RSA key ----
String encryptedstr =  str.ReadToEnd() ;

 try{   //should have b64 encrypted RSA key now
    binkey = Convert.FromBase64String(encryptedstr) ;
 }
   catch(System.FormatException) {  // bad b64 data.
    return null;
    }

//------ Get the 3DES 24 byte key using PDK used by OpenSSL ----

    SecureString  despswd = GetSecPswd("Enter password to derive 3DES key==>") ;
   //Console.Write("\nEnter password to derive 3DES key: ");
   //String pswd = Console.ReadLine();
  byte[] deskey = GetOpenSSL3deskey(salt, despswd, 1, 2);    // count=1 (for OpenSSL implementation); 2 iterations to get at least 24 bytes
  if(deskey == null)
    return null;
  //showBytes("3DES key", deskey) ;

//------ Decrypt the encrypted 3des-encrypted RSA private key ------
 byte[] rsakey = DecryptKey(binkey, deskey, salt);  //OpenSSL uses salt value in PEM header also as 3DES IV
if(rsakey !=null) 
    return rsakey;  //we have a decrypted RSA private key
else {
    Console.WriteLine("Failed to decrypt RSA private key; probably wrong password.");
    return null;
   }
 }


    // ----- Decrypt the 3DES encrypted RSA private key ----------
    public static byte[] DecryptKey(byte[] cipherData, byte[] desKey, byte[] IV) {
        MemoryStream memst = new MemoryStream(); 
        TripleDES alg = TripleDES.Create(); 
        alg.Key = desKey; 
        alg.IV = IV; 
        try {
            CryptoStream cs = new CryptoStream(memst, alg.CreateDecryptor(), CryptoStreamMode.Write); 
            cs.Write(cipherData, 0, cipherData.Length); 
            cs.Close(); 
        } catch(Exception exc) {
            Console.WriteLine(exc.Message); 
            return null;
        }
        byte[] decryptedData = memst.ToArray(); 
        return decryptedData; 
    }

//-----   OpenSSL PBKD uses only one hash cycle (count); miter is number of iterations required to build sufficient bytes ---
 private static byte[] GetOpenSSL3deskey(byte[] salt, SecureString secpswd, int count, int miter )  {
    IntPtr unmanagedPswd = IntPtr.Zero;
    int HASHLENGTH = 16;    //MD5 bytes
    byte[] keymaterial = new byte[HASHLENGTH*miter] ;     //to store contatenated Mi hashed results


    byte[] psbytes = new byte[secpswd.Length] ;
    unmanagedPswd = Marshal.SecureStringToGlobalAllocAnsi(secpswd);
    Marshal.Copy(unmanagedPswd, psbytes, 0, psbytes.Length) ;
    Marshal.ZeroFreeGlobalAllocAnsi(unmanagedPswd);

    //UTF8Encoding utf8 = new UTF8Encoding();
    //byte[] psbytes = utf8.GetBytes(pswd);

    // --- contatenate salt and pswd bytes into fixed data array ---
    byte[] data00 = new byte[psbytes.Length + salt.Length] ;
    Array.Copy(psbytes, data00, psbytes.Length);        //copy the pswd bytes
    Array.Copy(salt, 0, data00, psbytes.Length, salt.Length) ;  //concatenate the salt bytes

    // ---- do multi-hashing and contatenate results  D1, D2 ...  into keymaterial bytes ----
    MD5 md5 = new MD5CryptoServiceProvider();
    byte[] result = null;
    byte[] hashtarget = new byte[HASHLENGTH + data00.Length];   //fixed length initial hashtarget

    for(int j=0; j<miter; j++)
    {
    // ----  Now hash consecutively for count times ------
    if(j == 0)
        result = data00;    //initialize 
    else {
        Array.Copy(result, hashtarget, result.Length);
        Array.Copy(data00, 0, hashtarget, result.Length, data00.Length) ;
        result = hashtarget;
            //Console.WriteLine("Updated new initial hash target:") ;
            //showBytes(result) ;
    }

    for(int i=0; i<count; i++)
        result = md5.ComputeHash(result);
     Array.Copy(result, 0, keymaterial, j*HASHLENGTH, result.Length);  //contatenate to keymaterial
    }
    //showBytes("Final key material", keymaterial);
    byte[] deskey = new byte[24];
   Array.Copy(keymaterial, deskey, deskey.Length) ;

   Array.Clear(psbytes, 0,  psbytes.Length);
   Array.Clear(data00, 0, data00.Length) ;
   Array.Clear(result, 0, result.Length) ;
   Array.Clear(hashtarget, 0, hashtarget.Length) ;
   Array.Clear(keymaterial, 0, keymaterial.Length) ;

   return deskey; 
 }






//------   Since we are using an RSA with nonpersisted keycontainer, must pass it in to ensure it isn't colledted  -----
private static byte[] GetPkcs12(RSA rsa, String keycontainer, String cspprovider, uint KEYSPEC, uint cspflags)
 {
  byte[] pfxblob    = null;
  IntPtr hCertCntxt = IntPtr.Zero;

  String DN = "CN=Opensslkey Unsigned Certificate";

    hCertCntxt =  CreateUnsignedCertCntxt(keycontainer, cspprovider, KEYSPEC, cspflags, DN) ;
    if(hCertCntxt == IntPtr.Zero){
        Console.WriteLine("Couldn't create an unsigned-cert\n") ;
        return null;
    }
 try{
    X509Certificate cert = new X509Certificate(hCertCntxt) ;    //create certificate object from cert context.
    //X509Certificate2UI.DisplayCertificate(new X509Certificate2(cert)) ;   // display it, showing linked private key
    SecureString pswd = GetSecPswd("Set PFX Password ==>") ;
    pfxblob = cert.Export(X509ContentType.Pkcs12, pswd);
  }

 catch(Exception exc) 
 { 
    Console.WriteLine( "BAD RESULT" + exc.Message);
    pfxblob = null;
 }
    
rsa.Clear() ;
if(hCertCntxt != IntPtr.Zero)
    Win32.CertFreeCertificateContext(hCertCntxt) ;
  return pfxblob;
}




private static IntPtr CreateUnsignedCertCntxt(String keycontainer, String provider, uint KEYSPEC, uint cspflags, String DN) {
 const uint AT_KEYEXCHANGE  = 0x00000001;
 const uint AT_SIGNATURE        = 0x00000002;
 const uint CRYPT_MACHINE_KEYSET    = 0x00000020;
 const uint PROV_RSA_FULL       = 0x00000001;
 const String MS_DEF_PROV       = "Microsoft Base Cryptographic Provider v1.0";
 const String MS_STRONG_PROV    =  "Microsoft Strong Cryptographic Provider";
 const String MS_ENHANCED_PROV  = "Microsoft Enhanced Cryptographic Provider v1.0";
 const uint CERT_CREATE_SELFSIGN_NO_SIGN        = 1 ;
 const uint X509_ASN_ENCODING   = 0x00000001;
 const uint CERT_X500_NAME_STR  = 3;
 IntPtr hCertCntxt = IntPtr.Zero;
 byte[] encodedName = null;
 uint cbName = 0;

 if( provider != MS_DEF_PROV && provider != MS_STRONG_PROV && provider != MS_ENHANCED_PROV)
    return IntPtr.Zero;
 if(keycontainer == "")
    return IntPtr.Zero;
 if( KEYSPEC != AT_SIGNATURE &&  KEYSPEC != AT_KEYEXCHANGE)
    return IntPtr.Zero;
 if(cspflags != 0 && cspflags != CRYPT_MACHINE_KEYSET)   //only 0 (Current User) keyset is currently used.
    return IntPtr.Zero;
if (DN == "")
    return IntPtr.Zero;


if(Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, null, ref cbName, IntPtr.Zero))
 {
    encodedName = new byte[cbName] ;
    Win32.CertStrToName(X509_ASN_ENCODING, DN, CERT_X500_NAME_STR, IntPtr.Zero, encodedName, ref cbName, IntPtr.Zero);
 }

  CERT_NAME_BLOB subjectblob = new CERT_NAME_BLOB();
  subjectblob.pbData = Marshal.AllocHGlobal(encodedName.Length);
  Marshal.Copy(encodedName, 0, subjectblob.pbData, encodedName.Length);
  subjectblob.cbData = encodedName.Length;

  CRYPT_KEY_PROV_INFO pInfo = new CRYPT_KEY_PROV_INFO();
  pInfo.pwszContainerName = keycontainer;
  pInfo.pwszProvName = provider;
  pInfo.dwProvType = PROV_RSA_FULL;
  pInfo.dwFlags = cspflags;
  pInfo.cProvParam = 0;
  pInfo.rgProvParam = IntPtr.Zero;
  pInfo.dwKeySpec = KEYSPEC;

 hCertCntxt = Win32.CertCreateSelfSignCertificate(IntPtr.Zero, ref subjectblob, CERT_CREATE_SELFSIGN_NO_SIGN, ref pInfo, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
 if(hCertCntxt == IntPtr.Zero)
     showWin32Error(Marshal.GetLastWin32Error());
 Marshal.FreeHGlobal(subjectblob.pbData);
 return hCertCntxt ;
}




 private static SecureString GetSecPswd(String prompt)
  {
        SecureString password = new SecureString();

        Console.ForegroundColor = ConsoleColor.Gray;
        Console.Write(prompt);
        Console.ForegroundColor = ConsoleColor.Magenta;

        while (true)
            {
            ConsoleKeyInfo cki = Console.ReadKey(true);
                if (cki.Key == ConsoleKey.Enter)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (cki.Key == ConsoleKey.Backspace)
                {
                    // remove the last asterisk from the screen...
                    if (password.Length > 0)
                    {
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        password.RemoveAt(password.Length - 1);
                    }
                }
                else if (cki.Key == ConsoleKey.Escape)
                {
                    Console.ForegroundColor = ConsoleColor.Gray;
                    Console.WriteLine();
                    return password;
                }
                else if (Char.IsLetterOrDigit(cki.KeyChar) || Char.IsSymbol(cki.KeyChar))
                {
                    if (password.Length < 20)
                    {
                        password.AppendChar(cki.KeyChar);
                        Console.Write("*");
                    }
                    else
                    {
                        Console.Beep();
                    }
                } 
                else
                {
                    Console.Beep();
                }
            }
  }

    private static bool CompareBytearrays(byte [] a, byte[] b) {
        if(a.Length != b.Length)
            return false;
        int i =0;
        foreach(byte c in a) {
            if(c != b[i] ) 
                return false;
            i++;
        }
        return true;
     } 

    private static void showRSAProps(RSACryptoServiceProvider rsa) {
        Console.WriteLine("RSA CSP key information:");
        CspKeyContainerInfo keyInfo = rsa.CspKeyContainerInfo;
        Console.WriteLine("Accessible property: " + keyInfo.Accessible);
        Console.WriteLine("Exportable property: " + keyInfo.Exportable);
        Console.WriteLine("HardwareDevice property: " + keyInfo.HardwareDevice);
        Console.WriteLine("KeyContainerName property: " + keyInfo.KeyContainerName);
        Console.WriteLine("KeyNumber property: " + keyInfo.KeyNumber.ToString());
        Console.WriteLine("MachineKeyStore property: " + keyInfo.MachineKeyStore);
        Console.WriteLine("Protected property: " + keyInfo.Protected);
        Console.WriteLine("ProviderName property: " + keyInfo.ProviderName);
        Console.WriteLine("ProviderType property: " + keyInfo.ProviderType);
        Console.WriteLine("RandomlyGenerated property: " + keyInfo.RandomlyGenerated);
        Console.WriteLine("Removable property: " + keyInfo.Removable);
        Console.WriteLine("UniqueKeyContainerName property: " + keyInfo.UniqueKeyContainerName);
    }

    private static void showBytes(String info, byte[] data){
        Console.WriteLine("{0}  [{1} bytes]", info, data.Length);
        for(int i=1; i<=data.Length; i++){  
            Console.Write("{0:X2}  ", data[i-1]) ;
            if(i%16 == 0)
                Console.WriteLine();
        }
        Console.WriteLine("\n\n");
    }


    private static byte[] GetFileBytes(String filename) {
        if(!File.Exists(filename))
            return null;
        Stream stream=new FileStream(filename,FileMode.Open);
        int datalen = (int)stream.Length;
        byte[] filebytes =new byte[datalen];
        stream.Seek(0,SeekOrigin.Begin);
        stream.Read(filebytes,0,datalen);
        stream.Close();
        return filebytes;
    }

    private static void PutFileBytes(String outfile, byte[] data, int bytes) {
        FileStream fs = null;
        if(bytes > data.Length) {
            Console.WriteLine("Too many bytes");
            return;
        }
        try {
            fs = new FileStream(outfile, FileMode.Create);
            fs.Write(data, 0, bytes);
        } catch(Exception e) {
            Console.WriteLine(e.Message) ; 
        }
        finally {
            fs.Close();
        }
    }

    private static void showWin32Error(int errorcode) {
        Win32Exception myEx=new Win32Exception(errorcode);
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("Error code:\t 0x{0:X}", myEx.ErrorCode);
        Console.WriteLine("Error message:\t {0}\n", myEx.Message);
        Console.ForegroundColor = ConsoleColor.Gray;
    }


    }
}

'@

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUXXhuQdeo3FyKDkUZ+eKAnpl/
# jwKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOvlS8MrsIaw3H1w
# yntZhlCzNEoNMA0GCSqGSIb3DQEBAQUABIIBAKoOA2iD0SfNR5TXqHDls1AtHwIY
# x4WUXwv4HzlOu9Dtu/x5tHtz/mu0u/oRiCfgSH1L2VtvgoPIxlM7Rd/+eqUYZpcH
# +BSsKLdqLACDV6MRIbmi3VRXPoImisWsKG32W8/uTcY1ikryuXeZJ+xpvLu7Ux5d
# +24IOcrBNZtZIa1pEc8hg43a/L61ltSl617JHK47c5jPWn8m/85F5n6PbTXBpO5y
# qFruMomhtMHr8HrQJBAGgPG/Tx8FA68/ZI9KnavqQQjVO0IJN7oyX+F2Tzbl8Qix
# LOGjeQSuSVe1Q39hhoFtxA+2hmdZ2v9ZjaRfDObmOSdr/pZ7VnZuwnf61xU=
# SIG # End signature block
