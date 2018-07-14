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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUmP9Dx2hmCT5RzivLExaJpOC6
# L9Ggggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNCXYB0B2ij74Evq
# WrznS01z4WPpMA0GCSqGSIb3DQEBAQUABIIBAGYI49SJWcCtyvDjGcVcQ13gyfi/
# /SLqJp+JCq3QFx7Bc2LaLSCKp8/moKeJw2ZwjlmXj+9EBQipKGCxbHrV+dA03vKV
# n6HP32lYxW47CKk7+cYbCacP6GA4q7ikJuoEh1NHsPl8aE7OhCeHd1tzpn5ATbDV
# L7yzy2ERH0EIwoaMeoYQMjUMTVjtn+0yUDwlqTI2xW1nWlfrDocVcM5J7bTB/rN4
# SeebyFGlo+igqNxiYJIQsA6s+O0Id2CwyLHXqB/clux/fMO8ummIlY4bhrBjs2QJ
# 6ppEuCUp8mNQEvFyO3v+5GUxH5X6CMjuxG7ArC2gH1GFeSpev1Fuu5uMy2k=
# SIG # End signature block
