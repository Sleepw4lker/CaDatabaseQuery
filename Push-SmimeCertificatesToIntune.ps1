<#

    .SYNOPSIS

    .Parameter ConfigString

    .Parameter CertificateTemplates

    .Parameter UserName

    .Parameter RequestId

    .Parameter PfxEncryptionKeyName

#>

#Requires -Modules IntunePfxImport, ActiveDirectory

[cmdletbinding()]
param(
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ConfigString = "ca02.intra.adcslabor.de\ADCS Labor Issuing CA 1",

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $CertificateTemplates = @(
        "1.3.6.1.4.1.311.21.8.6301991.2938543.412570.1725121.735828.231.4136173.9322655" # Some S/MIME Certificate Template
        ),

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $UserName,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [Int]
    $RequestId,

    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $PfxEncryptionKeyName = "PFXEncryptionKey"
)

# Ensuring the Script will be run with Elevation
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error -Message "This must be run as Administrator! Aborting."
    Return
}

. $(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)\lib\Get-CADatabaseRecord.ps1

New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1
New-Variable -Option Constant -Name szOID_KEY_USAGE -Value "2.5.29.15"
New-Variable -Option Constant -Name szOID_ENHANCED_KEY_USAGE -Value "2.5.29.37"
New-Variable -Option Constant -Name szOID_KP_KEY_RECOVERY_AGENT -Value "1.3.6.1.4.1.311.21.6"
New-Variable -Option Constant -Name szOID_PKIX_KP_EMAIL_PROTECTION -Value "1.3.6.1.5.5.7.3.4"

Add-Type -AssemblyName 'System.Web'

$AllKraCertificates = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Extensions |
    Where-Object { $_.Oid.Value -eq $szOID_ENHANCED_KEY_USAGE } | 
        Where-Object { $_.EnhancedKeyUsages.Value -eq $szOID_KP_KEY_RECOVERY_AGENT }
    }

$CertAdmin = New-Object -ComObject CertificateAuthority.Admin

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

Set-IntuneAuthenticationToken

foreach ($CertificateTemplate in $CertificateTemplates) {

    $Arguments = @{
        ConfigString = $ConfigString
        CertificateTemplate = $CertificateTemplate
        HasArchivedKeys = $True
        Properties = "RequestId","SerialNumber","UPN","Request.RequesterName","CertificateHash"
    }

    If ($UserName)  { $Arguments.Add("RequesterName", $UserName) }
    If ($RequestId) { $Arguments.Add("RequestId", $RequestId) }

    foreach ($Result in (Get-CADatabaseRecord @Arguments)) {

        $RawCertificate = $CertAdmin.GetArchivedKey($ConfigString, $Result.RequestID, $XCN_CRYPT_STRING_BASE64)

        $CertificateCollection = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection

        [void]$CertificateCollection.Import(
            [Convert]::FromBase64String($RawCertificate), 
            $null,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"PersistKeySet" -band [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]"Exportable"
            )

        $CurrentSmimeCertificate = $CertificateCollection | Where-Object { $_.Extensions |
            Where-Object { $_.Oid.Value -eq $szOID_ENHANCED_KEY_USAGE } | 
                Where-Object { $_.EnhancedKeyUsages.Value -eq $szOID_PKIX_KP_EMAIL_PROTECTION }
            }

        $KeyUsages = ($CurrentSmimeCertificate | ForEach-Object { $_.Extensions | Where-Object { $_.Oid.Value -eq $szOID_KEY_USAGE } }).KeyUsages

        $KraCertificates = ($CertificateCollection | Where-Object { $_.Extensions |
            Where-Object { $_.Oid.Value -eq $szOID_ENHANCED_KEY_USAGE } | 
                Where-Object { $_.EnhancedKeyUsages.Value -eq $szOID_KP_KEY_RECOVERY_AGENT }
            }).SerialNumber

        If (-not $AllKraCertificates | Where-Object { $KraCertificates -contains $_.SerialNumber -and $_.HasPrivateKey -eq $True }) { 
            Write-Warning -Message "No KRA Certificate found for certificate with RequestId $($Result.RequestId)."
            continue 
        }
            
        $TempFileName = "$env:Temp\$($Result.SerialNumber).p7b"
        $ExportFileName = $TempFileName.Replace(".p7b", ".pfx")
        $Password = [System.Web.Security.Membership]::GeneratePassword(16, 4)
        
        Set-Content -Path $TempFileName -Value $RawCertificate -Encoding Ascii
        
        [void] (& certutil -p $Password -f -recoverkey $TempFileName $ExportFileName)

        If ($LASTEXITCODE -ne 0) {
            Write-Warning -Message "Unable to recover certificate with RequestId $($Result.RequestId)."
            continue
        }

        $UserPrincipalName = (Get-AdUser -Identity ($Result."Request.RequesterName").split("\")[1]).UserPrincipalName

        $IntuneUserCertificates = Get-IntuneUserPfxCertificate -UserList $UserPrincipalName

        If (($null -ne $IntuneUserCertificates) -and ($IntuneUserCertificates.Thumbprint.ToUpper() -eq $Result.CertificateHash.Replace(" ", "").ToUpper())) {
            Write-Warning -Message "Certificate with RequestId $($Result.RequestId) has already been uploaded to Intune."
            continue
        }

        switch ($KeyUsages) {
            "KeyEncipherment" { $Purpose = "SmimeEncryption" }
            "DigitalSignature" { $Purpose = "SmimeSigning" }
            default { $Purpose = "unassigned"  }
        }

        $SecureFilePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force

        $UserPfxObject = New-IntuneUserPfxCertificate `
            -PathToPfxFile $ExportFileName `
            -PfxPassword $SecureFilePassword `
            -UPN $UserPrincipalName `
            -ProviderName "Microsoft Software Key Storage Provider" `
            -KeyName $PfxEncryptionKeyName `
            -IntendedPurpose $Purpose
        
        try {
            Import-IntuneUserPfxCertificate -CertificateList $UserPfxObject
        }
        catch {
            # HTTP 400 error occur in several cases
            Write-Warning -Message "Unable to upload certificate with RequestId $($Result.RequestId) to Intune."
        }

        Remove-Item -Path $ExportFileName -Force
        Remove-Item -Path $TempFileName -Force
    }
}

Remove-IntuneAuthenticationToken
[void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CertAdmin))