[cmdletbinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $ConfigStrings,
    
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $CertificateTemplates,

    [Parameter(Mandatory = $False)]
    [ValidateRange(0,3650)]
    [Int]
    $NumberOfDays = 3650
)


begin {

    $Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

    # Loading all Libary Scripts we depend on
    Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
        . ($_.FullName)
    }

    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1

}

process {

    ForEach ($ConfigString in $ConfigStrings) {

        ForEach ($CertificateTemplate in $CertificateTemplates) {

            Get-CADatabaseRecord `
                -ConfigString $ConfigString `
                -Disposition Issued `
                -CertificateTemplate $CertificateTemplate `
                -MaxExpiryDate $(Get-Date).AddDays($NumberOfDays) `
                -Properties RequestId,Request.RequesterName,CommonName,NotBefore,NotAfter,RawCertificate | ForEach-Object {

                    $CurrentRow = $_

                    Add-Member `
                        -InputObject $CurrentRow `
                        -MemberType NoteProperty `
                        -Name "CertificationAuthority" `
                        -Value $ConfigString

                    $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $CertificateObject.Import([Convert]::FromBase64String($CurrentRow.RawCertificate))
        
                    $SanExtension = $CertificateObject.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}

                    If ($SanExtension) {

                        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionalternativenames-initializedecode
                        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-encodingtype
                        $SanExtensionObject = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames                        
                        $SanExtensionObject.InitializeDecode(
                            $XCN_CRYPT_STRING_BASE64,
                            [System.Convert]::ToBase64String($SanExtension.RawData)
                            )

                        $SanArray = @()

                        Foreach ($SanObject in $SanExtensionObject.AlternativeNames) {
                            $SanArray += $SanObject.strValue
                        }

                        Add-Member `
                            -InputObject $CurrentRow `
                            -MemberType NoteProperty `
                            -Name "SubjectAlternativeNames" `
                            -Value $SanArray
                    }

                    $CurrentRow | Select-Object -Property CertificationAuthority,RequestId,Request.RequesterName,CommonName,NotBefore,NotAfter,SubjectAlternativeNames

                }

        }

    }

}