[cmdletbinding()]
param(
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $ConfigStrings = "ADCSCA02.corp.fabrikam.com\Fabrikam Issuing CA 1",
    
    [Parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $CertificateTemplates = "1.3.6.1.4.1.311.21.8.14597206.1215100.14962345.448403.10782732.61.658169.11549836"
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
                -Properties RequestId,Request.RequesterName,CommonName,RawCertificate | ForEach-Object -Process {

                    $CurrentRow = $_
                    $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $CertificateObject.Import([Convert]::FromBase64String($CurrentRow.RawCertificate))

                    $SanExtension = $CertificateObject.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}

                    If (-not $SanExtension) {

                        $OutputObject = $CurrentRow

                        Add-Member `
                            -InputObject $OutputObject `
                            -MemberType NoteProperty `
                            -Name "SubjectAltName" `
                            -Value ""

                        $OutputObject

                    }
                    Else {

                        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nf-certenroll-ix509extensionalternativenames-initializedecode
                        # https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-encodingtype
                        $SanObjects = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames                        
                        $SanObjects.InitializeDecode(
                            $XCN_CRYPT_STRING_BASE64,
                            [System.Convert]::ToBase64String($SanExtension.RawData)
                            ) 

                        Foreach ($SanObject in $SanObjects.AlternativeNames) {

                            $OutputObject = $CurrentRow

                            Add-Member `
                                -InputObject $OutputObject `
                                -MemberType NoteProperty `
                                -Name "SubjectAltName" `
                                -Value $SanObject.strValue `
                                -Force

                            $OutputObject | Select-Object -Property RequestId,Request.RequesterName,CommonName,SubjectAltName
                        }   

                    }
            
                }
        }
    }
}

end {}