[cmdletbinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $ConfigStrings,
    
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $CertificateTemplates
)

begin {

    $Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

    # Loading all Libary Scripts we depend on
    Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
        . ($_.FullName)
    }

    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1

    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_OTHER_NAME -Value 1
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_RFC822_NAME -Value 2
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DNS_NAME -Value 3
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_X400_ADDRESS -Value 4
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_DIRECTORY_NAME -Value 5
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_EDI_PARTY_NAME -Value 6
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_URL -Value 7
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_IP_ADDRESS -Value 8
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_REGISTERED_ID -Value 9
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_GUID -Value 10
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Value 11
    New-Variable -Option Constant -Name XCN_CERT_ALT_NAME_UNKNOWN -Value 12

}

process {

    ForEach ($ConfigString in $ConfigStrings) {

        ForEach ($CertificateTemplate in $CertificateTemplates) {

            # Though this may not seem to be the best solution in the first place, DB processing time is limited
            # If we take too long, our Session gets killed.
            # Thus we first load all into memory which allows us to process the results as long as we need
            $DbFields = Get-CADatabaseRecord `
                -ConfigString $ConfigString `
                -Disposition Issued `
                -CertificateTemplate $CertificateTemplate `
                -Properties RequestId,SerialNumber,NotBefore,NotAfter,Request.RequesterName,CommonName,RawCertificate
                
            $DbFields | ForEach-Object -Process {

                    $CurrentRow = $_
                    $CertificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $CertificateObject.Import([Convert]::FromBase64String($CurrentRow.RawCertificate))

                    $SanExtension = $CertificateObject.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}

                    If (-not $SanExtension) {

                        $OutputObject = $CurrentRow

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

                            switch ($SanObject.Type) {

                                $XCN_CERT_ALT_NAME_DNS_NAME {
                                    Add-Member `
                                    -InputObject $OutputObject `
                                    -MemberType NoteProperty `
                                    -Name "DNSName" `
                                    -Value $SanObject.strValue `
                                    -Force
                                }

                                $XCN_CERT_ALT_NAME_IP_ADDRESS {


                                    $b64ip = $SanObject.RawData($XCN_CRYPT_STRING_BASE64);

                                    Add-Member `
                                    -InputObject $OutputObject `
                                    -MemberType NoteProperty `
                                    -Name "IPAddress" `
                                    -Value ([IPAddress] ([Convert]::FromBase64String($b64ip))) `
                                    -Force
                                }
                                
                                $XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME {
                                    Add-Member `
                                    -InputObject $OutputObject `
                                    -MemberType NoteProperty `
                                    -Name "UserPrincipalName" `
                                    -Value $SanObject.strValue `
                                    -Force
                                }
                            }

                            $OutputObject
                        }   

                    }
            
                } | Select-Object -Property CommonName,DNSName,IPAddress,UserPrincipalName,RequestId,Request.RequesterName,SerialNumber,NotBefore,NotAfter
        }
    }
}

end {}