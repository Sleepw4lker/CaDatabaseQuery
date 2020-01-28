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

    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64_ANY -Value 0x6
    New-Variable -Option Constant -Name szOID_SUBJECT_ALT_NAME2 -Value 2.5.29.17
    New-Variable -Option Constant -Name REQUESTTYPE_PKCS10 -Value 0x40100
    New-Variable -Option Constant -Name REQUESTTYPE_PKCS7 -Value 0x40300
    New-Variable -Option Constant -Name REQUESTTYPE_CMC -Value 0x40400

}

process {

    ForEach ($ConfigString in $ConfigStrings) {

        ForEach ($CertificateTemplate in $CertificateTemplates) {

            Get-CADatabaseRecord `
                -ConfigString $ConfigString `
                -Disposition Pending `
                -CertificateTemplate $CertificateTemplate `
                -Properties RequestId,Request.RequestType,Request.RawRequest | ForEach-Object -Process {

                    $CurrentObject = $_

                    switch ($CurrentObject."Request.Requesttype") {
                        $REQUESTTYPE_PKCS7  { $RequestObject = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs7 }
                        $REQUESTTYPE_CMC    { $RequestObject = New-Object -ComObject X509Enrollment.CX509CertificateRequestCmc }
                        default             { $RequestObject = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10 }
                    }

                    Try {
                        $RequestObject.InitializeDecode(
                            $CurrentObject."Request.RawRequest",
                            $XCN_CRYPT_STRING_BASE64_ANY
                            )
                    }
                    Catch {
                        Write-Warning -Message "Unable to decode Request $($CurrentObject.RequestId). Skipping."
                        return
                    }

                    switch ($CurrentObject."Request.Requesttype") {
                        $REQUESTTYPE_PKCS7  { $Pkcs10Object = $RequestObject.GetInnerRequest(1) }
                        $REQUESTTYPE_CMC    { $Pkcs10Object = $RequestObject.GetInnerRequest(1) }
                        default             { $Pkcs10Object = $RequestObject }
                    }

                    If (-not ($Pkcs10Object.x509extensions | Where-Object {$_.Objectid.Value -eq $szOID_SUBJECT_ALT_NAME2})) {

                        Write-Verbose -Message "Request $($CurrentObject.RequestId) on $ConfigString does not have a SAN Extension."

                        Try {
                            $DistinguishedName = $Pkcs10Object.Subject.Name
                        }
                        Catch {
                            Write-Warning -Message "Request $($CurrentObject.RequestId) on $ConfigString seems to neither have a Subject nor a SAN Extension. Skipping."
                            return
                        }

                        # Extracting the Common Name from the Distinguished Name
                        $RegEx = '(?<=CN=)([^,]+)'
                
                        If ($DistinguishedName -match $RegEx) {
                            $DnsName = $Matches[0]
                            Write-Output "Adding DnsName SAN Extension for $DnsName to Request $($CurrentObject.RequestId) on $ConfigString."
                            Add-SANCertificateExtension -ConfigString $ConfigString -RequestId $CurrentObject.RequestID -DnsName $DnsName
                        }
                
                    }

                }
        }
    }
}

end {}