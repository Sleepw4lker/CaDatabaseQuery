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

                    $CurrentRow = $_

                    switch ($CurrentRow."Request.Requesttype") {
                        $REQUESTTYPE_PKCS7  { $RequestObject = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs7 }
                        $REQUESTTYPE_CMC    { $RequestObject = New-Object -ComObject X509Enrollment.CX509CertificateRequestCmc }
                        default             { $RequestObject = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10 }
                    }

                    Try {
                        $RequestObject.InitializeDecode(
                            $CurrentRow."Request.RawRequest",
                            $XCN_CRYPT_STRING_BASE64_ANY
                            )
                    }
                    Catch {
                        Write-Warning -Message "Unable to decode Request $($CurrentRow.RequestId). Skipping."
                        return
                    }

                    switch ($CurrentRow."Request.Requesttype") {
                        $REQUESTTYPE_PKCS7  { $Pkcs10Object = $RequestObject.GetInnerRequest(1) }
                        $REQUESTTYPE_CMC    { $Pkcs10Object = $RequestObject.GetInnerRequest(1) }
                        default             { $Pkcs10Object = $RequestObject }
                    }

                    If (-not ($Pkcs10Object.x509extensions | Where-Object {$_.Objectid.Value -eq $szOID_SUBJECT_ALT_NAME2})) {

                        Write-Verbose -Message "Request $($CurrentRow.RequestId) on $ConfigString does not have a SAN Extension."

                        Try {
                            $DistinguishedName = $Pkcs10Object.Subject.Name
                        }
                        Catch {
                            Write-Warning -Message "Request $($CurrentRow.RequestId) on $ConfigString seems to neither have a Subject nor a SAN Extension. Skipping."
                            return
                        }

                        # Extracting the Common Name from the Distinguished Name
                        $RegEx = '(?<=CN=)([^,]+)'
                
                        If ($DistinguishedName -match $RegEx) {
                            $DnsName = $Matches[0]
                            Write-Output "Adding DnsName SAN Extension for $DnsName to Request $($CurrentRow.RequestId) on $ConfigString."
                            Add-SANCertificateExtension -ConfigString $ConfigString -RequestId $CurrentRow.RequestID -DnsName $DnsName
                        }
                
                    }

                }
        }
    }
}

end {}