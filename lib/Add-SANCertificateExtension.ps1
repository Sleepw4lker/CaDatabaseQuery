# Kudos to: https://www.sysadmins.lv/blog-en/how-to-add-fqdn-to-hp-ilo-request.aspx
# Prerequisites:
# - ADCS Management Tools must be installed
# - User must have "Issue and Manage Certificates" Permission on the Target CA
# To Do: 
# Implement Error Handling

function Add-SANCertificateExtension {
#requires -Version 2.0
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $True)]
        [Int]
        $RequestId,

        [Parameter(Mandatory = $True)]
        [String[]]
        $DnsName
    )


    begin {

        function ConvertTo-DERstring ([byte[]]$bytes) {
            $SB = New-Object System.Text.StringBuilder
            $bytes1 = $bytes | %{"{0:X2}" -f $_}
            for ($n = 0; $n -lt $bytes1.count; $n = $n + 2) {
                [void]$SB.Append([char](Invoke-Expression 0x$(($bytes1[$n+1]) + ($bytes1[$n]))))
            }
            $SB.ToString()
        }

        New-Variable -Option Constant -Name szOID_SUBJECT_ALT_NAME2 -Value 2.5.29.17
        New-Variable -Option Constant -Name PROPTYPE_BINARY -Value 0x3
    }
    
    process {

        $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $IANs = New-Object -ComObject X509Enrollment.CAlternativeNames

        foreach ($SANstr in $DnsName) {
            $IAN = New-Object -ComObject X509Enrollment.CAlternativeName
            $IAN.InitializeFromString(0x3,$SANstr)
            $IANs.Add($IAN)
        }

        $SAN.InitializeEncode($IANs)
        $bytes = [Convert]::FromBase64String($SAN.RawData(1))

        $pvarvalue = ConvertTo-DERstring $bytes

        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        Try {
            $CertAdmin.SetCertificateExtension(
                $ConfigString,
                $RequestID,
                $szOID_SUBJECT_ALT_NAME2,
                $PROPTYPE_BINARY,
                0x0,
                $pvarvalue
                )
        }
        Catch {
            Write-Warning -Message "Unable to set Extension for $RequestId on $ConfigString."
        }
    }

    end {}
}