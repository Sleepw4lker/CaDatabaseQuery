function Revoke-Certificate {

    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $True)]
        [String]
        $SerialNumber,

        [ValidateRange(0,6)]
        [Parameter(Mandatory = $False)]
        [Int]
        $Reason = 6,

        [Parameter(Mandatory = $False)]
        [DateTime]
        $Date = $(Get-Date)
    )


    begin {

        <#
        New-Variable -Option Constant -Name CRL_REASON_UNSPECIFIED -Value 0
        New-Variable -Option Constant -Name CRL_REASON_KEY_COMPROMISE -Value 1
        New-Variable -Option Constant -Name CRL_REASON_CA_COMPROMISE -Value 2
        New-Variable -Option Constant -Name CRL_REASON_AFFILIATION_CHANGED -Value 3
        New-Variable -Option Constant -Name CRL_REASON_SUPERSEDED -Value 4
        New-Variable -Option Constant -Name CRL_REASON_CESSATION_OF_OPERATION -Value 5
        New-Variable -Option Constant -Name CRL_REASON_CERTIFICATE_HOLD -Value 6
        #>

    }
    
    process {

        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-revokecertificate
        Try {

            $CertAdmin.RevokeCertificate(
                $ConfigString,
                $SerialNumber,
                $Reason,
                $Date
                )
            return $True

        }
        Catch {
            Write-Warning -Message "Unable to revoke Certificate with Serial Number $SerialNumber on $ConfigString."
            return $False
        }

    }

    end {}
}