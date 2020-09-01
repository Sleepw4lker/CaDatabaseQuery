function Publish-CertificateRevocationList {

    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $False)]
        [DateTime]
        $Date = 0
    )


    begin {}
    
    process {

        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-publishcrl
        <#
            If Date is nonzero, the next update value for the CRL is Date, subject to rounding or ceiling limits 
            enforced by Certificate Services. If Date is zero, the next update value of the CRL is calculated 
            from the default CRL publication period.
        #>
        Try {

            $CertAdmin.PublishCRL(
                $ConfigString,
                $Date
                )
            return $True

        }
        Catch {
            Write-Warning -Message "Unable to publish Certificate Revocation List on $ConfigString."
            return $False
        }

    }

    end {}
}