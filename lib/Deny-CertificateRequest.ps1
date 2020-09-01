function Deny-CertificateRequest {

    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $False)]
        [Int]
        $RequestId
    )


    begin {}
    
    process {

        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-denyrequest
        Try {

            $CertAdmin.DenyRequest(
                $ConfigString,
                $RequestId
              )
            return $True

        }
        Catch {
            Write-Warning -Message "Unable to deny Certificate Request $RequestId on $ConfigString."
            return $False
        }

    }

    end {}
}