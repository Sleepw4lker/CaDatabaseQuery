function Approve-CertificateRequest {

    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $True)]
        [Int]
        $RequestId
    )


    begin {}
    
    process {

        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-denyrequest
        Try {

            $Result = $CertAdmin.ResubmitRequest(
                $ConfigString,
                $RequestId
              )

        }
        Catch {
            Write-Warning -Message "Unable to approve Certificate Request $RequestId on $ConfigString."
        }

        return [bool]$Result
    }

    end {}
}