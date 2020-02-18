function Remove-CADatabaseRow {
#requires -Version 2.0
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $True)]
        [Int]
        $RowId
    )


    begin {

        New-Variable -Option Constant -Name CVRC_TABLE_ATTRIBUTES  -Value  0x4000
        New-Variable -Option Constant -Name CVRC_TABLE_CRL  -Value  0x5000
        New-Variable -Option Constant -Name CVRC_TABLE_EXTENSIONS  -Value  0x3000
        New-Variable -Option Constant -Name CVRC_TABLE_REQCERT  -Value  0

    }
    
    process {

        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin

        # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin2-deleterow
        Try {
            $Result = $CertAdmin.DeleteRow(
                $ConfigString,
                0x0,
                0x0,
                $CVRC_TABLE_REQCERT,
                $RowId
                )
        }
        Catch {
            Write-Warning -Message "Unable to delete Row $Row on $ConfigString."
        }

        return [bool]$Result
    }

    end {}
}