[cmdletbinding()]
param(
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $ConfigStrings,
    
    [Parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $CertificateTemplates,

    [Parameter(Mandatory = $False)]
    [ValidateRange(0,3650)]
    [Int]
    $NumberOfDays = 180
)


begin {

    $Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

    # Loading all Libary Scripts we depend on
    Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
        . ($_.FullName)
    }

}

process {

    ForEach ($ConfigString in $ConfigStrings) {

        ForEach ($CertificateTemplate in $CertificateTemplates) {

            $Records = Get-CADatabaseRecord `
                -ConfigString $ConfigString `
                -Disposition Issued `
                -MaxExpiryDate $(Get-Date).AddDays($NumberOfDays * -1) `
                -CertificateTemplate $CertificateTemplate `
                -Properties RequestId
            
            # Temporarily saved into a variable as the process may take so long that the prior DB connection gets killed
            $Records | ForEach-Object -Process {

                Write-Host "Deleting Row $($_.RequestId) on $($ConfigString)"
                [void](Remove-CADatabaseRow -ConfigString $ConfigString -RowId $_.RequestId)

            }
       
        }

    }

}