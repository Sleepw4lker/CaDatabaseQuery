Function Get-CADatabaseRecord {

    param(
        [Parameter(Mandatory=$True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "Request.RequestID",
            "Request.RawRequest",
            "Request.RawArchivedKey",
            "Request.KeyRecoveryHashes",
            "Request.RawOldCertificate",
            "Request.RequestAttributes",
            "Request.RequestType",
            "Request.RequestFlags",
            "Request.StatusCode",
            "Request.Disposition",
            "Request.DispositionMessage",
            "Request.SubmittedWhen",
            "Request.ResolvedWhen",
            "Request.RevokedWhen",
            "Request.RevokedEffectiveWhen",
            "Request.RevokedReason",
            "Request.RequesterName",
            "Request.CallerName",
            "Request.SignerPolicies",
            "Request.SignerApplicationPolicies",
            "Request.Officer",
            "Request.DistinguishedName",
            "Request.RawName",
            "Request.Country",
            "Request.Organization",
            "Request.OrgUnit",
            "Request.CommonName",
            "Request.Locality",
            "Request.State",
            "Request.Title",
            "Request.GivenName",
            "Request.Initials",
            "Request.SurName",
            "Request.DomainComponent",
            "Request.EMail",
            "Request.StreetAddress",
            "Request.UnstructuredName",
            "Request.UnstructuredAddress",
            "Request.DeviceSerialNumber",
            "Request.AttestationChallenge",
            "Request.EndorsementKeyHash",
            "Request.EndorsementCertificateHash",
            "Request.RawPrecertificate",
            "RequestID",
            "RawCertificate",
            "CertificateHash",
            "CertificateTemplate",
            "EnrollmentFlags",
            "GeneralFlags",
            "PrivatekeyFlags",
            "SerialNumber",
            "IssuerNameID",
            "NotBefore",
            "NotAfter",
            "SubjectKeyIdentifier",
            "RawPublicKey",
            "PublicKeyLength",
            "PublicKeyAlgorithm",
            "RawPublicKeyAlgorithmParameters",
            "PublishExpiredCertInCRL",
            "UPN",
            "DistinguishedName",
            "RawName",
            "Country",
            "Organization",
            "OrgUnit",
            "CommonName",
            "Locality",
            "State",
            "Title",
            "GivenName",
            "Initials",
            "SurName",
            "DomainComponent",
            "EMail",
            "StreetAddress",
            "UnstructuredName",
            "UnstructuredAddress",
            "DeviceSerialNumber"
        )]
        [String[]]
        $Properties = (
            "RequestID",
            "RequesterName",
            "CommonName",
            "NotBefore",
            "NotAfter",
            "SerialNumber",
            "CertificateTemplate",
            "RawCertificate"
            ),

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "Pending",
            "Issued",
            "Revoked",
            "Failed",
            "Denied"
        )]
        [String]
        $Disposition = "Issued",

        [Parameter(Mandatory=$False)]
        [String]
        $CertificateTemplate,

        [Parameter(Mandatory=$False)]
        [String]
        $CommonName,

        [Parameter(Mandatory=$False)]
        [String]
        $RequesterName,

        [Parameter(Mandatory=$False)]
        [Int]
        $RequestId,

        [Parameter(Mandatory=$False)]
        [DateTime]
        $MinExpiryDate,

        [Parameter(Mandatory=$False)]
        [DateTime]
        $MaxExpiryDate,

        [Parameter(Mandatory=$False)]
        [Int]
        $PageSize = 50000,

        [Parameter(Mandatory=$False)]
        [Switch]
        $HasArchivedKeys = $False
    )

    begin {

        New-Variable -Option Constant -Name CVRC_COLUMN_SCHEMA -Value 0	# Schema column info
        New-Variable -Option Constant -Name CVRC_COLUMN_RESULT -Value 1	# Result column info
        New-Variable -Option Constant -Name CVRC_COLUMN_VALUE -Value 2	# Value column info
        New-Variable -Option Constant -Name CVRC_COLUMN_MASK -Value 0xfff # column info mask

        New-Variable -Option Constant -Name DISPOSITION_PENDING -Value 9
        New-Variable -Option Constant -Name DISPOSITION_ISSUED -Value 20
        New-Variable -Option Constant -Name DISPOSITION_REVOKED -Value 21
        New-Variable -Option Constant -Name DISPOSITION_FAILED -Value 30
        New-Variable -Option Constant -Name DISPOSITION_DENIED -Value 31

        New-Variable -Option Constant -Name CVR_SEEK_EQ -Value 0x1
        New-Variable -Option Constant -Name CVR_SEEK_LT -Value 0x2
        New-Variable -Option Constant -Name CVR_SEEK_LE -Value 0x4
        New-Variable -Option Constant -Name CVR_SEEK_GE -Value 0x8
        New-Variable -Option Constant -Name CVR_SEEK_GT -Value 0x10

        New-Variable -Option Constant -Name CVR_SORT_NONE -Value 0
        New-Variable -Option Constant -Name CVR_SORT_ASCEND -Value 1
        New-Variable -Option Constant -Name CVR_SORT_DESCEND -Value 2

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-ienumcertviewextension-getvalue
        New-Variable -Option Constant -Name CV_OUT_BASE64HEADER -Value 0
        New-Variable -Option Constant -Name CV_OUT_BASE64 -Value 1
        New-Variable -Option Constant -Name CV_OUT_BINARY -Value 2
    }

    process {

        # Kudos to the Research made by Vadims Podans
        # https://www.pkisolutions.com/adcs-certification-authority-database-query-numbers/

        # This restricts the Request ID to start from. We start with no restriction.
        $LastIndex = 0

        # We split the Request processing into separate slices to speed up Query Performance and to avoid the ERROR_INVALID_HANDLE Issue
        do {

            Try {
                # https://docs.microsoft.com/en-us/windows/win32/api/certview/nn-certview-icertview
                $CaView = New-Object -ComObject CertificateAuthority.View
            }
            Catch {
                throw "Unable to create the CertificateAuthority.View Object. Ensure you have the Certificate Authority Management Tools installed."
            }

            Try {
                $CaView.OpenConnection($ConfigString)
            }
            Catch {
                throw "Unable to connect to $ConfigString"
            }

            Write-Verbose -Message "Starting new Database Query against $ConfigString with a Page Size of $PageSize"

            # Set the Columns to be returned
            # We always must include RequestId - at the moment there is no Code yet to ensure this

            $CaView.SetResultColumnCount($Properties.Count)

            $Properties | ForEach-Object -Process {
                $CaView.SetResultColumn(
                    $CaView.GetColumnIndex(
                        $CVRC_COLUMN_SCHEMA,
                        $_
                        )
                    )
            }

            If ($Disposition) {

                Switch ($Disposition) {
                    "Pending" { $SelectedDisposition = $DISPOSITION_PENDING }
                    "Issued"  { $SelectedDisposition = $DISPOSITION_ISSUED }
                    "Revoked" { $SelectedDisposition = $DISPOSITION_REVOKED }
                    "Failed"  { $SelectedDisposition = $DISPOSITION_FAILED }
                    "Denied"  { $SelectedDisposition = $DISPOSITION_DENIED }
                    default   { $SelectedDisposition = $DISPOSITION_ISSUED }
                }

                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "Request.Disposition"),
                    $CVR_SEEK_EQ,
                    $CVR_SORT_NONE,
                    $SelectedDisposition
                    ) 
            }

            If ($MinExpiryDate) {
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "NotAfter"),
                    $CVR_SEEK_GT,
                    $CVR_SORT_NONE,
                    $MinExpiryDate
                    )
            }

            If ($MaxExpiryDate) {
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "NotAfter"),
                    $CVR_SEEK_LT,
                    $CVR_SORT_NONE,
                    $MaxExpiryDate
                    )
            }

            If ($CertificateTemplate) {
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "CertificateTemplate"),
                    $CVR_SEEK_EQ,
                    $CVR_SORT_NONE,
                    $CertificateTemplate
                    )
            }

            If ($CommoName) {
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "CommonName"),
                    $CVR_SEEK_EQ,
                    $CVR_SORT_NONE,
                    $CommonName
                    )
            }

            If ($RequesterName) {
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "RequesterName"),
                    $CVR_SEEK_EQ,
                    $CVR_SORT_NONE,
                    $RequesterName
                    )
            }

            If ($HasArchivedKeys.IsPresent) {
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "Request.KeyRecoveryHashes"),
                    $CVR_SEEK_GT,
                    $CVR_SORT_NONE,
                    [String]::Empty
                    )
            }

            If ($RequestId) {
                # A single row has been requested by specifying a Request ID
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "RequestId"),
                    $CVR_SEEK_EQ,
                    $CVR_SORT_NONE,
                    $RequestId
                    )
            }
            Else {
                # This ensures that Rows processed in previous Queries are skipped
                # and that the Results are sorted ascending by the Request ID
                $CaView.SetRestriction(
                    $CaView.GetColumnIndex($CVRC_COLUMN_SCHEMA, "RequestId"),
                    $CVR_SEEK_GT,
                    $CVR_SORT_ASCEND,
                    $LastIndex
                    )
            }

            # Executing the Query
            $Row = $CaView.OpenView()

            # The Reset method moves to the beginning of the row-enumeration sequence.
            # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-ienumcertviewrow-reset
            $Row.Reset()

            # We remember how many Rows we have processed
            $RowsRead = 0

            # Process all returned Rows
            while (($Row.Next() -ne -1) -and ($RowsRead -lt $PageSize)) {

                $RowsRead++

                $OutputObject = New-Object -TypeName PsObject

                # Enumerate the Columns of the current Row
                $Col = $Row.EnumCertViewColumn()

                # Process each Column in the current Row
                while ($Col.Next() -ne -1) {

                    # Handle only the Cases where there is a different Encoding to be defined or something special to process
                    switch ($Col.GetName()) {

                        "RequestId" {
                            $ColEncoding = $CV_OUT_BINARY

                            # Remember the current RowId, it could be the last before starting over
                            $LastIndex = $Col.GetValue($ColEncoding)
                        }
                        "Request.RawRequest"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "Request.RawArchivedKey"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "Request.RawOldCertificate"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "Request.RawName"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "Request.AttestationChallenge"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "RawCertificate" 
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "RawPublicKey"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "RawPublicKeyAlgorithmParameters"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        "RawName"
                            { $ColEncoding = $CV_OUT_BASE64 }
                        default
                            { $ColEncoding = $CV_OUT_BINARY }
                        
                    }

                    Add-Member `
                        -InputObject $OutputObject `
                        -MemberType NoteProperty `
                        -Name $Col.GetName() `
                        -Value $Col.GetValue($ColEncoding)
                }

                # Return the Object to the Pipeline
                $OutputObject

            }

            # We destroy the Interfaces and the Connection to start over, or clean up if we are done
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($Row))
            [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($CaView))
            $Row = $null
            $CaView = $null
            [System.GC]::Collect()

            Write-Verbose -Message "Read $RowsRead Rows in this Run"

        } while ($PageSize -eq $RowsRead)

    }

    end {}

}