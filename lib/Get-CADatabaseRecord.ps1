Function Get-CADatabaseRecord {

    param(
        [Parameter(Mandatory = $True)]
        [String]
        $ConfigString,

        [Parameter(Mandatory = $False)]
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

        [Parameter(Mandatory = $False)]
        [ValidateSet(
            "Pending",
            "Issued",
            "Revoked",
            "Failed",
            "Denied"
        )]
        [String]
        $Disposition,

        [Parameter(Mandatory = $False)]
        [String]
        $CertificateTemplate,

        [Parameter(Mandatory = $False)]
        [String]
        $CommonName,

        [Parameter(Mandatory = $False)]
        [String]
        $RequesterName,

        [Parameter(Mandatory = $False)]
        [Int]
        $RequestId,

        [Parameter(Mandatory = $False)]
        [datetime]
        $MinExpiryDate = ([datetime]::Now), # default to show only time-valid Certificates

        [Parameter(Mandatory = $False)]
        [datetime]
        $MaxExpiryDate
   
    )

    begin {

        $DISPOSITION_PENDING = 9	# request is taken under submission
        $DISPOSITION_ISSUED = 20	# certificate was issued
        $DISPOSITION_REVOKED = 21	# certificate is revoked
        $DISPOSITION_FAILED = 30	# certificate request failed
        $DISPOSITION_DENIED = 31	# certificate request is denied

        $CVR_SEEK_EQ = 0x1;
        #$CVR_SEEK_LT = 0x2;
        #$CVR_SEEK_LE = 0x4;
        #$CVR_SEEK_GE = 0x8;
        $CVR_SEEK_GT = 0x10;

        $CVR_SORT_NONE = 0;
        #$CVR_SORT_ASCEND = 1;
        #$CVR_SORT_DESCEND = 2;

        # https://docs.microsoft.com/en-us/windows/win32/api/certview/nf-certview-ienumcertviewextension-getvalue
        #$CV_OUT_BASE64HEADER = 0;
        $CV_OUT_BASE64 = 1;
        $CV_OUT_BINARY = 2;

        Try {
            $CaView = New-Object -ComObject CertificateAuthority.View
        }
        Catch {
            throw "Unable to create the CertificateAuthority.View Object.c Ensure you have the Certificate Authority Management Tools installed."
        }

        Try {
            $CaView.OpenConnection($ConfigString)
        }
        Catch {
            throw "Unable to connect to $ConfigString"
        }

    }

    process {

        # Set the Columns to be returned

        $CaView.SetResultColumnCount($Properties.Count)

        $Properties | ForEach-Object -Process {
            $CAView.SetResultColumn(
                $CAView.GetColumnIndex(
                    $False,
                    $_
                    )
                )
        }

        If ($Disposition) {

            Switch ($Disposition) {
                "Pending" {$SelectedDisposition = $DISPOSITION_PENDING}
                "Issued"  {$SelectedDisposition = $DISPOSITION_ISSUED}
                "Revoked" {$SelectedDisposition = $DISPOSITION_REVOKED}
                "Failed"  {$SelectedDisposition = $DISPOSITION_FAILED}
                "Denied"  {$SelectedDisposition = $DISPOSITION_DENIED}
                default   {$SelectedDisposition = $DISPOSITION_ISSUED}
            }

            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "Request.Disposition"),
                $CVR_SEEK_EQ,
                $CVR_SORT_NONE,
                $SelectedDisposition
                ) 
        }

        If ($MinExpiryDate) {
            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "NotAfter"),
                $CVR_SEEK_GT,
                $CVR_SORT_NONE,
                $MinExpiryDate
                )
        }

        If ($MaxExpiryDate) {
            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "NotAfter"),
                $CVR_SEEK_LT,
                $CVR_SORT_NONE,
                $MaxExpiryDate
                )
        }

        If ($CertificateTemplate) {
            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "CertificateTemplate"),
                $CVR_SEEK_EQ,
                $CVR_SORT_NONE,
                $CertificateTemplate
                )
        }

        If ($CommoName) {
            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "CommonName"),
                $CVR_SEEK_EQ,
                $CVR_SORT_NONE,
                $CommonName
                )
        }

        If ($RequesterName) {
            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "RequesterName"),
                $CVR_SEEK_EQ,
                $CVR_SORT_NONE,
                $RequesterName
                )
        }

        If ($RequestId) {
            $CaView.SetRestriction(
                $CAView.GetColumnIndex($False, "RequestId"),
                $CVR_SEEK_EQ,
                $CVR_SORT_NONE,
                $RequestId
                )
        }

        # Executing the Query
        $Row = $CaView.OpenView()

        # Setting the Current Row to the first one
        $Row.Reset()

        # Process all returned Rows
        while ($Row.Next() -ne -1) {

            $OutputObject = New-Object -TypeName PsObject

            # Enumerate the Columns of the current Row
            $Col = $Row.EnumCertViewColumn()

            # Process each Column in the current Row
            while ($Col.Next() -ne -1) {

                # Handle only the Cases where there is a different Encoding to be defined
                switch ($Col.GetName()) {

                    "Request.RawRequest"    { $ColEncoding = $CV_OUT_BASE64 }
                    "RawCertificate"        { $ColEncoding = $CV_OUT_BASE64 }
                    default                 { $ColEncoding = $CV_OUT_BINARY }
                    
                }

                Add-Member `
                    -InputObject $OutputObject `
                    -MemberType NoteProperty `
                    -Name $Col.GetName() `
                    -Value $Col.GetValue($ColEncoding)
            }

            # Return the Object to the Pipe
            $OutputObject
        }

    }

}