<#
LDAP Functions
FORK of https://www.powershellgallery.com/packages/Ldap/0.1.0.17/Content/Ldap.psm1
Addition of Timeout (seconds) for Get-LdapConnection
#>

# Need to reference to .NET assembly used in the script.
Add-Type -AssemblyName System.DirectoryServices.Protocols

function Get-LdapConnection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [String] $Server,

        # LDAP port to use. Default is 389 for LDAP or 636 for LDAPS
        [Parameter()]
        [Int] $Port,

        # Do not use SSL
        [Parameter()]
        [Switch] $NoSsl,

        # Timeout
        [Parameter()]
        [Int] $TimeOut,

        # Ignore certificate validation (use with self-signed certs)
        [Parameter()]
        [Switch] $IgnoreCertificate,

        [Parameter()]
        [PSCredential] $Credential,

        [Parameter()]
        [System.DirectoryServices.Protocols.AuthType] $AuthType
    )

    process {
        $ldapIdentifier = New-Object -TypeName System.DirectoryServices.Protocols.LdapDirectoryIdentifier -ArgumentList $Server, $Port 

        if ($Credential) {
            Write-Debug "[Get-LdapConnection] Creating authenticated LdapConnection for user $($Credential.UserName)"
            $ldap = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ldapIdentifier, ($Credential.GetNetworkCredential())
            if (-not $AuthType) {
                Write-Debug "[Get-LdapConnection] AuthType was not specified; defaulting to Basic"
                $AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
            }
        }
        else {
            Write-Debug "[Get-LdapConnection] Creating anonymous LdapConnection"
            $ldap = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $ldapIdentifier
            if (-not $AuthType) {
                Write-Debug "[Get-LdapConnection] AuthType was not specified; defaulting to Anonymous"
                $AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
            }
        }

        $ldap.AuthType = $AuthType

        if ($NoSsl) {
            Write-Debug "[Get-LdapConnection] NoSsl was sent; not setting SSL"
        }
        else {
            $ldap.SessionOptions.SecureSocketLayer = $true
        }

        if ($IgnoreCertificate) {
            $ldap.SessionOptions.VerifyServerCertificate = { $true }
        }

        if ($TimeOut) {          
            $timespan = new-timespan -Seconds $TimeOut
            $ldap.Timeout = $timespan
        }

        Write-Output $ldap
    }
}

function Get-LdapObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.DirectoryServices.Protocols.LdapConnection] $LdapConnection,

        [Parameter(ParameterSetName = 'DistinguishedName',
            Mandatory)]
        [String] $Identity,

        [Parameter(ParameterSetName = 'LdapFilter',
            Mandatory)]
        [Alias('Filter')]
        [String] $LdapFilter,

        [Parameter(ParameterSetName = 'LdapFilter',
            Mandatory)]
        [String] $SearchBase,

        [Parameter(ParameterSetName = 'LdapFilter')]
        [System.DirectoryServices.Protocols.SearchScope] $Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree,

        [Parameter()]
        [String[]] $Property,

        [Parameter()]
        [ValidateSet('String', 'ByteArray')]
        [String] $AttributeFormat = 'String',

        # Do not attempt to clean up the LDAP output - provide the output as-is
        [Parameter()]
        [Switch] $Raw
    )

    begin {
        if ($AttributeFormat -eq 'String') {
            $attrType = [string]
        }
        else {
            $attrType = [byte[]]
        }
    }

    process {
        $request = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest

        if ($PSCmdlet.ParameterSetName -eq 'DistinguishedName') {
            $request.DistinguishedName = $Identity
        }
        else {
            $request.Filter = $LdapFilter
            $request.DistinguishedName = $SearchBase
        }

        if (-not $Property -or $Property -contains '*') {
            Write-Debug "[Get-LdapObject] Returning all properties"
        }
        else {
            foreach ($p in $Property) {
                [void] $request.Attributes.Add($p)
            }
        }

        Write-Debug "[Get-LdapObject] Sending LDAP request"
        $response = $LdapConnection.SendRequest($request)

        if (-not $response) {
            Write-Verbose "No response was returned from the LDAP server."
            return
        }

        if ($response.ResultCode -eq 'Success') {
            if ($Raw) {
                Write-Output ($response.Entries)
            }
            else {
                # Convert results to a PSCustomObject.
                foreach ($e in $response.Entries) {
                    $hash = @{
                        PSTypeName        = 'LdapObject'
                        DistinguishedName = $e.DistinguishedName
                        # Controls = $e.Controls # Not actually sure what this is
                    }

                    # Attributes are returned as an instance of the class
                    # System.DirectoryServices.Protocols.DirectoryAttribute.
                    # Translate that to a more PowerShell-friendly format here.
                    foreach ($a in $e.Attributes.Keys | Sort-Object) {
                        # Write-Debug "[Get-LdapObject] Adding type [$a]"
                        $hash[$a] = $e.Attributes[$a].GetValues($attrType) | Expand-Collection
                    }

                    Write-Output ([PSCustomObject] $hash)
                }
                return
            }
        }

        Write-Output $response
    }
}

function Remove-LdapConnection {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory,
            Position = 0,
            ValueFromPipeline = $true)]
        [System.DirectoryServices.Protocols.LdapConnection[]] $LdapConnection
        ,

        [Parameter()]
        [Switch] $Force
    )

    process {
        foreach ($l in $LdapConnection) {
            if ($l) {
                if (-not ($Force -or $PSCmdlet.ShouldProcess($l, "Close LDAP connection"))) {
                    Write-Debug "[Remove-LdapConnection] WhatIf mode or user denied prompt; not closing connection [[ $l ]"
                }
                else {
                    Write-Debug "[Remove-LdapConnection] Disposing LdapConnection [$l]"
                    $l.Dispose()
                }
            }
        }
    }
}

function Expand-Collection {
    # Simple helper function to expand a collection into a PowerShell array.
    # The advantage to this is that if it's a collection with a single element,
    # PowerShell will automatically parse that as a single entry.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory,
            Position = 0,
            ValueFromPipeline,
            ValueFromRemainingArguments)]
        [ValidateNotNull()]
        [Object[]] $InputObject
    )

    process {
        foreach ($i in $InputObject) {
            ForEach-Object -InputObject $i -Process { Write-Output $_ }
        }
    }
}

Set-StrictMode -Version Latest
