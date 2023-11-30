function ConvertTo-TrustObject {
	<#
	.SYNOPSIS
		Converts an AD Object for a trust object and parses it into humanly useful information.
	
	.DESCRIPTION
		Converts an AD Object for a trust object and parses it into humanly useful information.
		This includes encryption settings and parsing the numeric values of the trust attributes.
	
	.PARAMETER Trust
		The trust object retrieved from active directory, for example using Get-ADObject -LdapFilter '(objectClass=trustedDomain)'
		NOT the result object of Get-ADTrust!
	
	.EXAMPLE
		PS C:\> Get-ADObject -LdapFilter '(objectClass=trustedDomain)' -Properties * | ConvertTo-TrustObject

		Reads all trusts from the current domain and processes them into something human friendly
	#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		$Trust
	)

	begin {
		$trustType = @{
			1 = 'WindowsDomainNonAD'
			2 = 'WindowsDomainAD'
			3 = 'MIT'
		}
		$trustDirection = @{
			0 = 'Disabled'
			1 = 'Inbound'
			2 = 'Outbound'
			3 = 'Bidirectional'
		}
	}
	process {
		[PSCustomObject]@{
			From                  = ($Trust.CanonicalName -split "/")[0]
			To                    = ($Trust.CanonicalName -split "/")[-1]
			AesEnabled            = $Trust.'msDS-SupportedEncryptionTypes' -eq 24
			Direction             = $trustDirection[$Trust.trustDirection]
			Attributes            = $Trust.trustAttributes
			Type                  = $trustType[$Trust.trustType]

			# Attributes: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
			NonTransitive         = ($trust.trustAttributes -band 0x1) -as [bool]
			UplevelOnly           = ($trust.trustAttributes -band 0x2) -as [bool]
			SIDFilteringEnabled   = ($trust.trustAttributes -band 0x4) -as [bool] # Quarantined
			ForestTransitive      = ($trust.trustAttributes -band 0x8) -as [bool]
			CrossOrganization     = ($trust.trustAttributes -band 0x10) -as [bool]
			WithinForest          = ($trust.trustAttributes -band 0x20) -as [bool]
			TreatAsExternal       = ($trust.trustAttributes -band 0x40) -as [bool]
			MITUsesRC4Encryption  = ($trust.trustAttributes -band 0x80) -as [bool]
			CrossOrgTGTDelegation = ($trust.trustAttributes -band 0x800) -as [bool]
			PIMTrust              = ($trust.trustAttributes -band 0x400) -as [bool]
		}
	}
}

function Get-TrustRecursive {
	<#
	.SYNOPSIS
		Generates a configuration map of all trusts in all directions.
	
	.DESCRIPTION
		Generates a configuration map of all trusts in all directions.
		This search recursively follows trust-links as it is able, documenting the entire web of trusts it can reach.
	
	.PARAMETER Server
		The domain to start the search from.
		Defaults to the current user's domain.
	
	.PARAMETER Credential
		Credentials to use for the request.
	
	.PARAMETER Trusts
		A hashtable containing the results.
		Defaults to an empty hashtable and will be filled by the command.
		Specify a custom hashtable if you want the result in a structured format.
	
	.PARAMETER FailedTrusts
		A hashtable containing failed access attempts to a target domain.
		Errors accessing a domain as you follow a trust link will be suppressed and stored in here.
		Provide a hashtable to have it filled with all access errors.
		Defaults to an empty hashtable.
	
	.EXAMPLE
		PS C:\> Get-TrustRecursive

		Returns all trusts from the current domain, recursively following all trust links.
	#>
	[CmdletBinding()]
	param (
		[string]
        $Server = $env:USERDNSDOMAIN,

		[PSCredential]
		$Credential,

		[hashtable]
		$Trusts = @{ },

		[hashtable]
		$FailedTrusts = @{ }
	)

	$credParam = @{ }
	if ($Credential) { $credParam.Credential = $Credential }

	$param = @{
		Properties = 'msDS-SupportedEncryptionTypes', 'trustAttributes', 'trustDirection', 'trustType', 'CanonicalName'
		LdapFilter = '(objectClass=trustedDomain)'
	}
	try { $trustResults = Get-ADObject @param @credParam -Server $Server | ConvertTo-TrustObject }
	catch { $FailedTrusts[$Server] = $_ }

	if (-not $trustResults) { return $Trusts.Values.Values }
    $Trusts[$trustResults[0].From] = @{ }

	foreach ($result in $trustResults) {
		$Trusts[$trustResults[0].From][$result.To] = $result
	}

	$targets = $trustResults.To | Where-Object {
		$_ -notin $Trusts.Keys -and
		$_ -notin $FailedTrusts.Keys
	}

	foreach ($target in $targets) {
		$null = Get-TrustRecursive @credParam -Server $target -Trusts $Trusts -FailedTrusts $FailedTrusts
	}

	$Trusts.Values.Values
}