
function Get-ADObjectAttributeReplication {
	<#
	.SYNOPSIS
		Tracks the replication progress of a single attribute change, as it propagates across Active Directory domain controllers.
	
	.DESCRIPTION
		Tracks the replication progress of a single attribute change, as it propagates across Active Directory domain controllers.
		This is attempted by polling all domain controllers for for the replication metadata for the specified attribute.

		Unfortunately, Active Directory domain controllers do not actually maintain a USN/Timestamp match, hence this toolkit will ...
		- use the metadata to find whether the replication was received
		- use the "WhenChanged" property on the object _after_ that replication was received, to determine the timestamp.

		This means, that if some time has passed and the object has been modified again in the meantime (maybe in another attribute), this new timestamp will be reported,
		leading to later timestamps than expected.

		In short:
		This tool is for live troubleshooting.
		It is NOT suitable for forensics trying to look further into the past!
	
	.PARAMETER Identity
		The identity of the object to troubleshoot.
		Expects a unique ID "Get-ADObject" accepts, so DN or ObjectGUID should work, SamAccountName should not.
	
	.PARAMETER Attribute
		The attribute to track.
		Note: This parameter is CASE SENSITIVE and expects the LDAP name, not the DisplayName in PowerShell.
		E.g.: "Description" will fail, "description" works.
	
	.PARAMETER Server
		The domain to work against.
		Even when specifying a single server, all servers in that server's domain will be polled.
	
	.PARAMETER Credential
		The credentials to use for the request.
	
	.PARAMETER Timeout
		How long should the command wait before giving up in case of replication errors.
		Defaults to 30 minutes.
		Domain Controllers that did not receive the replicated object will be reported with an empty timestamp.
	
	.EXAMPLE
		PS C:\> Get-ADObjectAttributeReplication -Identity $user -Attribute description

		Tracks the replication of the "description" attribute change across the domain.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Identity,

		[Parameter(Mandatory = $true)]
		[string]
		$Attribute,

		[string]
		$Server,

		[pscredential]
		$Credential,

		[timespan]
		$Timeout = '00:30:00'
	)

	begin {
		$adParam = @{}
		if ($Server) { $adParam.Server = $Server }
		if ($Credential) { $adParam.Credential = $Credential }

		$domainControllers = Get-ADComputer @adParam -LDAPFilter '(primaryGroupID=516)'
		$adParam.Remove('Server')
	}
	process {
		$pending = @{}
		
		# Determine Minimum Version
		$attributeStats = foreach ($domainController in $domainControllers) {
			$pending[$domainController.DNSHostName] = $domainController
			try { Get-ADReplicationAttributeMetadata @adParam -Server $domainController.DNSHostName -Object $Identity -Properties $Attribute }
			catch { }
		}
		if (-not $attributeStats) { throw "AD Object '$Identity' (or attribute '$Attribute') not found!" }
		$minVersion = ($attributeStats | Measure-Object Version -Maximum).Maximum

		$limit = (Get-Date).Add($Timeout)
		do {
			foreach ($domainController in $($pending.Keys)) {
				try { $attributeItem = Get-ADReplicationAttributeMetadata @adParam -Server $domainController -Object $Identity -Properties $Attribute }
				catch { $attributeItem = $null }
				if (-not $attributeItem -or $attributeItem.Version -lt $minVersion) { continue }

				$adObject = Get-ADObject @adParam -Server $domainController -Identity $Identity -Properties uSNChanged, WhenChanged
				[PSCustomObject]@{
					Server          = $domainController
					Identity        = $Identity
					Timestamp       = $adObject.WhenChanged
					Attribute       = $Attribute
					Version         = $attributeItem.Version
					LocalUSN        = $adObject.uSNChanged
					OriginUSN       = $attributeItem.LastOriginatingChangeUsn
					OriginTimestamp = $attributeItem.LastOriginatingChangeTime
					OriginServer    = $attributeItem.LastOriginatingChangeDirectoryServerIdentity -replace '^CN=NTDS Settings,CN=(.+?),.+', '$1'
				}

				$pending.Remove($domainController)
			}

			if ((Get-Date) -lt $limit) {
				Start-Sleep -Seconds 1
				continue
			}

			foreach ($domainController in $pending.Keys) {
				Write-Warning "Timeout on DC $DomainController, replication still not completed!"
				try { $attributeItem = Get-ADReplicationAttributeMetadata @adParam -Server $domainController -Object $Identity -Properties $Attribute }
				catch { $attributeItem = $null }

				[PSCustomObject]@{
					Server          = $domainController
					Identity        = $Identity
					Timestamp       = $null
					Attribute       = $Attribute
					Version         = $attributeItem.Version
					LocalUSN        = $null
					OriginUSN       = $attributeItem.LastOriginatingChangeUsn
					OriginTimestamp = $attributeItem.LastOriginatingChangeTime
					OriginServer    = $attributeItem.LastOriginatingChangeDirectoryServerIdentity -replace '^CN=NTDS Settings,CN=(.+?),.+', '$1'
				}
			}
			break
		}
		until ($pending.Count -lt 1)
	}
}
