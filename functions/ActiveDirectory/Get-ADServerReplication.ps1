function Get-ADServerReplication {
	<#
	.SYNOPSIS
		List replication status between domain controllers in an Active Directory domain.
	
	.DESCRIPTION
		List replication status between domain controllers in an Active Directory domain.
	
	.PARAMETER Server
		THe domain to scan.
		Even when specifying an explicit domain controller, it will enumerate all replication links of all DCs in the domain it is part of.
	
	.PARAMETER Credential
		The credentials to use on AD requests.
	
	.EXAMPLE
		PS C:\> Get-ADServerReplication
		
		List replication status between domain controllers in the current Active Directory  domain.
	#>
	[CmdletBinding()]
	param (
		[string]
		$Server,

		[pscredential]
		$Credential
	)
	begin {
		$adParam = @{}
		if ($Server) { $adParam.Server = $Server }
		if ($Credential) { $adParam.Credential = $Credential }

		$domainControllers = Get-ADComputer @adParam -LDAPFilter '(primaryGroupID=516)'
		$adParam.Remove("Server")
	}
	process {
		foreach ($domainController in $domainControllers) {
			try { $metadata = Get-ADReplicationPartnerMetadata @adParam -Scope Server -Target $domainController.DNSHostName }
			catch {
				[PSCustomObject]@{
					Source      = $domainController.DNSHostName
					Partition   = $null
					From        = $null
					To          = $null
					USN         = $null
					LastAttempt = $null
					LastSuccess = $null
					LastCode    = $null
					ErrorCount  = $null
					Object      = $_
				}
				continue
			}
			foreach ($datum in $metadata) {
				if ($datum.PartnerType -eq 'Inbound') {
					$from = $datum.Partner -replace 'CN=NTDS Settings,CN=(.+?),.+', '$1'
					$to = $datum.Server
				}
				else {
					$from = $datum.Server
					$to = $datum.Partner -replace 'CN=NTDS Settings,CN=(.+?),.+', '$1'
				}

				[PSCustomObject]@{
					Source      = $domainController.DNSHostName
					Partition   = $datum.Partition
					From        = $from
					To          = $to
					USN         = $datum.LastChangeUsn
					LastAttempt = $datum.LastReplicationAttempt
					LastSuccess = $datum.LastReplicationSuccess
					LastCode    = $datum.LastReplicationResult
					ErrorCount  = $datum.ConsecutiveReplicationFailures
					Object      = $datum
				}
			}
		}
	}
}
