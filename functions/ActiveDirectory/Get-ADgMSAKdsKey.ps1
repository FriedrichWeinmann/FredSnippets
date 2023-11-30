function Get-ADgMSAKdsKey {
	<#
	.SYNOPSIS
		Retrieves KDS Information for a gMSA.
	
	.DESCRIPTION
		Retrieves KDS Information for a group managed service account (gMSA).
		It will attempt to verify the existence of the KDS Key, but depending on the rights involed, access might be denied.
	
	.PARAMETER ServiceAccount
		The service account to retrieve the KDS information from.
	
	.PARAMETER Server
		The server / domain to contact.
	
	.PARAMETER Credential
		The credentials to use with the request
	
	.EXAMPLE
		PS c:\> Get-ADServiceAccount -Filter * | Get-ADgMSAKdsKey
		
		Retrieves the KDS information for all gMSA in the current user's domain.
	#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true, Mandatory = $true)]
		$ServiceAccount,

		[string]
		$Server,

		[PSCredential]
		$Credential
	)

	begin {
		$adParam = @{ }
		if ($Server) { $adParam.Server = $Server }
		if ($Credential) { $adParam.Credential = $Credential }

		$kdsExists = @{ }
		$rootDSE = Get-ADRootDSE @adParam
	}
	process {
		foreach ($account in $ServiceAccount) {
			try { $object = Get-ADServiceAccount @adParam -Identity $account -Properties msDS-ManagedPasswordId, msDS-ManagedPasswordInterval -ErrorAction Stop }
			catch {
				Write-Warning "Failed to retrieve $($account): $_"
				Write-Error $_
				continue
			}
			$key = [guid][byte[]]$object.'msDS-ManagedPasswordId'[24..39]
			if ($kdsExists.Keys -notcontains $key) {
				$kdsExists[$key] = (Get-ADObject @adParam -Identity "CN=$key,CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($rootDSE.configurationNamingContext)" -ErrorAction Ignore) -as [bool]
			}

			[PSCustomObject]@{
				SamAccountName    = $object.SamAccountName
				KdsKeyID          = $key
				KdsExists         = $kdsExists[$key]
				PasswordInterval  = $object.'msDS-ManagedPasswordInterval'
				DistinguishedName = $object.DistinguishedName
			}
		}
	}
}