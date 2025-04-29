function Set-LdapAccountPassword {
	[CmdletBinding(DefaultParameterSetName = 'Change')]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$SamAccountName,

		[Parameter(Mandatory = $true, ParameterSetName = 'Change')]
		[securestring]
		$OldPassword,

		[Parameter(Mandatory = $true)]
		[securestring]
		$NewPassword,

		[Parameter(Mandatory = $true, ParameterSetName = 'Reset')]
		[switch]
		$Reset,

		[string]
		$Server,

		[pscredential]
		$Credential
	)

	$param = @{}
	if ($Server) { $param.Server = $Server }
	if ($Credential) { $param.Credential = $Credential }

	$rawAccount = Get-LdapObject @param -LdapFilter "(samAccountName=$SamAccountName)" -Property DistinguishedName -Raw
	if (-not $rawAccount) { throw "Account not found: $SamAccountName!" }
	
	#region Reset
	if ($Reset) {
		$accountEntry = $rawAccount.GetDirectoryEntry()
		$accountEntry.PSBase.Invoke("SetPassword", [PSCredential]::new("whatever", $NewPassword).GetNetworkCredential().Password)
		$accountEntry.CommitChanges()
		return
	}
	#endregion Reset

	#region Change
	$domain = Get-LdapObject @param -LdapFilter '(objectClass=domainDNS)'
	$partition = Get-LdapObject @param -LdapFilter "(ncname=$($domain.DistinguishedName))" -SearchRoot "CN=Partitions,CN=Configuration,$($domain.DistinguishedName)"

	<#
	https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_authentication_enum
	705:
	ADS_SECURE_AUTHENTICATION (0x1) - Use Kerberos
	ADS_USE_SIGNING (0x40) - Sign the package to verify integrity
	ADS_USE_SEALING (0x80) - Use Kerberos
	ADS_SERVER_BIND (0x200) - Ignore SRV records when resolving server
	#>
	$UserDN = New-Object System.DirectoryServices.DirectoryEntry($rawAccount.Path, "$($partition.Netbiosname)\$($SamAccountName)", ([PSCredential]::new("whatever", $OldPassword).GetNetworkCredential().Password), 705)
	$UserDN.PsBase.Invoke("ChangePassword", [PSCredential]::new("whatever", $OldPassword).GetNetworkCredential().Password, [PSCredential]::new("whatever", $NewPassword).GetNetworkCredential().Password)
	$UserDN.CommitChanges()
	#endregion Change
}
