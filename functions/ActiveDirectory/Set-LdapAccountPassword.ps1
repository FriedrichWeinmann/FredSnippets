function Set-LdapAccountPassword {
	<#
	.SYNOPSIS
		Changes or resets an Active Directory account password through LDAP.

	.DESCRIPTION
		Locates an Active Directory account by sAMAccountName and changes or resets its password by using System.DirectoryServices.
		This command can operate on two modi:
		- Administrative Reset
		- User resetting their own password
		The former requires high privileges, the latter providing the previous password.

	.PARAMETER SamAccountName
		The sAMAccountName of the account whose password should be changed or reset.

	.PARAMETER OldPassword
		The account's current password.
		Required when changing a password, not used for an administrative reset.

	.PARAMETER NewPassword
		The new password for the account, supplied as a secure string.
		E.g.: (Read-Host -AsSecureString)

	.PARAMETER Reset
		Performs an administrative password reset instead of changing the password with the account's current credentials.

	.PARAMETER Server
		The domain controller or LDAP server used to locate the account and domain information.

	.PARAMETER Credential
		The credential used for LDAP queries and the administrative reset bind. The current session credentials are used when this parameter is omitted.

	.EXAMPLE
		PS C:\> $oldPassword = Read-Host 'Current password' -AsSecureString
		PS C:\> $newPassword = Read-Host 'New password' -AsSecureString
		PS C:\> Set-LdapAccountPassword -SamAccountName 'alice' -OldPassword $oldPassword -NewPassword $newPassword -Server 'dc01.contoso.com'

		Changes Alice's password by authenticating with her current password against the specified domain controller.

	.EXAMPLE
		PS C:\> $newPassword = Read-Host 'New password' -AsSecureString
		PS C:\> Set-LdapAccountPassword -SamAccountName 'alice' -NewPassword $newPassword -Reset -Credential (Get-Credential)

		Resets Alice's password by using an administrative credential for the LDAP connection.
	#>
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
