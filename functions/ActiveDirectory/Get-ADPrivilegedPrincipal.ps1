function Get-ADPrivilegedPrincipal {
	<#
	.SYNOPSIS
		Retrieves all privileged accounts in a domain.
	
	.DESCRIPTION
		Retrieves all privileged accounts in a domain.
		Includes nested group memberships and non-user principals.

		Note: This scan is ONLY scanning for membership in privileged groups.
		If you want to ensure no other escalation path exists, use a tool such as the
		Active Directory Management Framework (admf.one) to scan for unexpected delegations.

		List of privileged groups taken from the Protected Accounts and Groups:
		https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
	
	.PARAMETER Name
		Name filter applied to the returned principals.
		Defaults to: *
	
	.PARAMETER Group
		Name of privileged group to consider for the result.
		Defaults to: *
	
	.PARAMETER ExcludeBuiltIn
		By default, the krbtgt and Administrator account are returned, irrespective of any other filtering.
		This disables that behavior.
	
	.PARAMETER IncludeGroups
		Include groups in the list of members of privileged groups.
		By default, groups that are members of a privileged groups are not returned, just its non-group members (recursively).
	
	.PARAMETER Server
		The server / domain to contact.
	
	.PARAMETER Credential
		The credentials to use with the request
	
	.EXAMPLE
		PS C:\> Get-ADPrivilegedPrincipal

		Retrieves all privileged accounts in the current domain.

	.LINK
		https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory
	#>
	[CmdletBinding()]
	param (
		[string]
		$Name = '*',

		[string]
		$Group = '*',

		[switch]
		$ExcludeBuiltIn,

		[switch]
		$IncludeGroups,

		[string]
		$Server,

		[PSCredential]
		$Credential
	)
	begin {
		$privilegedGroupRids = @(
			'498' # Enterprise Read-only Domain Controllers
			'512' # Domain Admins
			'516' # Domain Controllers
			'518' # Schema Admins
			'519' # Enterprise Admins
			'521' # Read-only DOmain Controllers
		)
		$privilegedBuiltinGroups = @(
			'S-1-5-32-544' # Administrators
			'S-1-5-32-548' # Account Operators
			'S-1-5-32-549' # Server Operators
			'S-1-5-32-550' # Print Operators
			'S-1-5-32-551' # Backup Operators
			'S-1-5-32-552' # Replicator
		)
		$privilegedAccountRids = @(
			'500' # Administrator
			'502' # krbtgt
		)

		$adParam = @{}
		if ($Server) { $adParam.Server = $Server }
		if ($Credential) { $adParam.Credential = $Credential }
	}
	process {
		$domain = Get-ADDomain @adParam -ErrorAction Stop

		#region Builtin Privileged Accounts
		if (-not $ExcludeBuiltIn) {
			foreach ($rid in $privilegedAccountRids) {
				$user = Get-ADUser @adParam -Identity "$($domain.DomainSID)-$rid"
				if ($user.Name -notlike $Name) { continue }

				[PSCustomObject]@{
					GroupName  = 'n/a'
					GroupDN    = $null
					GroupSID   = $null
					MemberName = $user.Name
					MemberType = $user.ObjectClass
					MemberSID  = $user.SID
					MemberDN   = $user.DistinguishedName
				}
			}
		}
		#endregion Builtin Privileged Accounts

		#region Resolve Groups to check
		$groupsDefault = foreach ($rid in $privilegedGroupRids) {
			try { Get-ADGroup @adParam -Identity "$($domain.DomainSID)-$rid" -ErrorAction Stop }
			catch {
				# This is expected for child domains and domains at a lower domain/forest level
				Write-Verbose "Group not found: $($domain.DomainSID)-$rid"
			}
		}
		$groupsBuiltin = foreach ($sid in $privilegedBuiltinGroups) {
			try { Get-ADGroup @adParam -Identity $sid -ErrorAction Stop }
			catch {
				# This is expected for child domains and domains at a lower domain/forest level
				Write-Verbose "Group not found: $sid"
			}
		}
		$relevantGroups = @($groupsDefault) + @($groupsBuiltin) | Write-Output | Where-Object { $_ -and $_.Name -like $Group }
		#endregion Resolve Groups to check

		#region Resolve privileged entities
		foreach ($relevantGroup in $relevantGroups) {
			$members = Get-ADObject -LdapFilter "(&(objectSID=*)(memberof:1.2.840.113556.1.4.1941:=$($relevantGroup.DistinguishedName)))" -Properties ObjectSID, SamAccountName
			foreach ($member in $members) {
				if ($member.Name -notlike $Name) { continue }
				if ($member.ObjectClass -eq 'Group' -and -not $IncludeGroups) { continue }
				[PSCustomObject]@{
					GroupName  = $relevantGroup.Name
					GroupDN    = $relevantGroup.DistinguishedName
					GroupSID   = $relevantGroup.SID
					MemberName = $member.Name
					MemberType = $member.ObjectClass
					MemberSID  = $member.SID
					MemberDN   = $member.DistinguishedName
				}
			}
		}
		#endregion Resolve privileged entities
	}
}