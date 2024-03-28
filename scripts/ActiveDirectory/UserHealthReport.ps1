#requires -Modules ActiveDirectory
#requires -Modules ImportExcel

<#
.SYNOPSIS
	Scans a domain for users with a bad configuration / state and generates a report.

.DESCRIPTION
	Scans a domain for users with a bad configuration / state and generates a report.
	Scans for ...
	- Has not logged in for a long time
	- Has not changed the password for a long time
	- Has its password set to never expires
	- Has never logged in
	- Has only weak encryption types configured

.PARAMETER OutPath
	Path to the Excel file to create.
	Folder must exist, may be a relative path, must include the filename.

.PARAMETER Checks
	What kinds of check to perform.
	Defaults to all of them.

.PARAMETER LogonThreshold
	How many days a user may chose to not log in before being considered unhealthy.
	Defaults to 180 days
	Note: There is an up to 14 days inprecision in this check, due to how AD replicates the related attribute.

.PARAMETER PasswordThreshold
	How many days a password may be old before it is considered unhealthy.
	Defaults to 180 days.

.PARAMETER CreationGrace
	A new account is not considered unhealthy for never having logged in until this many days have passed.
	Defaults to 30 days.

.PARAMETER Server
	The server / domain to contact.

.PARAMETER Credential
	The credentials to use with the request

.EXAMPLE
	PS C:\> .\UserHealthReport.ps1 -OutPath .\users.xlsx

	Scans the current user's domain for unhealthy users and writes the result to users.xlsx
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[ValidateScript({
			if ($_ -match '\.xlsx$') { return $true }
			throw "Not an xlsx file: $_"
		})]
	[string]
	$OutPath,

	[ValidateSet('LastLogon', 'PwdLastSet', 'NeverExpires', 'NeverLoggedIn', 'EncryptionTypes')]
	[string[]]
	$Checks = @('LastLogon', 'PwdLastSet', 'NeverExpires', 'NeverLoggedIn', 'EncryptionTypes'),

	[int]
	$LogonThreshold = 180,

	[int]
	$PasswordThreshold = 180,

	[int]
	$CreationGrace = 30,

	[string]
	$Server,

	[PSCredential]
	$Credential	
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

$adParam = @{ }
if ($Server) { $adParam.Server = $Server }
if ($Credential) { $adParam.Credential = $Credential }

#region Classes
[flags()]enum EncryptionType {
	DesCbcCrc = 1
	DesCbcMD5 = 2
	RRC4 = 4
	AES128 = 8
	AES256 = 16
	AES256SK = 32

	FastSupported = 65536
	CompoundIdentitySupported = 131072
	ClaimsSupported = 262144
	ResourceSIDCompressionDisabled = 524288
}
#endregion Classes

#region Functions
function Get-ADUnhealthyUser {
	<#
	.SYNOPSIS
		Scans a domain for users with a bad configuration / state.
	
	.DESCRIPTION
		Scans a domain for users with a bad configuration / state.
		Scans for ...
		- Has not logged in for a long time
		- Has not changed the password for a long time
		- Has its password set to never expires
		- Has never logged in
		- Has only weak encryption types configured
	
	.PARAMETER Checks
		What kinds of check to perform.
		Defaults to all of them.
	
	.PARAMETER LogonThreshold
		How many days a user may chose to not log in before being considered unhealthy.
		Defaults to 180 days
		Note: There is an up to 14 days inprecision in this check, due to how AD replicates the related attribute.
	
	.PARAMETER PasswordThreshold
		How many days a password may be old before it is considered unhealthy.
		Defaults to 180 days.
	
	.PARAMETER CreationGrace
		A new account is not considered unhealthy for never having logged in until this many days have passed.
		Defaults to 30 days.
	
	.PARAMETER Server
		The server / domain to contact.
	
	.PARAMETER Credential
		The credentials to use with the request
	
	.EXAMPLE
		PS C:\> Get-ADUnhealthyUser

		Scans the current domain for users with a bad configuration / state.
	#>
	[CmdletBinding()]
	param (
		[ValidateSet('LastLogon', 'PwdLastSet', 'NeverExpires', 'NeverLoggedIn', 'EncryptionTypes')]
		[string[]]
		$Checks = @('LastLogon', 'PwdLastSet', 'NeverExpires', 'NeverLoggedIn', 'EncryptionTypes'),

		[int]
		$LogonThreshold = 180,

		[int]
		$PasswordThreshold = 180,

		[int]
		$CreationGrace = 30,

		[string]
		$Server,

		[PSCredential]
		$Credential
	)
	begin {
		$filterSegments = @()
		switch ($Checks) {
			LastLogon { $filterSegments += "(lastLogonTimestamp<=$((Get-Date).AddDays(-$LogonThreshold).ToFileTime()))" <# Precise to ~14 Days #> }
			PwdLastSet { $filterSegments += "(pwdLastSet<=$((Get-Date).AddDays(-$PasswordThreshold).ToFileTime()))" }
			NeverExpires { $filterSegments += '(userAccountControl:1.2.840.113556.1.4.803:=65536)' <# Password never expires #> }
			NeverLoggedIn { $filterSegments += "(&(!(lastLogonTimestamp=*))(whenCreated<=$((Get-Date).AddDays(-$CreationGrace).ToString('yyyyMMddHHmmss.fZ'))))" <# Will possibly also find really new accounts if not filtering for creation date #> }
			EncryptionTypes {
				# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
				# https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax
				$subSegments = @(
					'(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=7)' # RC4 and worse
					'(!(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=56))' # NOT Aes 128 or better
				)
				$filterSegments += ('(&{0})' -f ($subSegments -join ''))
			}
		}
		$ldapFilter = '(|{0})' -f ($filterSegments -join '')
		$properties = @(
			'LastLogonDate'
			'PwdLastSet'
			'PasswordNeverExpires'
			'Enabled'
			'msDS-SupportedEncryptionTypes'
			'WhenCreated'
		)
	}
	process {
		Get-ADUser -LDAPFilter $ldapFilter -Properties $properties | ForEach-Object {
			[PSCustomObject]@{
				SamAccountName       = $_.SamAccountName
				DistinguishedName    = $_.DistinguishedName
				LastLogonDate        = $_.LastLogonDate
				PwdLastSet           = if ($_.PwdLastSet) { [datetime]::FromFileTime($_.PwdLastSet) }
				PasswordNeverExpires = $_.PasswordNeverExpires
				Enabled              = $_.Enabled
				EncryptionTypes      = $_.'msDS-SupportedEncryptionTypes' -as [EncryptionType]
				WhenCreated          = $_.WhenCreated

				IsLateLogon          = $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-$LogonThreshold)
				IsOldPassword        = $_.PwdLastSet -and $_.PwdLastSet -lt (Get-Date).AddDays(-$PasswordThreshold).ToFileTime()
				IsNonExpiring        = $_.PasswordNeverExpires
				IsNoLogon            = -not $_.LastLogonDate -and $_.WhenCreated -lt (Get-Date).AddDays(-$CreationGrace)
				IsBadEncryption      = ($_.'msDS-SupportedEncryptionTypes' -band 7) -and -not ($_.'msDS-SupportedEncryptionTypes' -band 56)
			}
		}
	}
}

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
			$members = Get-ADObject -LDAPFilter "(&(objectSID=*)(memberof:1.2.840.113556.1.4.1941:=$($relevantGroup.DistinguishedName)))" -Properties ObjectSID, SamAccountName
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

function Export-UnhealthyUserReport {
	[CmdletBinding()]
	param (
		$Users,

		$Privileged,

		[string]
		$Path,

		[string[]]
		$Checks
	)

	if (-not $Users) { return }

	$checkPropertyMap = @{
		LastLogon       = 'IsLateLogon'
		PwdLastSet      = 'IsOldPassword'
		NeverExpires    = 'IsNonExpiring'
		NeverLoggedIn   = 'IsNoLogon'
		EncryptionTypes = 'IsBadEncryption'
	}

	foreach ($user in $Users) {
		$privilegedEntries = $Privileged | Where-Object MemberDN -EQ $user.DistinguishedName
		$isPrivileged = $privilegedEntries -as [bool]

		Add-Member -InputObject $user -MemberType NoteProperty -Name IsPrivileged -Value $isPrivileged -Force
		Add-Member -InputObject $user -MemberType NoteProperty -Name PrivilegedGroups -Value ($privilegedEntries.GroupName -join ', ') -Force
	}

	$summaryEntries = foreach ($check in $Checks) {
		$applicable = $Users | Where-Object $checkPropertyMap[$check]

		[PSCustomObject]@{
			Check      = $check
			Total      = @($applicable).Count
			Enabled    = @($applicable).Where{ $_.Enabled }.Count
			Disabled   = @($applicable).Where{ -not $_.Enabled }.Count
			Privileged = @($applicable).Where{ $_.IsPrivileged }.Count
		}
	}

	$summaryEntries | Export-Excel -Path $Path -WorksheetName Summary
	$Users | Export-Excel -Path $Path -WorksheetName Global
	foreach ($check in $Checks) {
		$Users | Where-Object $checkPropertyMap[$check] | Export-Excel -Path $Path -WorksheetName $check
	}
}
#endregion Functions

$privilegedUsers = Get-ADPrivilegedPrincipal @adParam
$unhealthyUsers = Get-ADUnhealthyUser @adParam -Checks $Checks -LogonThreshold $LogonThreshold -PasswordThreshold $PasswordThreshold -CreationGrace $CreationGrace
Export-UnhealthyUserReport -Users $unhealthyUsers -Privileged $privilegedUsers -Path $OutPath -Checks $Checks