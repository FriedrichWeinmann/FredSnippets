
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