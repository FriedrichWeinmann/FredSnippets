<#
.SYNOPSIS
	Scans an Active Directory domain's and its principal's kerberos encryption configuration.

.DESCRIPTION
	Scans an Active Directory domain's and its principal's kerberos encryption configuration.
	It will generate all data via LDAP, and analyze the results for possible authentication issues.

	It supports three ways to report:
	- Print:    Write analysis of results to screen
	- PassThru: Return result objects for manual processing
	- OutPath:  Generate report files

	Generally, it is recommended to at least also generate a report via -OutPath, as that allows investigating
	issues at your leissure.
	Most notably, the summary file contains a per-domain summary of what was found,
	the items file can then be used to look up affected AD objects.

	The listed Columns are:

	+ Domain
	+ Total
	+ CountLegacyOS
	+ CountDefaultSET
	+ CountDefaultExtendedSET
	+ CountDefaultSuperSET
	+ CountWeakEncryption
	+ CountDCnoRC4
	+ CountTooOldPassword

	> Domain
	Name of the Domain Scanned

	> Total
	Number of principals found

	> CountLegacyOS
	Number of windows computers that cannot support anything later than RC4.
	Disabling RC4 on your DCs will prevent authentication for machines affected by this.
	Verify these computers are still relevant and migrate them as soon as possible:
	They are an active security risk to your environment!

	> CountDefaultSET
	Number of machines that use the domain default Supported Encryption Types.
	Before the November 2022 Update, these machines would receive both a RC4 and an Aes Session Key.
	After the update they will only receive the default encrypted type (usually AES).
	If they cannot support that, authentication will fail.
	Try migrating the account (or service backing it) to support AES.
	To mitigate, update the 'msDS-SupportedEncryptionType' attribute to include the required encryption types
	Details: https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/what-happened-to-kerberos-authentication-after-installing-the/ba-p/3696351

	> CountDefaultExtendedSET
	Number of machines that have no supported encryption types configured but use some advanced flags
	on the same ad attribute.
	After the November 2022 update they will NOT BE ABLE TO AUTHENTICATE (or authenticated to) at all.
	To fix, update the 'msDS-SupportedEncryptionType' attribute to include actual encryption types
	Details: https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/what-happened-to-kerberos-authentication-after-installing-the/ba-p/3696351

	> CountDefaultSuperSET
	Sum of the two above.

	> CountWeakEncryption
	Number of accounts that are limited to RC4 or weaker algorithms.
	Consider migrating / replacing these accounts, as they will no longer be able to authenticate
	when you disable RC4, even if the updates themselves will not automatically affect them.

	> CountDCnoRC4
	Number of Domain Controllers that do not support RC4.
	This is not an issue if no account still depends on RC4.

	> CountTooOldPassword
	Number of accounts with passwords from before the domain supported AES.
	These will be affected by the change, if they are set to default, as after the update,
	their RC4 session keys will no longer be considered valid.
	Change the password once and this should not be a problem.


	This script was based on the original post and code under the following MSFT post:
	https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/what-happened-to-kerberos-authentication-after-installing-the/ba-p/3696351

.PARAMETER Server
	Domain(s) to scan. Specify domain controller FQDN instead of domain name to specify an exact server to work with.
	Defaults to $env:USERDNSDOMAIN

.PARAMETER Credential
	Credentials to use for scans.
	All requests wiill use the current user's identity if not specified.

.PARAMETER OutPath
	The path where to write the results to.
	Must be an existing folder.

.PARAMETER PassThru
	Return a result object, containing all the data o a given domain.

.PARAMETER Print
	Print the analysis result of the scan on screen.
	This will be returned as string to output, unless also -PassThru is specified, in which case it will be printed with Out-Host.
	To access the printed analysis string (including advice) from the objects returned by -PassThru, call the Print() method on the object.

.PARAMETER Delimiter
	CSV Delimiter on CSV-based result files.

.EXAMPLE
	PS C:\> .\DomainCryptographyScan.ps1 -OutPath .

	Scan the current domain and write the results to the current path.

.EXAMPLE
	PS C:\> .\DomainCryptographyScan.ps1 -OutPath . -PassThru -Server (Get-ADForest).Domains

	Scan all domains in the current forest and write the results to the current path.
	Also returns result objects for each domain.

.EXAMPLE
	PS C:\> .\DomainCryptographyScan.ps1 -Print

	Scan the current domain and print the results to screen.

.LINK
	https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/what-happened-to-kerberos-authentication-after-installing-the/ba-p/3696351

.LINK
	https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/decrypting-the-selection-of-supported-kerberos-encryption-types/ba-p/1628797

.LINK
	https://github.com/takondo/11Bchecker/blob/main/Check-11Bissues.ps1
#>
[CmdletBinding()]
param (
	[string[]]
	$Server = $env:USERDNSDOMAIN,

	[PSCredential]
	$Credential,

	[ValidateScript({
			if (Test-Path -Path $_ -PathType Container) { return $true }
			Write-Warning "Not an existing folder: $_"
			throw "Not an existing folder: $_"
		})]
	[string]
	$OutPath,

	[switch]
	$PassThru,

	[switch]
	$Print,

	[string]
	$Delimiter = ','
)

if (-not ($OutPath -or $PassThru -or $Print)) {
	throw "None of the result parameters were specified! Specify at least one of '-OutPath', '-PassThru', '-Print'"
}

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script Failed: $_"
	throw $_
}

$PSDefaultParameterValues['Export-Csv:Delimiter'] = $Delimiter

#region Classes
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
[Flags()] enum EncryptionType {
	Default = 0x0
	DesCrc = 0x1
	DesMd5 = 0x2
	RC4 = 0x4
	Aes128 = 0x8
	Aes256 = 0x10
	Aes256SK = 0x20

	SupFast = 0x10000
	SupCompoundIdentity = 0x20000
	SupClaims = 0x40000
	ResourceSIDCompressionDisabled = 0x80000
}

class ADPrincipalCryptoConfiguration {
	[string] $Name
	[EncryptionType] $Encryption
	[string] $ObjectClass
	[string] $DistinguishedName
	[string] $Domain
	[object] $PwdLastSet
	[DateTime] $LastLogonTime
	[string] $OperatingSystem
	[string] $OperatingSystemVersion

	[object] $InputObject

	hidden [DomainData] $DomainObject

	ADPrincipalCryptoConfiguration([object]$Object, [DomainData]$Domain) {
		$this.Name = $Object.SamAccountName
		$this.Domain = $Domain.Name
		$this.DomainObject = $Domain
		$this.ObjectClass = $Object.ObjectClass
		$this.DistinguishedName = $Object.DistinguishedName
		try { $this.Encryption = $Object.'msDS-SupportedEncryptionTypes' -as [int] }
		catch {
			Write-Warning "Invalid msDS-SupportedEncryptionTypes value: $($Object.'msDS-SupportedEncryptionTypes') ($($Object.DistinguishedName))"
			throw
		}
		$this.PwdLastSet = $Object.PwdLastSet
		try { $this.LastLogonTime = [DateTime]::FromFileTimeUtc($Object.LastLogonTimestamp) }
		catch { $this.LastLogonTime = [datetime]::MinValue }

		if ($Object.ObjectClass -eq 'Computer') {
			$this.OperatingSystem = $Object.OperatingSystem
			$this.OperatingSystemVersion = $Object.OperatingSystemVersion
		}
		$this.InputObject = $Object
	}
}

$common = @{
	TypeName   = 'ADPrincipalCryptoConfiguration'
	MemberType = 'ScriptProperty'
	Force      = $true
}
Update-TypeData @common -MemberName HasLegacyOS -Value {
	if ($this.ObjectClass -ne 'computer') { return $false }

	return (
		$this.InputObject.OperatingSystem -match 'Windows' -and
		6 -gt ($this.InputObject.OperatingSystemVersion -replace '\..+')
	)
}
Update-TypeData @common -MemberName HasVersionLess6 -Value {
	if ($this.ObjectClass -ne 'computer') { return $false }

	return (
		-not $this.InputObject.OperatingSystemVersion -or
		-not (($this.InputObject.OperatingSystemVersion -replace '\..+') -as [int]) -or
		6 -gt ($this.InputObject.OperatingSystemVersion -replace '\..+')
	)
}
Update-TypeData @common -MemberName HasDefaultSET -Value {
	$bad = [EncryptionType]::Default
	return $this.Encryption -EQ $bad
}
Update-TypeData @common -MemberName HasDefaultExtendedSET -Value {
	$bad = [EncryptionType]::Default
	$encryption = [EncryptionType]'DesCrc, DesMd5, RC4, Aes128, Aes256'
	return $this.Encryption -EQ $bad -and -not ($this.Encryption -band $encryption)
}
Update-TypeData @common -MemberName HasWeakEncryption -Value {
	$strongTypes = [EncryptionType]'Aes128, Aes256'
	$weakTypes = [EncryptionType]'DesCrc, DesMd5, RC4'
	return $this.Encryption -band $weakTypes -and -not ($this.Encryption -band $strongTypes)
}
Update-TypeData @common -MemberName HasTooOldPassword -Value {
	$this.PwdLastSet -and $this.PwdLastSet -lt $this.DomainObject.AesSupported
}
Update-TypeData @common -MemberName IsDC -Value {
	$this.ObjectClass -eq 'computer' -and $this.InputObject.UserAccountControl -band 2000
}
Update-TypeData @common -MemberName IsDCRC4Disabled -Value {
	$rc4 = [EncryptionType]::RC4
	return (
		$this.ObjectClass -eq 'computer' -and
		$this.InputObject.UserAccountControl -band 2000 -and
		-not ($this.Encryption -band $rc4)
	)
}

class DomainData {
	[string] $Name
	[DateTime] $AesSupported

	[ADPrincipalCryptoConfiguration[]] $Computers
	[ADPrincipalCryptoConfiguration[]] $Users
	[ADPrincipalCryptoConfiguration[]] $ServiceAccounts

	hidden [string] $Server
	hidden [PSCredential] $Credential



	[hashtable] GetParam() {
		$hash = @{
			Server = $this.Server
		}
		if ($this.Credential) { $hash.Credential = $this.Credential }
		return $hash
	}

	[ADPrincipalCryptoConfiguration[]] GetAll()	{
		return (@($this.Computers) + @($this.Users) + @($this.ServiceAccounts) | Write-Output | Where-Object { $_ })
	}

	[object] GetSummary() {
		return [PSCustomObject]@{
			Domain                  = $this.Name
			Total                   = $this.GetAll().Count
			CountLegacyOS           = $this.GetCaseLegacyOS().Count
			CountOSLessV6           = $this.GetCaseOSLessV6().Count
			CountDefaultSET         = $this.GetCaseDefaultSET().Count
			CountDefaultExtendedSET = $this.GetCaseDefaultExtendedSET().Count
			CountDefaultSuperSET    = $this.GetCaseDefaultSuperSET().Count
			CountWeakEncryption     = $this.GetCaseWeakEncryption().Count
			CountDCnoRC4            = $this.GetCaseDCnoRC4().Count
			CountTooOldPassword     = $this.GetCaseTooOldPassword().Count
		}
	}

	#region Case Methods
	[ADPrincipalCryptoConfiguration[]] GetCaseLegacyOS() {
		return $this.Computers | Where-Object {
			$_.InputObject.OperatingSystem -match 'Windows' -and
			6 -gt ($_.InputObject.OperatingSystemVersion -replace '\..+')
		}
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseOSLessV6() {
		return $this.Computers | Where-Object {
			-not $_.InputObject.OperatingSystemVersion -or
			-not (($_.InputObject.OperatingSystemVersion -replace '\..+') -as [int]) -or
			6 -gt ($_.InputObject.OperatingSystemVersion -replace '\..+')
		}
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseDefaultSET() {
		$bad = [EncryptionType]::Default
		return $this.GetAll() | Where-Object Encryption -EQ $bad
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseDefaultExtendedSET() {
		$bad = [EncryptionType]::Default
		$encryption = [EncryptionType]'DesCrc, DesMd5, RC4, Aes128, Aes256'
		return $this.GetAll() | Where-Object {
			$_.Encryption -ne $bad -and
			-not ($_.Encryption -band $encryption)
		}
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseDefaultSuperSET() {
		$encryption = [EncryptionType]'DesCrc, DesMd5, RC4, Aes128, Aes256'
		return $this.GetAll() | Where-Object {
			-not ($_.Encryption -band $encryption)
		}
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseWeakEncryption() {
		$strongTypes = [EncryptionType]'Aes128, Aes256'
		$weakTypes = [EncryptionType]'DesCrc, DesMd5, RC4'
		return $this.GetAll() | Where-Object {
			$_.Encryption -band $weakTypes -and
			-not ($_.Encryption -band $strongTypes)
		}
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseDCnoRC4() {
		$rc4 = [EncryptionType]::RC4
		return $this.Computers | Where-Object {
			$_.InputObject.UserAccountControl -band 2000 -and
			-not ($_.Encryption -band $rc4)
		}
	}

	[ADPrincipalCryptoConfiguration[]] GetCaseTooOldPassword() {
		return $this.GetAll() | Where-Object {
			$_.PwdLastSet -as [datetime] -and
			$_.PwdLastSet -LT $this.AesSupported
		}
	}
	#endregion Case Methods

	[string] Print() {
		#region Functions
		function Add-Indent {
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[string]
				$Text,

				[Parameter(Mandatory = $true)]
				[string]
				$Indent
			)

			$lines = foreach ($line in $Text -split "[\n\r]+") {
				'{0}{1}' -f $Indent, $line
			}
			$lines -join "`n"
		}
		function Write-ByType {
			[CmdletBinding()]
			param (
				$Entities
			)

			$grouped = $Entities | Group-Object ObjectClass
			$lines = foreach ($group in $grouped) {
				'{0}: {1}' -f $group.Name, ($group.Group.Name -join ", ")
			}
			$lines -join "`n"
		}
		#endregion Functions

		$main = @'


# {0}
#------------------------------

{1}
'@
		$findings = @()
		$activeLimit = (Get-Date).AddDays(-180)

		#region Legacy OS
		if ($legacy = $this.GetCaseLegacyOS()) {
			$legacyOSString = $legacy | Group-Object { $_.InputObject.OperatingSystem } | Select-Object @(
				'Count'
				@{ Name = 'CountActive'; Expression = { ($_.Group | Where-Object { $activeLimit -gt $_.LastLogonTime }).Count }}
				@{ Name = 'OSVersion'; Expression = { $_.Group[0].OperatingSystemVersion }}
				'Name'
			) | Out-String
			$legacyOSString = Add-Indent -Text $legacyOSString -Indent '  '
			$computerNameString = $legacy.Name -join ", "
			$findings += @'

## Legacy Windows Version Detected!
These OS are not compatible with the new behavior, and authentication to this computer will fail after installing Windows Update released on November 2022 or newer on DCs:
{0}

{1}
'@ -f $legacyOSString, $computerNameString
		}
		#endregion Legacy OS

		#region OS Version Less than 6
		if ($legacy = $this.GetCaseOSLessV6()) {
			$legacyOSString = $legacy | Group-Object { $_.InputObject.OperatingSystem } | Select-Object @(
				'Count'
				@{ Name = 'CountActive'; Expression = { ($_.Group | Where-Object { $activeLimit -gt $_.LastLogonTime }).Count }}
				@{ Name = 'OSVersion'; Expression = { $_.Group[0].OperatingSystemVersion }}
				'Name'
			) | Out-String
			$legacyOSString = Add-Indent -Text $legacyOSString -Indent '  '
			$computerNameString = $legacy.Name -join ", "
			$findings += @'

## OS with version lower than 6!
TGS for connecting to this computer will ignore msDS-SupportedEncryptionTypes on the computer account and use the Domain Default setting.
Whether connections can be established or not depends on whether the actual computer accounts support the domain default setting!
{0}

{1}
'@ -f $legacyOSString, $computerNameString
		}
		#endregion OS Version Less than 6

		#region Default Supported Encryption Types
		# Computers, Users or Service Accounts with the default ET
		$badEntities = $this.GetCaseDefaultSET()
		if ($badEntities) {
			$findings += @'

## Principals with default Supported Encryption Types Detected!
There are {0} objects that do not have msDS-SupportedEncryptionTypes configured or is set to zero.
When authenticating to this target, Kerberos will use the DefaultDomainSupportedEncTypes registry value on the authenticating DC to determinte supported etypes.
If the registry value is not configured, the default value is 0x27, which means 'use AES for session keys and RC4 for ticket encryption'
  - If this target server does not support AES, you must set msDS-SupportedEncryptionTypes to 4 on this object so that only RC4 is used.
    (Please consider working with your vendor to upgrade or configure this server to support AES. Using RC4 is not recommended)
  - If this target server does not support RC4, or you have disabled RC4 on DCs, please set DefaultDomainSupportedEncTypes on DCs to 0x18
    or msDS-SupportedEncryptionTypes on this object to 0x18 to specify that AES must be used. The target server must support AES in this case.
Here are the objects that do not have msDS-SupportedEncryptionTypes configured:

'@ -f $badEntities.Count
			$findings += Write-ByType -Entities $badEntities
		}
		#endregion Default Supported Encryption Types

		#region Extended SET
		# Computers, Users or Service Accounts with the extended ET, but no actual ET
		$badEntities2 = $this.GetCaseDefaultExtendedSET()
		if ($badEntities2) {
			$findings += @'

## Principals without Supported Encryption Types Detected, that do define complex flags on the SET field!
There are {0} objects that have msDS-SupportedEncryptionTypes configured, but no etypes are enabled.
etypes are configured in the low 6 bits of msDS-SupportedEncryptionTypes, and having a value configured without etypes can cause authentication to/from this object to fail.
Please either delete the existing msDS-SupportedEncryptionTypes settings, or add supported etypes to the existing msDS-SupportedEncryptionTypes value.
Example: Add 0x1C (or 28 in decimal) to signal support for AES128, AES256, and RC4
Here are the objects with no etypes enabled:

'@ -f $badEntities2.Count
			$findings += Write-ByType -Entities $badEntities2
		}
		#endregion Extended SET

		#region Weak Encryption Only
		# Computers, Users or Service Accounts without AES but also no default ET
		$weakEntities = $this.GetCaseWeakEncryption()
		if ($weakEntities) {
			$findings += @'

## Weak Encryption Only Enabled
There are {0} objects that are configured for RC4 or DES only.
Authentication to this target can fail if AES is required by either the client or the DC.
We do not recommend the use of RC4. Please consider working with your vendor to upgrade or configure this server to support AES.
Here are the objects that are configured for RC4 only:
'@ -f $weakEntities.Count
			$findings += Write-ByType -Entities $weakEntities
		}
		#endregion Weak Encryption Only

		#region DCs without RC4
		# DCs without RC4
		$dcNoRC4 = $this.GetCaseDCnoRC4()
		if ($dcNoRC4) {
			$findings += @'

## DCs with RC4 disabled detected
In this environment, Kerberos authentication can fail if the target server/service does not have msDS-SupportedEncryptionTypes configured,
or has configured msDS-SupportedEncryptionTypes and has explitcitly enabled only RC4.
Setting the DefaultDomainSupportedEncTypes registry value on DCs to 0x18 will set the default supported etypes to AES only,
and may prevent Kerberos authentication issues due to unexpected RC4 use after installing November 2022 update or newer on DCs.
Here are the DCs that have RC4 disabled:

{0}
'@ -f ($dcNoRC4.Name -join ", ")
		}
		#endregion DCs without RC4

		#region Password too old
		# Computers, Users or Service Accounts with passwords older than the domain's AES capability
		$badPasswordCrypto = $this.GetCaseTooOldPassword()
		if ($badPasswordCrypto) {
			$findings += @'

## Objects with too old passwords for AES detected
There are {0} objects that do not have AES Keys generated.
This can occur if the account's password has not been changed after adding Server 2008 or newer DCs
Authentication to this target can fail if AES is required by either the client or the KDC.
Please change/reset the accounts' password, and AES keys will be automatically generated. 
Here are the objects with no AES keys
'@
			$findings += Write-ByType -Entities $badPasswordCrypto
		}
		#endregion Password too old

		$findingsString = Add-Indent -Text ($findings -join "`n") -Indent '  '

		return $main -f $this.Name, $findingsString
	}
}
#endregion Classes

#region Functions
function Get-LdapObject {

	<#
        .SYNOPSIS
            Use LDAP to search in Active Directory

        .DESCRIPTION
            Utilizes LDAP to perform swift and efficient LDAP Queries.

        .PARAMETER LdapFilter
            The search filter to use when searching for objects.
            Must be a valid LDAP filter.

        .PARAMETER Property
            The properties to retrieve.
            Keep bandwidth in mind and only request what is needed.

        .PARAMETER SearchRoot
            The root path to search in.
            This generally expects either the distinguished name of the Organizational unit or the DNS name of the domain.
            Alternatively, any legal LDAP protocol address can be specified.

        .PARAMETER Configuration
            Rather than searching in a specified path, switch to the configuration naming context.

        .PARAMETER Raw
            Return the raw AD object without processing it for PowerShell convenience.

        .PARAMETER PageSize
            Rather than searching in a specified path, switch to the schema naming context.

        .PARAMETER MaxSize
            The maximum number of items to return.

        .PARAMETER SearchScope
            Whether to search all OUs beneath the target root, only directly beneath it or only the root itself.
	
		.PARAMETER AddProperty
			Add additional properties to the output object.
			Use to optimize performance, avoiding needing to use Add-Member.

        .PARAMETER Server
            The server to contact for this query.

        .PARAMETER Credential
            The credentials to use for authenticating this query.
	
		.PARAMETER TypeName
			The name to give the output object

        .EXAMPLE
            PS C:\> Get-LdapObject -LdapFilter '(PrimaryGroupID=516)'
            
            Searches for all objects with primary group ID 516 (hint: Domain Controllers).
    #>
	[Alias('ldap')]
	[CmdletBinding(DefaultParameterSetName = 'SearchRoot')]
	param (
		[Parameter(Mandatory = $true, Position = 0)]
		[string]
		$LdapFilter,
		
		[Alias('Properties')]
		[string[]]
		$Property = "*",
		
		[Parameter(ParameterSetName = 'SearchRoot')]
		[Alias('SearchBase')]
		[string]
		$SearchRoot,
		
		[Parameter(ParameterSetName = 'Configuration')]
		[switch]
		$Configuration,
		
		[switch]
		$Raw,
		
		[ValidateRange(1, 1000)]
		[int]
		$PageSize = 1000,
		
		[Alias('SizeLimit')]
		[int]
		$MaxSize,
		
		[System.DirectoryServices.SearchScope]
		$SearchScope = 'Subtree',
		
		[System.Collections.Hashtable]
		$AddProperty,
		
		[string]
		$Server,
		
		[PSCredential]
		$Credential,
		
		[Parameter(DontShow = $true)]
		[string]
		$TypeName
	)
	
	begin {
		#region Utility Functions
		function Get-PropertyName {
			[OutputType([string])]
			[CmdletBinding()]
			param (
				[string]
				$Key,
				
				[string[]]
				$Property
			)
			
			if ($hit = @($Property).Where{ $_ -eq $Key }) { return $hit[0] }

			switch ($Key) {
				ObjectClass { 'ObjectClass' }
				ObjectGuid { 'ObjectGuid' }
				ObjectSID { 'ObjectSID' }
				DistinguishedName { 'DistinguishedName' }
				SamAccountName { 'SamAccountName' }
				PwdLastSet { 'PwdLastSet' }
				default { $script:culture.TextInfo.ToTitleCase($Key) }
			}
		}
		
		function New-DirectoryEntry {
			<#
        .SYNOPSIS
            Generates a new directoryy entry object.
        
        .DESCRIPTION
            Generates a new directoryy entry object.
        
        .PARAMETER Path
            The LDAP path to bind to.
        
        .PARAMETER Server
            The server to connect to.
        
        .PARAMETER Credential
            The credentials to use for the connection.
        
        .EXAMPLE
            PS C:\> New-DirectoryEntry

            Creates a directory entry in the default context.

        .EXAMPLE
            PS C:\> New-DirectoryEntry -Server dc1.contoso.com -Credential $cred

            Creates a directory entry in the default context of the target server.
            The connection is established to just that server using the specified credentials.
    #>
			[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
			[CmdletBinding()]
			param (
				[string]
				$Path,
		
				[AllowEmptyString()]
				[string]
				$Server,
		
				[PSCredential]
				[AllowNull()]
				$Credential
			)
	
			if (-not $Path) { $resolvedPath = '' }
			elseif ($Path -like "LDAP://*") { $resolvedPath = $Path }
			elseif ($Path -notlike "*=*") { $resolvedPath = "LDAP://DC={0}" -f ($Path -split "\." -join ",DC=") }
			else { $resolvedPath = "LDAP://$($Path)" }
	
			if ($Server -and ($resolvedPath -notlike "LDAP://$($Server)/*")) {
				$resolvedPath = ("LDAP://{0}/{1}" -f $Server, $resolvedPath.Replace("LDAP://", "")).Trim("/")
			}
	
			if (($null -eq $Credential) -or ($Credential -eq [PSCredential]::Empty)) {
				if ($resolvedPath) { New-Object System.DirectoryServices.DirectoryEntry($resolvedPath) }
				else {
					$entry = New-Object System.DirectoryServices.DirectoryEntry
					New-Object System.DirectoryServices.DirectoryEntry(('LDAP://{0}' -f $entry.distinguishedName[0]))
				}
			}
			else {
				if ($resolvedPath) { New-Object System.DirectoryServices.DirectoryEntry($resolvedPath, $Credential.UserName, $Credential.GetNetworkCredential().Password) }
				else { New-Object System.DirectoryServices.DirectoryEntry(("LDAP://DC={0}" -f ($env:USERDNSDOMAIN -split "\." -join ",DC=")), $Credential.UserName, $Credential.GetNetworkCredential().Password) }
			}
		}
		#endregion Utility Functions
		
		$script:culture = Get-Culture

		#region Prepare Searcher
		$searcher = New-Object system.directoryservices.directorysearcher
		$searcher.PageSize = $PageSize
		$searcher.SearchScope = $SearchScope
		
		if ($MaxSize -gt 0) {
			$Searcher.SizeLimit = $MaxSize
		}
		
		if ($SearchRoot) {
			$searcher.SearchRoot = New-DirectoryEntry -Path $SearchRoot -Server $Server -Credential $Credential
		}
		else {
			$searcher.SearchRoot = New-DirectoryEntry -Server $Server -Credential $Credential
		}
		if ($Configuration) {
			$searcher.SearchRoot = New-DirectoryEntry -Path ("LDAP://CN=Configuration,{0}" -f $searcher.SearchRoot.distinguishedName[0]) -Server $Server -Credential $Credential
		}
		
		Write-Verbose "Searching $($SearchScope) in $($searcher.SearchRoot.Path)"
		
		if ($Credential) {
			$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($searcher.SearchRoot.Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
		}
		
		$searcher.Filter = $LdapFilter
		
		foreach ($propertyName in $Property) {
			$null = $searcher.PropertiesToLoad.Add($propertyName)
		}
		
		Write-Verbose "Search filter: $LdapFilter"
		#endregion Prepare Searcher
	}
	process {
		try {
			$ldapObjects = $searcher.FindAll()
		}
		catch {
			throw
		}
		foreach ($ldapobject in $ldapObjects) {
			if ($Raw) {
				$ldapobject
				continue
			}
			#region Process/Refine Output Object
			$resultHash = @{ }
			foreach ($key in $ldapobject.Properties.Keys) {
				$resultHash[(Get-PropertyName -Key $key -Property $Property)] = switch ($key) {
					'ObjectClass' { $ldapobject.Properties[$key][@($ldapobject.Properties[$key]).Count - 1] }
					'ObjectGuid' { [guid]::new(([byte[]]($ldapobject.Properties[$key] | Write-Output))) }
					'ObjectSID' { [System.Security.Principal.SecurityIdentifier]::new(([byte[]]($ldapobject.Properties[$key] | Write-Output)), 0) }
					'UserCertificate' {
						foreach ($certificate in $ldapobject.Properties[$key]) {
							[System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
						}
					}
					'PwdLastSet' {
						try { [DateTime]::FromFileTimeUtc($ldapobject.Properties[$key][0]) }
						catch { $ldapobject.Properties[$key][0] }
					}
						
					default { $ldapobject.Properties[$key] | Write-Output }
				}
			}
			if ($resultHash.ContainsKey("ObjectClass")) { $resultHash["PSTypeName"] = $resultHash["ObjectClass"] }
			if ($TypeName) { $resultHash["PSTypeName"] = $TypeName }
			if ($AddProperty) { $resultHash += $AddProperty }
			$item = [pscustomobject]$resultHash
			Add-Member -InputObject $item -MemberType ScriptMethod -Name ToString -Value {
				if ($this.DistinguishedName) { $this.DistinguishedName }
				else { $this.AdsPath }
			} -Force -PassThru
			#endregion Process/Refine Output Object
		}
	}
}

function Get-DomainData {
	[OutputType([DomainData])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Server,

		[PSCredential]
		$Credential,

		[switch]
		$Continue
	)

	$domainData = [DomainData]::new()
	$domainData.Server = $Server
	$domainData.Credential = $Credential
	$param = $domainData.GetParam()
	try { $domainObject = Get-LdapObject @param -LdapFilter '(objectClass=domainDNS)' -Property DistinguishedName, ObjectSID }
	catch { 
		if (-not $Continue) { throw }
		Write-Warning "Error accessing $Server : $_"
		continue
	}

	$readOnlyDCSID = '{0}-521' -f $domainObject.ObjectSID
	$roDCGroup = Get-LdapObject @param -LdapFilter "(objectSID=$readOnlyDCSID)" -Property WhenCreated

	$domainData.Name = $domainObject.DistinguishedName -replace '^DC=' -replace ',DC=', '.'
	$domainData.AesSupported = $roDCGroup.WhenCreated

	$domainData
}

function Get-PrincipalCryptoData {
	[CmdletBinding()]
	param (
		[DomainData]
		$Domain,

		[string]
		$ObjectCategory,

		[Alias('Property')]
		[string[]]
		$Properties
	)

	$param = $Domain.GetParam()
	$param += @{
		LdapFilter = "(&(samAccountName=*)(objectCategory=$ObjectCategory)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
		Property   = 'SamAccountName', 'ObjectClass', 'DistinguishedName', 'msDS-SupportedEncryptionTypes', 'pwdLastSet', 'LastLogonTimestamp'
	}
	if ($Properties) { $param.Property = @($param.Property) + @($Properties) | Sort-Object -Unique }

	foreach ($object in Get-LdapObject @param) {
		try { [ADPrincipalCryptoConfiguration]::new($object, $Domain) }
		catch { Write-Warning "Error generating dataset for $($object.DistinguishedName): $_" }
	}
}

function Write-DomainResult {
	[CmdletBinding()]
	param (
		[string]
		$Path,

		[switch]
		$PassThru,

		[switch]
		$Print,

		[Parameter(ValueFromPipeline = $true)]
		[DomainData[]]
		$DomainData
	)

	process {
		foreach ($domainDatum in $DomainData) {
			if ($PassThru) { $domainDatum }
			if ($Print) {
				if ($PassThru) { $domainDatum.Print() | Out-Host }
				else { $domainDatum.Print() }
			}

			if (-not $Path) { continue }

			# Report / Print
			$reportPath = Join-Path -Path $Path -ChildPath "report-$($domainDatum.Name).txt"
			$domainDatum.Print() | Set-Content -Path $reportPath

			# Item Export
			$principals = $domainDatum.GetAll()
			if (-not $principals) { Write-Warning "No Items found for $($domainDatum.Name)! Probably a weird bug you want to investigate." }
			else {
				## CSV
				$csvItemPath = Join-Path -Path $Path -ChildPath "items-$($domainDatum.Name).csv"
				$principals | Export-Csv -Path $csvItemPath
			}

			# Summary
			$summaryPath = Join-Path -Path $Path -ChildPath 'summary.csv'
			$domainDatum.GetSummary() | Export-Csv -Path $summaryPath -Append
		}
	}
}
#endregion Functions

$domains = foreach ($serverName in $Server) {
	$domainData = Get-DomainData -Server $serverName -Credential $Credential -Continue
	$domainData.Computers = Get-PrincipalCryptoData -ObjectCategory 'computer' -Domain $domainData -Properties OperatingSystem, OperatingSystemVersion, UserAccountControl
	$domainData.Users = Get-PrincipalCryptoData -ObjectCategory 'user' -Domain $domainData
	$domainData.ServiceAccounts = Get-PrincipalCryptoData -ObjectCategory 'msDS-GroupManagedServiceAccount' -Domain $domainData
	$domainData
}
$domains | Write-DomainResult -Path $OutPath -PassThru:$PassThru -Print:$Print