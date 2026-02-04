#requires -RunAsAdministrator
<#
.SYNOPSIS
	Requests a computer certificate and store it to disk as pfx.

.DESCRIPTION
	Requests a computer certificate and store it to disk as pfx.
	Some of the settings - TemplateName, CA & PrintPW - can be define via config file.
	The file must be named "config.psd1" and stored in the same path as the script.

	Example config:
	@{
		# The Default CA to use
		CA = 'pki.contoso.com/MS-CA-CON-01'

		# The Default Template to use
		TemplateName = 'ContosoServerCertificate'

		# Print all Passwords to Screen
		# PrintPW = $true
	}

.PARAMETER Subject
	The subject of the certificate to request.
	Do NOT include the "CN=" prefix!
	Generally the FQDN of the computer to get the certificate for.

.PARAMETER OutPath
	The path where the PFX file should be generated.
	Will be prompted via UI for a path if not specified.

.PARAMETER Password
	The password to protect the PFX file with.
	If not specified, a strong password will be generated and written to clipboard.

.PARAMETER TemplateName
	Name of the certificate template to request the certificate under.
	Expects the name, but will also resolve the DisplayName, unless disabled via -DontResolveTemplate
	Will be prompted for a template if not specified.
	Can be defined via config file.

.PARAMETER CA
	The CA to request the certificate from.
	Will be prompted for a CA if not specified.
	Can be defined via config file.

.PARAMETER PrintPW
	Whether the password should be printed on the console screen.
	Can be defined via config file.

.PARAMETER DontResolveTemplate
	Do not resolve the provided template name.
	Useful if the provided template cannot be resolved, or as performance improvement, if it has been previously resolved.

.EXAMPLE
	PS C:\> .\request-computer-certificate.ps1

	Requests, receives and exports a computer certificate.
	User will be prompted for the subject, which CA to use, which template to use and where to store the certificate.
	The password will be written to clipboard.
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string]
	$Subject,

	[string]
	$OutPath,

	[SecureString]
	$Password,

	[string]
	$TemplateName,

	[string[]]
	$CA,

	[switch]
	$PrintPW,

	[switch]
	$DontResolveTemplate
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script Failed: $_"
	Remove-Item -Path $workingDirectory -Force -Recurse -ErrorAction SilentlyContinue
	throw $_
}

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
			if ($Key -eq 'ObjectClass') { return 'ObjectClass' }
			if ($Key -eq 'ObjectGuid') { return 'ObjectGuid' }
			if ($Key -eq 'ObjectSID') { return 'ObjectSID' }
			if ($Key -eq 'DistinguishedName') { return 'DistinguishedName' }
			if ($Key -eq 'SamAccountName') { return 'SamAccountName' }
			$script:culture.TextInfo.ToTitleCase($Key)
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
		
		Write-PSFMessage -Level InternalComment -String 'Get-LdapObject.Search' -StringValues $SearchScope, $searcher.SearchRoot.Path
		
		if ($Credential) {
			$searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry($searcher.SearchRoot.Path, $Credential.UserName, $Credential.GetNetworkCredential().Password)
		}
		
		$searcher.Filter = $LdapFilter
		
		foreach ($propertyName in $Property) {
			$null = $searcher.PropertiesToLoad.Add($propertyName)
		}
		
		Write-PSFMessage -String 'Get-LdapObject.Filter' -StringValues $ldapFilter
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
					'ObjectGuid' { [guid]::new(([byte[]]($($ldapobject.Properties[$key])))) }
					'ObjectSID' { [System.Security.Principal.SecurityIdentifier]::new(([byte[]]$($ldapobject.Properties[$key])), 0) }
						
					default { $($ldapobject.Properties[$key]) }
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
function Get-PkiTemplate {
	<#
	.SYNOPSIS
		Retrieve templates from Active Directory.
	
	.DESCRIPTION
		Retrieve templates from Active Directory.
		Templates are stored forest-wide and selectively made available to CAs.
		This command retrieves the global list.
	
	.PARAMETER Server
		The domain or server to contact.
	
	.PARAMETER Credential
		The credential to use for the request.
	
	.EXAMPLE
		PS C:\> Get-PkiTemplate

		Retrieve all templates from the current forest.
	#>
	[CmdletBinding()]
	param (
		[string]
		$Server,

		[PSCredential]
		$Credential
	)
	process {
		$param = @{}
		if ($Server) { $param.Server = $Server }
		if ($Credential) { $param.Credential = $Credential }
		$param.LdapFilter = '(objectClass=pKICertificateTemplate)'
		$param.TypeName = 'PkiExtension.Template'
		$param.Configuration = $true
		$param.TypeName = 'PkiExtension.Template'
		Get-LdapObject @param
	}
}
function Resolve-Template {
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[string]
		$Template,

		[switch]
		$DontResolveTemplate
	)

	if ($Template -and $DontResolveTemplate) { return $Template }
	$templates = Get-PkiTemplate | Select-Object Name, DisplayName, @{ Name = "Version"; Expression = { '{0}.{1}' -f $_.Revision, $_.'Mspki-Template-Minor-Revision' } }
	if ($Template) {
		if ($templates.Name -contains $Template) { return $Template }
		$templateData = $templates | Where-Object DisplayName -EQ $Template
		if (-not $templateData) { throw "Template $Template not found!" }
		if (@($templateData).Count -gt 1) { throw "Ambiguous Template provided: $Template maps to $($templateData.Name -join ", ")" }
		return $templateData.Name
	}

	$selected = $templates | Out-GridView -PassThru -Title 'Select (single) template to use'
	if (@($selected).Count -gt 1) { throw "More than one template selected!" }
	if (@($selected).Count -lt 1) { throw "No template selected!" }
	$selected.Name
}

function Resolve-Configuration {
	<#
	.SYNOPSIS
		Merges settings between parameters provided to the script and content of the config file specified.
	
	.DESCRIPTION
		Merges settings between parameters provided to the script and content of the config file specified.
		This makes it simple to support a config file with default parameters for the script.

		The config file may contain any setting and will be overwritten with any parameters specified.
	
	.PARAMETER Parameters
		The $PSBoundParameters variable of the script
	
	.PARAMETER Defaults
		Default settings to use when neither config file nor bound parameters contain a value.
		Useful to map through default parameter values of the script.
	
	.PARAMETER ConfigName
		The name - without extension - of the config file to load from the folder the current script is in.
		Defaults to "config"
	
	.EXAMPLE
		PS C:\> $config = Resolve-Configuration -Parameters $PSBoundParameters -Defaults @{ CA = $CA; TemplateName = $TemplateName }

		Resolves all settings, by merging the values from "config.psd1" in the current file's directory with the parameters bound directly to the script.
		If neither contains a CA or TemplateName, the default values provided via hashtable are used instead.
	#>
	[OutputType([hashtable])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Parameters,

		[hashtable]
		$Defaults = @{},

		[string]
		$ConfigName = 'config'
	)

	$config = @{}
	if (Test-Path -Path "$PSScriptRoot\$ConfigName.psd1") {
		$config = Import-PowerShellDataFile -Path "$PSScriptRoot\$ConfigName.psd1"
	}

	foreach ($pair in $Parameters.GetEnumerator()) {
		$config[$pair.Key] = $pair.Value
	}
	foreach ($pair in $Defaults.GetEnumerator()) {
		if ($config.Keys -notcontains $pair.Key) {
			$config[$pair.Key] = $pair.Value
		}
	}

	$config
}

function Resolve-CertificateAuthority {
	[CmdletBinding()]
	param (
		[AllowEmptyCollection()]
		[AllowNull()]
		[string[]]
		$CA
	)

	if (-not $CA) {
		# Shows CA selection dialog
		$response = certutil -getconfig3

		$data = @{}
		$response | ForEach-Object {
			$key, $value = $_.Trim() -split ":", 2
			if (-not $value) { return }
			$data[$key.Trim()] = $value.Trim().Trim('" ')
		}

		if (-not $data.Config) {
			throw "No valid CA selected!"
		}
		return $data.Config
	}

	if ($CA.Count -eq 1) { return $CA }

	$selected = $CA | Out-GridView -PassThru -Title 'Select CA to use (Pick one only!)'
	if ($selected.Count -gt 1) { throw "More than one CA chosen, can only pick one!" }
	$selected
}

function New-CertificateRequest {
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Template,

		[Parameter(Mandatory = $true)]
		[string]
		$Fqdn,

		[Parameter(Mandatory = $true)]
		[string]
		$WorkingDirectory
	)

	$templateData = @"
[Version]
Signature="`$Windows NT$"
[NewRequest]
Subject = "CN=$Fqdn"
Exportable = True
KeyLength = 4096
KeySpec = 1
KeyUsage = 0xA0
MachineKeySet = True
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
RequestType = PKCS10
SMIME = FALSE
[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=$Fqdn"
[RequestAttributes]
CertificateTemplate = "$Template"
"@
	Remove-Item "$WorkingDirectory\_certReq.req" -ErrorAction Ignore
	[System.IO.File]::WriteAllText("$WorkingDirectory\_certReq.inf", $templateData, [System.Text.Encoding]::ASCII)
	$result = CertReq.exe -new -q "$WorkingDirectory\_certReq.inf" "$WorkingDirectory\_certReq.req"
	if ($LASTEXITCODE -ne 0) {
		Remove-Item "$WorkingDirectory\_certReq.inf" -ErrorAction Ignore
		foreach ($line in $result) {
			Write-Warning $line
		}
		throw "Failed to create certificate request!"
	}

	Remove-Item "$WorkingDirectory\_certReq.inf" -ErrorAction Ignore
	"$WorkingDirectory\_certReq.req"
}

function Send-CertificateRequest {
	#[OutputType([int])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$RequestPath,

		[Parameter(Mandatory = $true)]
		[string]
		$CA
	)

	$certPath = $RequestPath -replace '\.req$', '.cer'
	$responsePath = $RequestPath -replace '\.req$', '.rsp'
	Remove-Item $certPath -ErrorAction Ignore
	Remove-Item $responsePath -ErrorAction Ignore
	$result = CertReq.exe -submit -kerberos -q -config $CA $RequestPath $certPath
	if ($LASTEXITCODE -ne 0) {
		Remove-Item $RequestPath -ErrorAction Ignore
		Remove-Item $responsePath -ErrorAction Ignore
		foreach ($line in $result) {
			Write-Warning $line
		}
		throw "Failed to submit certificate request!"
	}
	Remove-Item $RequestPath -ErrorAction Ignore
	Remove-Item $responsePath -ErrorAction Ignore

	[PSCustomObject]@{
		Path      = $certPath
		RequestID = ($result | Where-Object { $_ -match '^RequestID: \d+$' }) -replace '^RequestID: (\d+)$', '$1' -as [int]
		Result    = $result
	}
}

function Test-CertificateRequest {
	[CmdletBinding()]
	param (
		[string]
		$CA,

		[int]
		$RequestID,

		[string]
		$CertPath
	)

	Remove-Item -Path ($CertPath -replace '\.cer$', '.rsp') -ErrorAction Ignore
	$result = CertReq.exe -retrieve -kerberos -q -config $CA $RequestID $CertPath
	if ($LASTEXITCODE -ne 0) {
		foreach ($line in $result) {
			Write-Warning $line
		}
		throw "Failed to retrieve certificate request!"
	}
	Test-Path $CertPath
}

function Receive-Certificate {
	[CmdletBinding()]
	param (
		[string]
		$CA,

		[int]
		$RequestID,

		[string]
		$CertPath
	)

	#region Case: AutoEnroll
	if (Test-Path $CertPath) {
		Remove-Item -Path ($CertPath -replace '\.cer$', '.rsp') -ErrorAction Ignore
		$result = certreq -accept -q $CertPath
		if ($LASTEXITCODE -ne 0) {
			foreach ($line in $result) {
				Write-Warning $line
			}
			Remove-Item -Path $CertPath -ErrorAction Ignore
			throw "Failed to accept certificate!"
		}

		$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
		$certificate.Thumbprint
		$certificate.Dispose()
		Remove-Item -Path $CertPath -ErrorAction Ignore
		return
	}
	#endregion Case: AutoEnroll

	#region Attempt to Approve
	$response = certutil.exe -config $CA -resubmit $RequestID
	if ($LASTEXITCODE -ne 0) {
		Write-Host "Failed to approve certificate, will need to be approved by CA admin"
		foreach ($line in $response) {
			Write-Verbose $line
		}
	}
	#endregion Attempt to Approve

	#region Wait for Approval
	if (-not (Test-CertificateRequest -RequestID $RequestID -CA $CA -CertPath $CertPath)) {
		Write-Host "Waiting for Certificate Request $($RequestID) from $($CA) being approved"
		while (-not (Test-CertificateRequest -RequestID $RequestID -CA $CA -CertPath $CertPath)) {
			Start-Sleep -Seconds 1
		}
	}
	#endregion Wait for Approval

	#region Receive Certificate
	Write-Host "Request approved, certificate received"
	Remove-Item -Path ($CertPath -replace '\.cer$', '.rsp') -ErrorAction Ignore
	$result = certreq -accept -q $CertPath
	if ($LASTEXITCODE -ne 0) {
		foreach ($line in $result) {
			Write-Warning $line
		}
		Remove-Item -Path $CertPath -ErrorAction Ignore
		throw "Failed to accept certificate!"
	}
	$certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertPath)
	$certificate.Thumbprint
	$certificate.Dispose()
	Remove-Item -Path $CertPath -ErrorAction Ignore
	#endregion Receive Certificate
}

function New-Password {
	<#
		.SYNOPSIS
			Generate a new, complex password.
		
		.DESCRIPTION
			Generate a new, complex password.
		
		.PARAMETER Length
			The length of the password calculated.
			Defaults to 32

		.PARAMETER AsSecureString
			Returns the password as secure string.
		
		.EXAMPLE
			PS C:\> New-Password

			Generates a new 32 character password.
	#>
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
	[CmdletBinding()]
	param (
		[int]
		$Length = 32,

		[switch]
		$AsSecureString
	)
	
	begin {
		$characters = @{
			0 = @('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
			1 = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z')
			2 = @(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
			3 = @('#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@')
			4 = @('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z')
			5 = @('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z')
			6 = @(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9)
			7 = @('#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@')
		}
	}
	process {
		$letters = foreach ($number in (1..$Length)) {
			$characters[(($number % 4) + (1..4 | Get-Random))] | Get-Random
		}
		$letters = $letters | Sort-Object { Get-Random }
		if ($AsSecureString) { $letters -join "" | ConvertTo-SecureString -AsPlainText -Force }
		else { $letters -join "" }
	}
}
function Show-SaveFileDialog {
	[CmdletBinding()]
	param (
		[string]
		$InitialDirectory = '.',

		[string]
		$Filter = '*.*',
		
		$Filename
	)
	
	Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
	$saveFileDialog = [Windows.Forms.SaveFileDialog]::new()
	$saveFileDialog.FileName = $Filename
	$saveFileDialog.InitialDirectory = Resolve-Path -Path $InitialDirectory
	$saveFileDialog.Title = "Save File to Disk"
	$saveFileDialog.Filter = $Filter
	$saveFileDialog.ShowHelp = $True
	
	$result = $saveFileDialog.ShowDialog()
	if ($result -eq "OK") {
		$saveFileDialog.FileName
	}
}
function Export-Certificate {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Thumbprint,

		[Parameter(Mandatory = $true)]
		[string]
		$Subject,

		[AllowEmptyString()]
		[string]
		$Path,

		[AllowNull()]
		[securestring]
		$Password,

		[switch]
		$Purge,

		[switch]
		$Print
	)

	$cert = Get-Item "Cert:\LocalMachine\My\$Thumbprint"
	
	if (-not $Path) {
		$name = $cert.Subject -replace '^CN='
		$Path = Show-SaveFileDialog -InitialDirectory $PSScriptRoot -Filter 'Certificate File (*.pfx)|*.pfx' -Filename "$name.pfx"
	}

	$toClipboard = -not $Password
	if (-not $Password) {
		$Password = New-Password -AsSecureString
	}

	
	
	$null = Get-Item "Cert:\LocalMachine\My\$Thumbprint" | Export-PfxCertificate -FilePath $Path -Password $Password
	if ($toClipboard) {
		Write-Host "Writing PFX Password to clipboard"
		[PSCredential]::new("Whatever", $Password).GetNetworkCredential().Password | Set-Clipboard
	}
	if ($Print) {
		Write-Host ("PWD: {0}: {1}" -f $Subject, ([PSCredential]::new("Whatever", $Password).GetNetworkCredential().Password))
	}

	if ($Purge) {
		Remove-Item "Cert:\LocalMachine\My\$Thumbprint"
	}
}
#endregion Functions

$config = Resolve-Configuration -Parameters $PSBoundParameters -Defaults @{ CA = $CA; TemplateName = $TemplateName }
$workingDirectory = New-Item -Path $env:TEMP -Name "Cert-$(Get-Random)" -ItemType Directory -Force

$caToUse = Resolve-CertificateAuthority -CA $config.CA
$resolvedTemplate = Resolve-Template -Template $config.TemplateName -DontResolveTemplate:$DontResolveTemplate
$requestPath = New-CertificateRequest -Template $resolvedTemplate -Fqdn $Subject -WorkingDirectory $workingDirectory.FullName
$request = Send-CertificateRequest -RequestPath $requestPath -CA $caToUse
$thumbprint = Receive-Certificate -CA $caToUse -RequestID $request.RequestID -CertPath $request.Path
Export-Certificate -Thumbprint $thumbprint -Subject $Subject -Path $OutPath -Password $Password -Purge -Print:$($config.PrintPW)

Remove-Item -Path $workingDirectory -Force -Recurse
