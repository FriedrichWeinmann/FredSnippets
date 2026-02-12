[CmdletBinding()]
param (
	[ValidateScript({
			if (Test-Path -Path $_ -PathType Leaf) { return }

			Write-Warning "Path not found or not a file: $_"
			throw "Path not found or not a file: $_"
		})]
	[string]
	$Path,

	[ValidateScript({
			if (Test-Path -Path $_ -PathType Container) { return }

			Write-Warning "Path not found or not a directory: $_"
			throw "Path not found or not a directory: $_"
		})]
	[string]
	$OutPath,

	[SecureString]
	$Password,

	[switch]
	$ExportPasswords,

	[string]
	$TemplateName,

	[string[]]
	$CA,

	[switch]
	$PrintPW
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

#region Functions
function Assert-CreationScript {
	[CmdletBinding()]
	param ()

	if (Test-Path -Path "$PSScriptRoot\request-computer-certificate.ps1") { return }

	throw "Required script not found! Ensure 'request-computer-certificate.ps1' exists in the same path as this script file! ($PSScriptRoot)"
}

function Resolve-CertificateAuthority {
	[CmdletBinding()]
	param (
		[AllowEmptyCollection()]
		[AllowNull()]
		[string[]]
		$CA
	)

	if ($CA) {
		if ($CA.Count -eq 1) { return $CA }

		$selected = $CA | Out-GridView -PassThru -Title 'Select CA to use (Pick one only!)'
		if ($selected.Count -gt 1) { throw "More than one CA chosen, can only pick one!" }
		return $selected
	}

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

function Import-CertificateWorkload {
	[CmdletBinding()]
	param (
		[string]
		$Path,

		[AllowNull()]
		[SecureString]
		$Password,

		[string]
		$DefaultCA,

		[switch]
		$ExportPasswords
	)

	$templates = Get-PkiTemplate
	$defaultTemplate = $null

	$file = Get-Item -LiteralPath $Path
	$entries = Import-DataFile -Path $file.FullName -RequiredProperties Name -OptionalProperties Template, CA, Password, ExportPWD -DefaultProperty Name -ErrorAction Stop
	foreach ($entry in $entries) {
		if ($entry.ExportPWD) {
			$entry.ExportPWD = $entry.ExportPWD -eq 'True'
		}
		else { $entry.ExportPWD = $ExportPasswords.ToBool() }

		if ($entry.Password) { $entry.Password = $entry.Password | ConvertTo-SecureString -AsPlainText -Force }
		else { $entry.Password = New-Password -AsSecureString }

		if (-not $entry.CA) { $entry.CA = $DefaultCA }

		if (-not $entry.Template) {
			if (-not $defaultTemplate) {
				$selected = $templates | Out-GridView -PassThru -Title 'Choose a default template to request for your certificates'
				if (-not $selected) { throw "No template selected!" }
				if (@($selected).Count -gt 1) { throw "More than one template selected!" }
				$defaultTemplate = $selected.Name
			}
			$entry.Template = $defaultTemplate
		}
		else {
			$byName = $templates | Where-Object Name -eq $entry.Template
			$byDisplayName = $templates | Where-Object DisplayName -eq $entry.Template

			if ($byName) { $entry.Template = $byName.Name }
			elseif ($byDisplayName) { $entry.Template = $byDisplayName.Name }
			else {
				throw "Unknown Certificate Template: $($entry.Template)"
			}
		}
		$entry
	}
}

function Invoke-CertificateRequest {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Task,

		[Parameter(Mandatory = $true)]
		[string]
		$Path
	)

	& "$PSScriptRoot\request-computer-certificate.ps1" -Subject $Task.Name -OutPath (Join-Path -Path $Path -ChildPath "$($Task.Name).pfx") -Password $Password -TemplateName $Task.Template -CA $Task.CA -PrintPW:$PrintPW
}

#region Templates
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
#endregion Templates

#region Generics
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
function Resolve-File {
	<#
	.SYNOPSIS
		Resolves a file path.
	
	.DESCRIPTION
		Resolves a file path, by either accepting an input path and verifying it, or prompting the user in a selection UI.
	
	.PARAMETER Path
		The path to select, if it contains any value.
	
	.PARAMETER Title
		The message to show when prompting the user to select a file.
	
	.PARAMETER Type
		What kind of file to select.
		This choice limits the selection in the UI prompt and is used to validate the extension of the input file.
		Selecting 'Any' removes any filtering / constraints.
	
	.EXAMPLE
		PS C:\> Resolve-File -Path $Path -Title 'Select Import File' -Type CSV

		Resolves a valid CSV. If $Path contains the value, that will be used, otherwise the user is prompted to select a CSV file.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[AllowNull()]
		[string]
		$Path,

		[string]
		$Title,

		[Parameter(Mandatory = $true)]
		[ValidateSet('Any', 'CSV', 'TXT', 'PSD1', 'JSON')]
		[string[]]
		$Type
	)

	#region Utility Function
	function Show-OpenFileDialog {
		<#
    .SYNOPSIS
        Show an Open File dialog using WinForms.
    
    .DESCRIPTION
        Show an Open File dialog using WinForms.
    
    .PARAMETER InitialDirectory
        The initial directory from which the user gets to pick a file.
        Defaults to the current path.

	.PARAMETER Filter
		Adds a filter to the dialog window.
		Can be used to prompt the user to only select files of relevant extensions.
		Example: 'Text files (*.txt)|*.txt|All files (*.*)|*.*'

    .PARAMETER Title
        The window title to display.
    
    .PARAMETER MultiSelect
        Whether the user may pick more than one file.
    
    .EXAMPLE
        PS C:\> Show-OpenFileDialog

        Opens a file selection dialog in the current folder
    #>
		[OutputType([string])]
		[CmdletBinding()]
		param (
			[string]
			$InitialDirectory = '.',

			[string]
			$Filter,

			[string]
			$Title,

			[switch]
			$MultiSelect
		)

		process {
			Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
			$dialog = [System.Windows.Forms.OpenFileDialog]::new()
			$dialog.InitialDirectory = Resolve-Path -Path $InitialDirectory
			$dialog.MultiSelect = $MultiSelect.ToBool()
			$dialog.Title = $Title
			if ($Filter) { $dialog.Filter = $Filter }
			$null = $dialog.ShowDialog()
			$dialog.FileNames
		}
	}
	#endregion Utility Function

	$filterMap = @{
		Any  = 'Any file (*.*)|*.*'
		CSV  = 'CSV File (*.csv)|*.csv'
		TXT  = 'TXT File (*.txt)|*.txt'
		PSD1 = 'PSD1 File (*.psd1)|*.psd1'
		JSON = 'JSON File (*.json)|*.json'
	}

	if ($Path) {
		try { $file = Get-Item -Path $Path -ErrorAction Stop }
		catch { throw "Path not found: $Path!" }

		if ($file.Count -gt 1) { throw "Path ambiguous! $($file.FullName -join ' | ')" }
		if (-not (Test-Path -LiteralPath $file.FullName -PathType Leaf)) { throw "Not a file: $($file.FullName)" }

		$extensions = switch ($Type) {
			CSV { '.csv' }
			TXT { '.txt' }
			PSD1 { '.psd1' }
			JSON { '.json' }
		}

		if ($Type -notcontains 'Any' -and $file.Extension -notin $extensions) {
			throw "Unexpected file extension! $file must be of type $($extensions -join ', ')!"
		}

		return $file.FullName
	}

	$selected = Show-OpenFileDialog -InitialDirectory (Get-Item -Path .).FullName -Filter (@($Type).ForEach{ $filterMap[$_] } -join '|') -Title $Title
	if (-not $selected) { throw "No file selected!" }
	$selected
}
function Resolve-Directory {
	<#
	.SYNOPSIS
		Resolves a directory path.
	
	.DESCRIPTION
		Resolves a directory path, by either accepting an input path and verifying it, or prompting the user in a selection UI.
	
	.PARAMETER Path
		The path to select, if it contains any value.
	
	.PARAMETER Description
		The message to show when prompting the user to select a directory.
	
	.EXAMPLE
		PS C:\> Resolve-Directory -Path $OutPath -Description 'Select an Export Path for the Certificates'

		Resolves a valid directory. If $Path contains the value, that will be used, otherwise the user is prompted to select a directory via UI.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[AllowNull()]
		[string]
		$Path,

		[string]
		$Description
	)

	#region Utility Function
	function Show-OpenFolderDialog {
		<#
	.SYNOPSIS
		Shows a dialog to select a folder.
	
	.DESCRIPTION
		Shows a dialog to select a folder.
	
	.PARAMETER Description
		The description to show in the UI dialog.

	.PARAMETER RootFolder
		Where the dialog should start at.
		Defaults to: desktop

	.PARAMETER InitialDirectory
		Path where the dialog window should start at.
		Overrides -RootFolder.
	
	.EXAMPLE
		PS C:\> Show-OpenFolderDialog

		Shows a dialog to select a folder
	#>
		[OutputType([string])]
		[CmdletBinding()]
		param (
			[string]
			$Description,

			[ValidateSet('Desktop', 'Programs', 'MyDocuments', 'Personal', 'Favorites', 'Startup', 'Recent', 'SendTo', 'StartMenu', 'MyMusic', 'MyVideos', 'DesktopDirectory', 'MyComputer', 'NetworkShortcuts', 'Fonts', 'Templates', 'CommonStartMenu', 'CommonPrograms', 'CommonStartup', 'CommonDesktopDirectory', 'ApplicationData', 'PrinterShortcuts', 'LocalApplicationData', 'InternetCache', 'Cookies', 'History', 'CommonApplicationData', 'Windows', 'System', 'ProgramFiles', 'MyPictures', 'UserProfile', 'SystemX86', 'ProgramFilesX86', 'CommonProgramFiles', 'CommonProgramFilesX86', 'CommonTemplates', 'CommonDocuments', 'CommonAdminTools', 'AdminTools', 'CommonMusic', 'CommonPictures', 'CommonVideos', 'Resources', 'LocalizedResources', 'CommonOemLinks', 'CDBurning')]
			[string]
			$RootFolder = 'Desktop',

			[string]
			$InitialDirectory
		)

		begin {
			Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
		}
		process {
			$dialog = [System.Windows.Forms.FolderBrowserDialog]::new()
			$dialog.Description = $Description
			$dialog.RootFolder = $RootFolder
			if ($InitialDirectory) { $dialog.InitialDirectory = $InitialDirectory }
			$null = $dialog.ShowDialog()
			if ($dialog.SelectedPath) {
				$dialog.SelectedPath
			}
		}
	}
	#endregion Utility Function

	if ($Path) {
		try { $directory = Get-Item -Path $Path -ErrorAction Stop }
		catch { throw "Path not found: $Path!" }

		if ($directory.Count -gt 1) { throw "Path ambiguous! $($directory.FullName -join ' | ')" }
		if (-not (Test-Path -LiteralPath $directory.FullName -PathType Container)) { throw "Not a directory: $($directory.FullName)" }

		return $directory.FullName
	}

	$selected = Show-OpenFolderDialog -InitialDirectory (Get-Item -Path .).FullName -Description $Description
	if (-not $selected) { throw "No directory selected!" }
	$selected
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
function Import-DataFile {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('FullName')]
		[string[]]
		$Path,

		[AllowEmptyCollection()]
		[AllowNull()]
		[string[]]
		$RequiredProperties,
		
		[AllowEmptyCollection()]
		[AllowNull()]
		[string[]]
		$OptionalProperties,

		[string]
		$DefaultProperty,

		[switch]
		$RetainExtraData
	)

	begin {
		function ConvertTo-DataSet {
			[CmdletBinding()]
			param (
				[Parameter(ValueFromPipeline = $true)]
				$InputObject,

				[AllowEmptyCollection()]
				[AllowNull()]
				[string[]]
				$RequiredProperties,
		
				[AllowEmptyCollection()]
				[AllowNull()]
				[string[]]
				$OptionalProperties,

				[switch]
				$RetainExtraData,

				[string]
				$FilePath
			)

			begin {
				$allProperties = @($RequiredProperties) + @($OptionalProperties) | Where-Object { $_ } | Select-Object -Unique
			}
			process {
				:main foreach ($entry in $InputObject) {
					# Enforce required properties
					foreach ($property in $RequiredProperties) {
						if ($null -eq $entry.$property -or "" -eq $entry.$property) {
							Write-Warning "Invalid Data in $FilePath : Empty/null $property"
							Write-Error "Invalid Data in $FilePath : Empty/null $property"
							continue main
						}
					}

					foreach ($property in $allProperties) {
						if ($entry.PSObject.Properties.Name -contains $property) { continue }
						Add-Member -InputObject $entry -MemberType NoteProperty -Name $property -Value $null -Force
					}

					if (-not $RetainExtraData) {
						$properties = $entry.PSObject.Properties.Name
						foreach ($property in $properties) {
							if ($property -in $allProperties) { continue }
							$entry.PSObject.Properties.Remove($property)
						}
					}

					$entry
				}
			}
		}
		
		$allProperties = @($RequiredProperties) + @($OptionalProperties) | Where-Object { $_ } | Select-Object -Unique
		$defaultHash = @{}
		foreach ($property in $allProperties) { $defaultHash[$property] = $null }
	}
	process {

		foreach ($filePath in $Path) {
			try { $files = Get-Item -Path $filePath -ErrorAction Stop }
			catch {
				Write-Warning "File not found: $filePath"
				Write-Error $_
				continue
			}

			:process foreach ($fileItem in $files) {
				if (-not (Test-Path -LiteralPath $fileItem.FullName -PathType Leaf)) {
					Write-Warning "Not a file: $fileItem"
					Write-Error "Not a file: $fileItem" -TargetObject $fileItem
					continue
				}

				if ($fileItem.Extension -notin '.txt', '.csv', '.json', '.psd1') {
					Write-Warning "Unsupported filetype: $($fileItem.Extension) in $($fileItem.FullName). Supported types are: .txt, .csv, .json, or .psd1"
					Write-Error "Unsupported filetype: $($fileItem.Extension) in $($fileItem.FullName). Supported types are: .txt, .csv, .json, or .psd1" -TargetObject $fileItem
				}

				switch ($fileItem.Extension) {
					#region Process TXT File
					'.txt' {
						if (-not $DefaultProperty) {
							Write-Warning "Cannot process a text file without specifying a default property!"
							Write-Error "Cannot process a text file without specifying a default property!"
							continue process
						}

						if ($RequiredProperties | Where-Object { $_ -ne $DefaultProperty }) {
							Write-Warning "Cannot process a text file with a required property that is not also a default property!"
							Write-Error "Cannot process a text file with a required property that is not also the default property!"
							continue process
						}

						foreach ($line in Get-Content -LiteralPath $fileItem.FullName) {
							if (-not $line.Trim()) { continue }
							if ($line.Trim() -like '#*') { continue }

							$data = $defaultHash.Clone()
							$data[$DefaultProperty] = $line.Trim()
							[PSCustomObject]$data
						}
					}
					#endregion Process TXT File

					#region Process CSV File
					'.csv' {
						$start = Get-Content -LiteralPath $fileItem.FullName -TotalCount 3
						if (-not $start) {
							Write-Verbose "File is empty: $fileItem"
							continue process
						}

						$dataCDelim = $start | ConvertFrom-Csv -Delimiter ','
						$dataSDelim = $start | ConvertFrom-Csv -Delimiter ';'

						if (-not $dataCDelim -and -not $dataSDelim) {
							Write-Warning "File not recognized as CSV content with either ',' or ';' delimiter: $fileItem"
							Write-Error "File not recognized as CSV content with either ',' or ';' delimiter: $fileItem"
							continue process
						}

						if (@($dataCDelim)[0].PSObject.Properties.Count -ge @($dataSDelim)[0].PSObject.Properties.Count) {
							$data = Import-Csv -LiteralPath $fileItem.FullName -Delimiter ',' -Encoding UTF8
						}
						else {
							$data = Import-Csv -LiteralPath $fileItem.FullName -Delimiter ';' -Encoding UTF8
						}
						
						$missingRequired = $RequiredProperties | Where-Object { $_ -notin @($data)[0].PSObject.Properties.Name }
						if ($missingRequired) {
							Write-Warning "Error loading CSV file $fileItem - required columns are missing: $($missingRequired -join ', ')"
							Write-Error "Error loading CSV file $fileItem - required columns are missing: $($missingRequired -join ', ')" -TargetObject $fileItem
							continue process
						}

						$data | ConvertTo-DataSet -RequiredProperties $RequiredProperties -OptionalProperties $OptionalProperties -RetainExtraData:$RetainExtraData -FilePath $fileItem.FullName
					}
					#endregion Process CSV File

					#region Process .json File
					'.json' {
						try { $text = Get-Content -LiteralPath $fileItem.FullName -ErrorAction Stop }
						catch {
							Write-Warning "Error accessing file $($fileItem.FullName): $_"
							Write-Error $_ -TargetObject $fileItem
							continue process
						}

						$text | ConvertFrom-Json | Write-Output | ConvertTo-DataSet -RequiredProperties $RequiredProperties -OptionalProperties $OptionalProperties -RetainExtraData:$RetainExtraData -FilePath $fileItem.FullName
					}
					#endregion Process .json File

					#region Process .psd1 File
					'.psd1' {
						$command = Get-Command Import-PSFPowerShellDataFile -ErrorAction Ignore
						if (-not $command) {
							Import-PowerShellDataFile -Path $fileItem.FullName | ForEach-Object { [PSCustomObject]$_ } | ConvertTo-DataSet -RequiredProperties $RequiredProperties -OptionalProperties $OptionalProperties -RetainExtraData:$RetainExtraData -FilePath $fileItem.FullName
						}
						else {
							Import-PSFPowerShellDataFile -Path $fileItem.FullName -Psd1Mode Safe | ForEach-Object { [PSCustomObject]$_ } | ConvertTo-DataSet -RequiredProperties $RequiredProperties -OptionalProperties $OptionalProperties -RetainExtraData:$RetainExtraData -FilePath $fileItem.FullName
						}
					}
					#endregion Process .psd1 File
				}
			}
		}
	}
}
#endregion Generics
#endregion Functions

Assert-CreationScript
$config = Resolve-Configuration -Parameters $PSBoundParameters -Defaults @{ CA = $CA; TemplateName = $TemplateName }
$caToUse = Resolve-CertificateAuthority -CA $config.CA
if ($PSBoundParameters.Keys -contains 'PrintPW') { $config.PrintPW = $PrintPW.ToBool() }

$inputPath = Resolve-File -Path $Path -Title 'Select Import File' -Type CSV, TXT, JSON, PSD1
$outputPath = Resolve-Directory -Path $OutPath -Description 'Select an Export Path for the Certificates'
$workload = Import-CertificateWorkload -Path $InputPath -Password $Password -ExportPasswords:$ExportPasswords -DefaultCA $caToUse
foreach ($task in $workload) {
	Invoke-CertificateRequest -Task $task -Path $outputPath -PrintPW:$($config.PrintPW)
}
