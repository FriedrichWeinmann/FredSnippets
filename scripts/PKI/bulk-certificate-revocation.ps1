#requires -Modules PSFramework, PkiExtension

[CmdletBinding(SupportsShouldProcess = $true)]
param (
	[string]
	$Path,

	[string[]]
	$CA,

	[string]
	$TemplateName,

	[DateTime]
	$When = (Get-Date)
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

#region Functions
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

function Resolve-RevocationTask {
	[CmdletBinding()]
	param (
		[string]
		$Path,

		[string]
		$DefaultCA,

		[string]
		$DefaultTemplate,

		[datetime]
		$DefaultWhen
	)

	$templates = Get-PkiTemplate
	$defaultTemplateName = ''
	if ($DefaultTemplate) {
		if ($templates.Name -contains $DefaultTemplate) { $defaultTemplateName = $DefaultTemplate }
		else { $defaultTemplateName = ($templates | Where-Object DisplayName -EQ $DefaultTemplate).Name }
	}

	$data = Import-DataFile -Path $Path -RequiredProperties Name -OptionalProperties Template, CA, When -DefaultProperty Name
	foreach ($entry in $data) {
		if ($entry.Template) {
			$byName = $templates | Where-Object Name -eq $entry.Template
			$byDisplayName = $templates | Where-Object DisplayName -eq $entry.Template

			if ($byName) { $entry.Template = $byName.Name }
			elseif ($byDisplayName) { $entry.Template = $byDisplayName.Name }
			else {
				throw "Unknown Certificate Template: $($entry.Template)"
			}
		}
		elseif ($defaultTemplateName) { $entry.Template = $defaultTemplateName }

		if (-not $entry.CA) { $entry.CA = $DefaultCA }

		if ($entry.When) { $entry.When = $entry.When -as [DateTime] }
		else { $entry.When = $DefaultWhen }
		if (-not $entry.When) { throw "Invalid Data Set! Unable to process revokation timestamp!" }

		$param = @{
			FQCAName = $entry.CA
			CommonName = $entry.Name
		}
		if ($entry.Name -notlike 'CN=*') { $param.CommonName = "CN=$($entry.Name)" }
		if ($entry.Template) { $param.TemplateName = $entry.Template }

		$certificates = Get-PkiCaCertificate @param
		if (-not $certificates) {
			Write-PSFMessage -Level Warning -Message "No certificate found for {0} on CA {1} with Template {2}" -StringValues $param.CommonName, $entry.CA, $entry.Template
			continue
		}

		Add-Member -InputObject $entry -MemberType NoteProperty -Name Certificates -Value $certificates -PassThru
	}
}
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
function Import-DataFile {
	<#
	.SYNOPSIS
		Loads data from a variety of data file types, such as CSV, Json, Psd1, or Txt.
	
	.DESCRIPTION
		Loads data from a variety of data file types, such as CSV, Json, Psd1, or Txt.
		In case of CSV, it supports both comma and semicolon as delimiter, automatically detecting the applicable option.
		Allows specifying the properties that MUST be on the datasets and those that MAY be.

		This offers flexibility in what & how users can provide input files.

		Any resulting object / dataset will have all properties - required or optional - whether the input contained it or not.
		All objects must not have a $null or empty string for any required properties.

		Notes on processing TXT Files:
		- Empty lines are ignored
		- Each line becomes its own entry
		- Lines whose first non-whitespace character is a "#" will be ignored
		- All lines will be trimmed - whitespace on both ends will be removed
	
	.PARAMETER Path
		Path to the file to read.
	
	.PARAMETER RequiredProperties
		Properties that MUST be on all input objects.
		These properties must not be empty or null.
		TXT files can only have a single Required Property. The property should also be specified as DefaultProperty.
	
	.PARAMETER OptionalProperties
		Properties that MAY be on all input objects.
		Resulting objects will always include all of these properties, whether they were found on the original input or not.
	
	.PARAMETER DefaultProperty
		When reading text files, each line becomes an entry, but TXT files are not structured data.
		The property specified here is used to store the data, all other properties will be included, but empty.
		This parameter only affects txt imports and should match the required parameter.
	
	.PARAMETER RetainExtraData
		Imports from structured data might contain more data than expected.
		For example, a CSV file could have columns not accounted for.
		These are by default removed during import - unless this parameter is specified.
	
	.EXAMPLE
		PS C:\> Import-DataFile -Path .\computers.txt -RequiredProperties Name -OptionalProperties Description, Account -DefaultProperty Name

		Reads the provided text file and returns objects with three properties: Name, Description, Account
		Empty or commented lines in the file will be ignored, each result object will have the Name property filled with the line from the file, Description and Account will be empty.

	.EXAMPLE
		PS C:\> Import-DataFile -Path .\computers.csv -RequiredProperties Name -OptionalProperties Description, Account -DefaultProperty Name

		Reads the provided csv file.
		The file MUST have a name column.
		The columns "Description" and "Account" will carry over if specified.

	.EXAMPLE
		PS C:\> Import-DataFile -Path $inputFile -RequiredProperties Name -OptionalProperties Description, Account -DefaultProperty Name

		Reads the provided file, no matter its type, assuming it is TXT, Json, Psd1 or Csv.
	#>
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

$config = Resolve-Configuration -Parameters $PSBoundParameters -Defaults @{ CA = $CA; Templatename = $TemplateName }
$caToUse = Resolve-CertificateAuthority -CA $config.CA

$inputPath = Resolve-File -Path $Path -Title 'Select Import File' -Type CSV, TXT, JSON, PSD1
$tasks = Resolve-RevocationTask -Path $inputPath -DefaultCA $caToUse -DefaultTemplate $config.TemplateName -DefaultWhen $When
foreach ($task in $tasks) {
	foreach ($certificate in $task.Certificates) {
		Revoke-PkiCaCertificate -FQCAName $task.CA -Certificate $certificate -Reason $task.Reason -RevocationDate $task.When
	}
}
