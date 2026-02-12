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
