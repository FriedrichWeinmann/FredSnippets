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
		[ValidateSet('Any', 'CSV', 'TXT', 'PSD!', 'JSON')]
		[string]
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

		switch ($Type) {
			CSV { if ($file.Extension -ne '.csv') { throw "Not a $Type file: $file" } }
			TXT { if ($file.Extension -ne '.txt') { throw "Not a $Type file: $file" } }
			PSD1 { if ($file.Extension -ne '.psd1') { throw "Not a $Type file: $file" } }
			JSON { if ($file.Extension -ne '.json') { throw "Not a $Type file: $file" } }
		}

		return $file.FullName
	}

	$selected = Show-OpenFileDialog -InitialDirectory (Get-Item -Path .).FullName -Filter $filterMap[$Type] -Title $Title
	if (-not $selected) { throw "No file selected!" }
	$selected
}
