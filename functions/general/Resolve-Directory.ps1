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
