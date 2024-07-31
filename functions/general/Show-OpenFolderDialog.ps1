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
	
	.EXAMPLE
		PS C:\> Show-OpenFolderDialog

		Shows a dialog to select a folder
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[string]
		$Description,

		[ValidateSet('Desktop','Programs','MyDocuments','Personal','Favorites','Startup','Recent','SendTo','StartMenu','MyMusic','MyVideos','DesktopDirectory','MyComputer','NetworkShortcuts','Fonts','Templates','CommonStartMenu','CommonPrograms','CommonStartup','CommonDesktopDirectory','ApplicationData','PrinterShortcuts','LocalApplicationData','InternetCache','Cookies','History','CommonApplicationData','Windows','System','ProgramFiles','MyPictures','UserProfile','SystemX86','ProgramFilesX86','CommonProgramFiles','CommonProgramFilesX86','CommonTemplates','CommonDocuments','CommonAdminTools','AdminTools','CommonMusic','CommonPictures','CommonVideos','Resources','LocalizedResources','CommonOemLinks','CDBurning')]
		[string]
		$RootFolder = 'Desktop'
	)

	begin {
		Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
	}
	process {
		$dialog = [System.Windows.Forms.FolderBrowserDialog]::new()
		$dialog.Description = $Description
		$dialog.RootFolder = $RootFolder
		$null = $dialog.ShowDialog()
		if ($dialog.SelectedPath) {
			$dialog.SelectedPath
		}
	}
}