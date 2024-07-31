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