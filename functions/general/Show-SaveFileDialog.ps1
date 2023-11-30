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