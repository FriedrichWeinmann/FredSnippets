function ConvertTo-Icon {
<#
    .SYNOPSIS
 	   Converts an image file to an .ico file.

    .DESCRIPTION
		Converts an image file to an .ico file.
		Input must be a valid picture file in a commonly used format, such as png or jpg.

    .PARAMETER Path
    	The full or relative path to the source image file.

    .PARAMETER OutPath
		The destination path for the generated `.ico` file.
		If omitted, the function creates the icon next to the source image using the same base name.

    .EXAMPLE
    	PS C:\> ConvertTo-Icon -Path 'C:\Images\logo.png'

		Converts `logo.png` to `logo.ico` in the same folder because `OutPath` is not provided.
#>
    [CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[string]
		$OutPath
	)

	Add-Type -AssemblyName System.Drawing.Common

	if (-not $OutPath) {
		$OutPath = $Path -replace '\.[^\.]+$','.ico'
	}
	$outParent = Split-Path -Path $OutPath
	$fileName = Split-Path -Path $OutPath -Leaf
	try { $outParentResolved = Resolve-Path -Path $outParent -ErrorAction Stop }
	catch { throw $_ }
	$outPathResolved = Join-Path -Path $outParentResolved -ChildPath $fileName

	$fileStream = $null
	$icon = $null

	try {
		$fileStream = [System.IO.FileStream]::new($outPathResolved, 'OpenOrCreate')
	
		$bitmap = [System.Drawing.Bitmap]::FromFile($Path)
		$iconHandle = $bitmap.GetHIcon()
		$icon = [System.Drawing.Icon]::FromHandle($iconHandle)
		$icon.Save($fileStream)
	}
	catch {
		if ($fileStream) { $fileStream.Dispose() }
		if ($icon) { $icon.Dispose() }

		throw $_
	}
}
