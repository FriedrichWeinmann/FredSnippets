function Copy-FileSystemItem {
	<#
	.SYNOPSIS
		Copies files and folders from one location to another.
	
	.DESCRIPTION
		Copies files and folders from one location to another.
		Key differences between this and the built-in Copy-Item cmdlet:
		- This function allows selecting the behavior in case of conflict (See parameter "-Conflict")
		- This function returns a report object for each item in scope, detailing the action taken.
		- This function is NOT capable of copying from or to a remote PowerShell session.
	
	.PARAMETER Path
		The path from where to copy the files and folders.
		If you only want to copy the CONTENTS of that path, be sure to append a "\*" to the path.
		For example: "C:\Folder\*".
	
	.PARAMETER Destination
		The destination path where to copy the files and folders.
		Must be a directory, not a file.
	
	.PARAMETER Conflict
		What to do in case the same file or folder already exists in the destination.
		- Overwrite: Overwrite the existing file or folder.
		- Skip: Skip the existing file or folder.
		- Newer: Skip the existing file or folder if the source file is older than the destination file.
	
	.PARAMETER Recurse
		Whether the function should process subfolders and their contents.
	
	.EXAMPLE
		PS C:\> Copy-FileSystemItem -Path "C:\Folder\*" -Destination "D:\Folder" -Conflict Overwrite

		Copies all files and folders from "C:\Folder" to "D:\Folder", overwriting any existing files or folders.

	.EXAMPLE
		PS C:\> Copy-FileSystemItem -Path "C:\Folder\*" -Destination "D:\Folder" -Conflict Skip -Recurse

		Copies all files and folders from "C:\Folder" (and all its subfolders) to "D:\Folder", skipping any existing files or folders.

	.EXAMPLE
		PS C:\> Copy-FileSystemItem -Path "C:\Folder\*" -Destination "D:\Folder" -Conflict Newer

		Copies all files and folders from "C:\Folder" to "D:\Folder", skipping any existing files or folders if the source file not newer than the destination file.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[ValidateScript({
				if (Test-Path -Path $_) { return $true }

				Write-Warning "Path not found: $_"
				throw "Path not found: $_"
			})]
		[string]
		$Path,

		[ValidateScript({
				if (Test-Path -Path $_ -PathType Container) { return $true }

				Write-Warning "Path not found or not a container: $_"
				throw "Path not found or not a container: $_"
			})]
		[string]
		$Destination,

		[ValidateSet('Overwrite', 'Skip', 'Newer')]
		[string]
		$Conflict = 'Skip',

		[switch]
		$Recurse
	)

	begin {
		#region Functions
		function Get-RelativeChildItem {
			[CmdletBinding()]
			param (
				[string]
				$Path,
		
				[switch]
				$Recurse
			)
		
			if (-not (Test-Path -Path $Path)) { return }
		
			$baseItems = Get-Item -Path $Path
			if ($baseItems.Count -gt 1 -or -not $baseItems.PSIsContainer) {
				$basePath = Split-Path -Path @($baseItems)[0].FullName
			}
			else { $basePath = $baseItems.FullName }
			$baseitem = Get-Item -Path $basePath -Force
		
			$resolvedPaths = Resolve-Path -Path $Path
			$resultItems = foreach ($resolvePath in $resolvedPaths) {
				$item = Get-Item -LiteralPath $resolvePath -Force
				$item
				if ($item.PSisContainer -and $Recurse) {
					Get-ChildItem -LiteralPath $item.FullName -Recurse -Force
				}
			}
			
			Foreach ($resultitem in $resultItems) {
				[PSCustomObject]@{
					RelativePath = $resultItem.FullName.SubString($baseItem.FullName.Length).Trim('\')
					Name         = $resultItem.Name
					IsFile       = -not $resultItem.PSisContainer
					FullName     = $resultitem.FullName
					BasePath     = $baseItem.FullName
					Item         = $resultitem
				}
			}
		}
		#endregion Functions
	}
	process {
		$sourceItems = Get-RelativeChildItem -Path $Path -Recurse:$Recurse | Sort-Object { $_.Item.PSParentPath.Length }, { $_.Item.PSParentPath }, Name
		$destinationItems = Get-RelativeChildItem -Path $Destination -Recurse
		$destinationBase = Get-Item -Path $Destination
		$destHash = @{ }
		foreach ($item in $destinationItems) { $destHash[$item.RelativePath] = $item }

		foreach ($sourceItem in $sourceItems) {
			$destItem = $destHash[$sourceItem.RelativePath]
			$targetPath = Join-Path -Path $destinationBase.FullName -ChildPath $sourceItem.RelativePath
			$update = [PSCustomObject]@{
				RelativePath         = $sourceItem.RelativePath
				Action               = 'Unprocessed'
				TimestampSource      = $sourceItem.Item.LastWriteTime
				TimestampDestination = $destItem.Item.LastWriteTime
				Error                = $null
				FullName             = $sourceItem.FullName
				TargetPath           = $targetPath
			}

			#region Handle Interrupt Conditions
			if ($destItem -and $Conflict -eq 'Skip') {
				$update.Action = 'Skipped (Exists)'
				$update
				continue
			}
			if ($destItem -and $update.TimestampSource -le $update.TimestampDestination -and $Conflict -eq 'Newer') {
				$update.Action = 'Skipped (Exists & Newer)'
				$update
				continue
			}

			if (-not $PSCmdlet.ShouldProcess($sourceItem.RelativePath, "Copy to $targetPath ($($update.TimestampSource) -> $($update.TimestampDestination))")) {
				$update.Action = 'No Change (Would have copied)'
				$update
				continue
			}
			#endregion Handle Interrupt Conditions

			try {
				Copy-Item -Path $sourceItem.FullName -Destination $targetPath -Force
				$update.Action = 'Copied'
			}
			catch {
				$update.Action = 'Failed'
				$update.Error = $_
				Write-Error $_
			}
			$update
		}
	}
}
