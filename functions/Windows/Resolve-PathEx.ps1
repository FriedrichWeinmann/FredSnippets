function Resolve-PathEx {
	<#
	.SYNOPSIS
		Resolve a path.
	
	.DESCRIPTION
		Resolve a path.
		Allows specifying success criteria, as well as selecting files or folders only.
	
	.PARAMETER Path
		The input path to resolve.
	
	.PARAMETER Type
		What kind of item to resolve to.
		Supported types:
		- Any: Can be whatever, so long as it exists.
		- File: Must be a file/leaf object and exist
		- Directory: Must be a container/directory object and exist
		- NewFile: The parent path must exist and be a container/directory. The item itself needs not exist, but if it exists, it must be a leaf/file
		Defaults to Any.
	
	.PARAMETER SingleItem
		Whether resolving to more than one item should cause an error.
	
	.PARAMETER Mode
		How results should be handled:
		- Any: At least one single successful path must be resolved, any errors are ignored as long as at least one is valid.
		- All: All items resolved must be valid.
		- AnyWarning: At least one single successful path must be resolved, any errors are filed as warning.

	.PARAMETER Provider
		What provider the item must be from.
		Defaults to FileSystem.
	
	.EXAMPLE
		PS C:\> Resolve-PathEx -Path .
		
		Resolves the current path.

	.EXAMPLE
		PS C:\> Resolve-PathEx -Path .\test\report.csv -Type NewFile -SingleItem

		Must resolve the full path of the file "report.csv" in the folder "test" under the current path.
		The file need not exist, but the folder must be present.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('FullName')]
		[string[]]
		$Path,

		[ValidateSet('File', 'Directory', 'Any', 'NewFile')]
		[string]
		$Type = 'Any',

		[switch]
		$SingleItem,

		[ValidateSet('Any', 'All', 'AnyWarning')]
		[string]
		$Mode = 'Any',

		[string]
		$Provider = 'FileSystem'
	)

	process {
		foreach ($pathEntry in $Path) {
			$data = [PSCustomObject]@{
				Input   = $pathEntry
				Path    = $null
				Success = $false
				Message = ''
				Error   = $null
			}
	
			$basePath = $pathEntry
			if ('NewFile' -eq $Type) {
				$basePath = Split-Path -Path $pathEntry -Parent
				$leaf = Split-Path -Path $pathEntry -Leaf
			}
			try { $resolved = (Resolve-Path -Path $basePath -ErrorAction Stop).ProviderPath }
			catch {
				$data.Error = $_
				$data.Message = "Path cannot be resolved: $pathEntry"
				return $data
			}
	
			if (@($resolved).Count -gt 1 -and $SingleItem) {
				$data.Message = "More than one item found: $pathEntry"
				return $data
			}
	
			$paths = [System.Collections.ArrayList]@()
			$messages = [System.Collections.ArrayList]@()
			$success = $false
			$failed = $false
	
			foreach ($resolvedPath in $resolved) {
				$item = Get-Item -LiteralPath $resolvedPath
	
				if ($Provider -ne $item.PSProvider.Name) {
					$failed = $true
					$null = $messages.Add("Not a $Provider path: $($resolvedPath)")
					continue
				}
	
				if ('File' -eq $Type -and $item.PSIsContainer) {
					$failed = $true
					$null = $messages.Add("Not a file: $($resolvedPath)")
					continue
				}
	
				if ('Directory' -eq $Type -and -not $item.PSIsContainer) {
					$failed = $true
					$null = $messages.Add("Not a directory: $($resolvedPath)")
					continue
				}
	
				if ('NewFile' -eq $Type) {
					if (-not $item.PSIsContainer) {
						$failed = $true
						$null = $messages.Add("Parent of $($pathEntry) is not a container: $($resolvedPath)")
						continue
					}
	
					$newFilePath = Join-Path -Path $resolvedPath -ChildPath $leaf
					if (Test-Path -LiteralPath $newFilePath -PathType Container) {
						$failed = $true
						$null = $messages.Add("Target path $($newFilePath) must not be a directory!")
						continue
					}
	
					$null = $paths.Add($newFilePath)
					$success = $true
					continue
				}
	
				$null = $paths.Add($resolvedPath)
				$success = $true
			}
	
			$data.Path = $($paths)
			$data.Message = $($messages)
			foreach ($pathItem in $data.Path) {
				Write-Verbose "Resolved $pathEntry to $pathItem"
			}
	
			switch ($Mode) {
				'Any' {
					$data.Success = $success
					foreach ($message in $data.Message) {
						Write-Verbose $message
					}
				}
				'All' {
					$data.Success = -not $failed
					foreach ($message in $data.Message) {
						Write-Verbose $message
					}
				}
				'AnyWarning' {
					$data.Success = $success
					foreach ($message in $data.Message) {
						Write-Warning $message
					}
				}
			}
	
			$data
		}
	}
}