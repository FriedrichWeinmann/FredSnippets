function Disable-ParameterCompletion {
	<#
	.SYNOPSIS
		Prevents a particular parameter from being part of the tab completion.
	
	.DESCRIPTION
		Prevents a particular parameter from being part of the tab completion.
		Note: On PS7 this also prevents tab completion of common parameters.
	
	.PARAMETER Command
		The command to update the parameter for.
		Can be either a full name or the actual command object.
	
	.PARAMETER ParameterName
		The name of the parameter to hide.
		Does not support wildcards.
	
	.EXAMPLE
		PS C:\> Disable-ParameterCompletion -Command Get-ChildItem -ParameterName Path

		Hides the "-Path" parameter on Get-ChildItem.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true)]
		$Command,

		[Parameter(Mandatory = $true)]
		[string]
		$ParameterName
	)

	process {
		foreach ($commandItem in $Command) {
			$commandObject = $commandItem
			if ($commandItem -is [string]) { $commandObject = Get-Command -Name $commandItem }

			if ($commandObject.Parameters.Keys -notcontains $ParameterName) {
				Write-Error "Command $($commandObject.Name) does not contain parameter $($ParameterName)"
				continue
			}

			foreach ($attribute in $commandObject.Parameters.$ParameterName.Attributes) {
				if (-not ($attribute -is [System.Management.Automation.ParameterAttribute])) {
					continue
				}
				$attribute.DontShow = $true
			}
		}
	}
}