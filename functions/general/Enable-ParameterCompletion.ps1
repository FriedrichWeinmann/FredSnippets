function Enable-ParameterCompletion {
	<#
	.SYNOPSIS
		Makes a parameter (that must exist) available for tab completion when it originally was not.
	
	.DESCRIPTION
		Makes a parameter (that must exist) available for tab completion when it originally was not.
		This counteracts the "DontShow" parameter attribute.
	
	.PARAMETER Command
		The command to update the parameter for.
		Can be either a full name or the actual command object.
	
	.PARAMETER ParameterName
		The name of the parameter to show.
		Does not support wildcards.
	
	.EXAMPLE
		PS C:\> Enable-ParameterCompletion -Command Export-Csv -ParameterName NoTypeInformation

		Tries to enable the NoTypeInformation parameter for tab completion
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
				$attribute.DontShow = $false
			}
		}
	}
}