function Resolve-Configuration {
	<#
	.SYNOPSIS
		Merges settings between parameters provided to the script and content of the config file specified.
	
	.DESCRIPTION
		Merges settings between parameters provided to the script and content of the config file specified.
		This makes it simple to support a config file with default parameters for the script.

		The config file may contain any setting and will be overwritten with any parameters specified.
	
	.PARAMETER Parameters
		The $PSBoundParameters variable of the script
	
	.PARAMETER Defaults
		Default settings to use when neither config file nor bound parameters contain a value.
		Useful to map through default parameter values of the script.
	
	.PARAMETER ConfigName
		The name - without extension - of the config file to load from the folder the current script is in.
		Defaults to "config"
	
	.EXAMPLE
		PS C:\> $config = Resolve-Configuration -Parameters $PSBoundParameters -Defaults @{ CA = $CA; TemplateName = $TemplateName }

		Resolves all settings, by merging the values from "config.psd1" in the current file's directory with the parameters bound directly to the script.
		If neither contains a CA or TemplateName, the default values provided via hashtable are used instead.
	#>
	[OutputType([hashtable])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Parameters,

		[hashtable]
		$Defaults = @{},

		[string]
		$ConfigName = 'config'
	)

	$config = @{}
	if (Test-Path -Path "$PSScriptRoot\$ConfigName.psd1") {
		$config = Import-PowerShellDataFile -Path "$PSScriptRoot\$ConfigName.psd1"
	}

	foreach ($pair in $Parameters.GetEnumerator()) {
		$config[$pair.Key] = $pair.Value
	}
	foreach ($pair in $Defaults.GetEnumerator()) {
		if ($config.Keys -notcontains $pair.Key) {
			$config[$pair.Key] = $pair.Value
		}
	}

	$config
}
