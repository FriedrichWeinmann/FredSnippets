function Resolve-TenantID {
	<#
	.SYNOPSIS
		Resolves the current user's tenant ID.
	
	.DESCRIPTION
		Resolves the current user's tenant ID.
		This is designed to autodetect the Microsoft Azure Tenant ID based on the current setup.

		- If an ID is provided, it will be returned as is.
		- If the az.* modules are loaded and connected, the current tenantID from that is used.
		- If on a windows machine, it will finally check for an office installation and use its ID (if present).
	
	.PARAMETER TenantID
		The ID of the tenant provided by the user, if any.
		If specified, this command will return this ID and stop right there.
	
	.PARAMETER Cmdlet
		The $PSCmdlet variable of the calling function.
		Used to throw errors in the context of the caller when no TenantID can be found.
	
	.EXAMPLE
		PS C:\> $TenantID = Resolve-TenantID -TenantID $TenantID -Cmdlet $PSCmdlet

		Will resolve the $TenantID if not yet provided, terminating the calling command if no TenantID can be found.
	#>
	[OutputType([string])]
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[AllowNull()]
		[string]
		$TenantID,

		[Parameter(Mandatory = $true)]
		$Cmdlet
	)
	process {
		if ($TenantID) { return $TenantID }

		if (Get-Command Get-AzContext -ErrorAction Ignore) {
			try {
				$context = Get-AzContext -ErrorAction Stop
				if ($context.Tenant.Id) { return $context.Tenant.Id }
			}
			catch { }
		}

		if ($PSVersionTable.PSVersion.Major -gt 5 -and -not $IsWindows) {
			Invoke-TerminatingException -Cmdlet $Cmdlet -Message "No TenantID found, specify one to authenticate!" -Category InvalidArgument
		}

		if (Test-Path -Path 'HKCU:\Software\Microsoft\OneDrive\Accounts') {
			foreach ($child in Get-ChildItem -Path 'HKCU:\Software\Microsoft\OneDrive\Accounts') {
				$properties = Get-ItemProperty -Path $child.PSPath
				if ($properties.ConfiguredTenantId) { return $properties.ConfiguredTenantId }
			}
		}

		Invoke-TerminatingException -Cmdlet $Cmdlet -Message "No TenantID found, specify one to authenticate!" -Category InvalidArgument
	}
}