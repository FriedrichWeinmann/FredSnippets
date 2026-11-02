function Group-ObjectEx {
	<#
	.SYNOPSIS
		Group Data equivalently to how Group-Object does.
	
	.DESCRIPTION
		Group Data equivalently to how Group-Object does.
		Implemented due to system issues with the default Group-Object.
	
	.PARAMETER Property
		The property on the input object to group by.
	
	.PARAMETER AsHashtable
		Returns the groups as a hashtable.
	
	.PARAMETER InputObject
		The objects to group, provided by pipeline.
	
	.EXAMPLE
		PS C:\> Get-ChildItem | Group-ObjectEx Attributes

		Gets all items in the current path and groups them by their Attributes
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Property,

		[switch]
		$AsHashtable,

		[Parameter(ValueFromPipeline = $true)]
		$InputObject
	)
	begin {
		$data = @{}
	}
	process {
		if ($Null -eq $InputObject) { return }
		$key = $InputObject.$Property
		if ($null -eq $key) { $key = '' }
		if (-not $data[$key]) { $data[$key] = [System.Collections.Generic.List[object]]::new() }
		$data[$key].Add($InputObject)
	}
	end {
		if ($AsHashtable) { return $data }

		foreach ($pair in $data.GetEnumerator()) {
			[PSCustomObject]@{
				Count = $pair.Value.Count
				Name  = $pair.Key
				Group = $($pair.Value)
			}
		}
	}
}
