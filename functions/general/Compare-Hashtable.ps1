function Read-Hashtable {
	<#
.Synopsis
    Reads a hash table and returns its contents as key/value objects.

.DESCRIPTION
    Reads a hash table and returns its contents as a hierarchical structure.
    Use the AsHashtable switch to return the result as a flat hashtable, rather than one object per.

.PARAMETER Hashtable
    The input hash table that is to be read.

.PARAMETER Namespace
    The namespace under which the keys should be read.
	Used to recursively resolve hashtables

.PARAMETER AsHashtable
    Specifies if the contents of the hash table are returned as an object
    hierarchy or as a hash table itself.

.EXAMPLE
    $struct = @{
        first = @{ second = '213' }
    }
    Read-Hashtable -Hashtable $struct

    Name                   Value
    ----                   -----
    first.second           213
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[hashtable]
		$Hashtable,
		
		[string]
		$Namespace,

		[switch]
		$AsHashtable
	)

	$prefix = ''
	if ($Namespace) { $prefix = "$Namespace." }

	$results = foreach ($pair in $Hashtable.GetEnumerator()) {
		$name = '{0}{1}' -f $prefix, $pair.Key
		if ($pair.Value -is [hashtable] -and $pair.Value.Count -gt 0) {
			Read-HashTable -Namespace $name -Hashtable $pair.Value
			continue
		}
		[PSCustomObject]@{
			Name  = $name
			Value = $pair.Value
		}
	}

	if (-not $AsHashtable) { return $results }

	$resultHash = @{ }
	foreach ($result in $results) {
		$resultHash[$result.Name] = $result.Value
	}
	$resultHash
}

function Compare-Hashtable {
<#
    .SYNOPSIS
    Compares a provided reference hashtable to a provided difference hashtable.
  
    .DESCRIPTION
    Compares a provided reference hashtable to a provided difference hashtable and returns the differences as specified.
  
    .PARAMETER ReferenceHashtable
    The reference hashtable to use for comparison.
    
    .PARAMETER DifferenceHashtable
    The difference hashtable to use for comparison.

    .PARAMETER IncludeEqual
    When specified, results are returned when the Reference and Difference are equal.

    .PARAMETER ExcludeDifferent
    When specified, results are not returned when the Reference and Difference are different.
    
    .EXAMPLE
    PS C:\> Compare-Hashtable -ReferenceHashtable $MyConfigReference -DifferenceHOshtable (Get-Something -Config) 
   
    Compares the loaded ReferenceHashtable to the result of Get-Something.

#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[hashtable]
		$ReferenceHashtable,
		
		[Parameter(Mandatory = $true)]
		[hashtable]
		$DifferenceHashtable,

		[switch]
		$IncludeEqual,

		[switch]
		$ExcludeDifferent
	)

	begin {
		function New-Change {
			[CmdletBinding()]
			param (
				[hashtable]
				$Reference,

				[hashtable]
				$Difference,

				[string]
				$Name,

				[ValidateSet('==', '!=', '=>', '<=')]
				[string]
				$Direction,

				[AllowEmptyCollection()]
				[AllowEmptyString()]
				[AllowNull()]
				$RefValue,

				[AllowEmptyCollection()]
				[AllowEmptyString()]
				[AllowNull()]
				$DifValue
			)

			[PSCustomObject]@{
				PSTypeName = 'Hashtable.Comparison'
				Reference  = $Reference
				Difference = $Difference
				Name       = $Name
				Direction  = $Direction
				RefValue   = $RefValue
				DifValue   = $DifValue
			}
		}
	}

	process {
		$paramChange = @{
			Difference = $DifferenceHashtable
			Reference  = $ReferenceHashtable
		}
		$flatReference = Read-HashTable -Hashtable $ReferenceHashtable -AsHashtable
		$flatDifference = Read-HashTable -Hashtable $DifferenceHashtable -AsHashtable

		foreach ($pair in $flatReference.GetEnumerator()) {
			if (-not $ExcludeDifferent) {
				if ($flatDifference.Keys -notcontains $pair.Key) {
					New-Change @paramChange -Name $pair.Key -Direction '=>' -RefValue $pair.Value
					continue
				}
				if ($pair.Value -ne $flatDifference[$pair.Key] -or $flatDifference[$pair.Key] -ne $pair.Value) {
					New-Change @paramChange -Name $pair.Key -Direction '!=' -RefValue $pair.Value -DifValue $flatDifference[$pair.Key]
				}
			}
			if ($IncludeEqual) {
				if ($pair.Value -eq $flatDifference[$pair.Key] -and $flatDifference[$pair.Key] -eq $pair.Value) {
					New-Change @paramChange -Name $pair.Key -Direction '==' -RefValue $pair.Value -DifValue $flatDifference[$pair.Key]
				}
			}
		}

		foreach ($pair in $flatDifference.GetEnumerator()) {
			if (-not $ExcludeDifferent -and $flatReference.Keys -notcontains $pair.Key) {
				New-Change @paramChange -Name $pair.Key -Direction '<=' -DifValue $pair.Value
				continue
			}
		}
	}
}
<#
# Examle usage

$hash1 = @{
	Foo  = 23
	Bar  = 1
	Data = @{
		Answer = 42
		Name   = 'Fred'
		Age    = 37
	}
}

$hash2 = @{
	Foo  = 42
	Data = @{
		Answer = 42
		Name   = 'Max'
		Age    = @(37,38)
	}
}
Read-HashTable -Hashtable $hash1

Compare-Hashtable -ReferenceHashtable $hash1 -DifferenceHashtable $hash2 | ft Name, Direction, DifValue, RefValue
Compare-Hashtable -ReferenceHashtable $hash1 -DifferenceHashtable $hash1 | ft Name, Direction, DifValue, RefValue
Compare-Hashtable -ReferenceHashtable $hash1 -DifferenceHashtable $hash1 -IncludeEqual | ft Name, Direction, DifValue, RefValue
Compare-Hashtable -ReferenceHashtable $hash1 -DifferenceHashtable $hash2 -IncludeEqual -ExcludeDifferent | ft Name, Direction, DifValue, RefValue
#>