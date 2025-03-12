<#
A quick experiment on comparing and filtering datasets between DataTables, then build a new DataTable from it.

Invoke-Sqlcmd can return full DataTable objects.
Write-SqlDataTable can write a DataTable into a table.

This allows transfering selected datasets from one SqlInstance to another.
#>

$table1 = [System.Data.DataTable]::new()
$table2 = [System.Data.DataTable]::new()

$columns = @(
	@{ Name = "Name"; Type = [string] }
	@{ Name = "Description"; Type = [string] }
	@{ Name = "Age"; Type = [int] }
)
foreach ($column in $columns) {
	$null = $table1.Columns.Add($column.Name, $column.Type)
	$null = $table2.Columns.Add($column.Name, $column.Type)
}

$entries1 = @(
	@{ Name = "Fred"; Description = "Whatever 1"; Age = 39 }
	@{ Name = "Max"; Description = "Whatever 2"; Age = 25 }
	@{ Name = "Peter"; Description = "Whatever 3"; Age = 27 }
	@{ Name = "Maria"; Description = "Whatever 4"; Age = 18 }
)
foreach ($entry in $entries1) {
	$null = $table1.Rows.Add($entry.Name, $entry.Description, $entry.Age)
}

$entries2 = @(
	@{ Name = "Fred"; Description = "Whatever 1"; Age = 39 }
	@{ Name = "Max"; Description = "Whatever 2"; Age = 27 }
	@{ Name = "Moritz"; Description = "Whatever 3"; Age = 27 }
)
foreach ($entry in $entries2) {
	$null = $table2.Rows.Add($entry.Name, $entry.Description, $entry.Age)
}

$entries = @($table1.Rows).Where{ -not $table2.Select("Name='$($_["Name"])' and Age=$($_["Age"])") }
$newTable = [System.Data.DataTable]::new()
foreach ($column in $table1.Columns) { $null = $newTable.Columns.Add($column.Name, $column.DataType) }
@($entries).ForEach{ $null = $newTable.Rows.Add($_.ItemArray) }