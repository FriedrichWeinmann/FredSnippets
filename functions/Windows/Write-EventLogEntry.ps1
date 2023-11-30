function Write-EventLogEntry
{
	<#
	.SYNOPSIS
		Write an eventlog entry
	
	.DESCRIPTION
		Write an eventlog entry
	
	.PARAMETER LogName
		The log to write to
	
	.PARAMETER Source
		The source associated with the event.
		Must be registered to the target log.
	
	.PARAMETER EventID
		The ID of the event to generate
	
	.PARAMETER Category
		The category ID of the event to generate.
		Defaults to 1
	
	.PARAMETER Type
		What kind of event to write (Information, Error, etc.)
		Defaults to Information
	
	.PARAMETER Data
		The data to include in the event.
		If no language file is associated with the source & EventID combination, the first item will become the message.
		All items become entries in the properties section of the event
	
	.EXAMPLE
		PS C:\> Write-EventLogEntry -LogName Application -Source Application -EventID 1000 -Data "Something happened", 42

		Generates an eventlog entry under Application\Application with ID 1000 and the message "Something happened"
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$LogName,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Source,
		
		[Parameter(Mandatory = $true)]
		[int]
		$EventID,
		
		[int]
		$Category = 1,
		
		[System.Diagnostics.EventLogEntryType]
		$Type = 'Information',
		
		[Parameter(Mandatory = $true)]
		[object[]]
		$Data
	)
	$id = New-Object System.Diagnostics.EventInstance($EventID, $Category, $Type)
	$evtObject = New-Object System.Diagnostics.EventLog
	$evtObject.Log = $LogName
	$evtObject.Source = $Source
	$evtObject.WriteEvent($id, $Data)
}