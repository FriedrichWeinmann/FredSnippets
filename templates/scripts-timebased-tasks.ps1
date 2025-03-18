<#
This template is designed to set up a task, that will execute a task in time blocks.
Imagine you want to process log entries, then publish the result somewhere.
HOWEVER:
- You can't do too much at a time due to memory constraints
- You want to make sure, that if the task failed for some reason, it can recover and try again the next time

This layout is designed to enable you to do just that, without forcing you to implement all that tracking yourself!
All that is missing is the actual business logic.
#>
[CmdletBinding()]
param (
	
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

#region Functions
function Start-Task {
	<#
	.SYNOPSIS
		Configures the upcoming task to process.
	
	.DESCRIPTION
		Configures the upcoming task to process.
	
	.PARAMETER Path
		The path to the file that tracks the progress of the task.
		Must point to a file. Extension is arbitrary, but ".clixml" is recommended.
	
	.PARAMETER Interval
		The size of each processign cycle.
		In the example of processing eventlogs being processed, setting this to 30 minutes means the logs are processed in batches of all events happening within 30 minutes each.
	
	.PARAMETER MaxHistory
		How far into the past we are at most willing to look.
		This only applies to tasks that had previously run and then be interrupted.
	
	.PARAMETER InitialHistory
		How far into the past we are at most willing to look.
		This only applies to tasks that have never been run before.
	
	.PARAMETER Partial
		If the last execution has not been a full interval in the past, process anyway.
		By default, the segment between the last execution and now will be skipped, if it is a shorter timespan than the configured interval.
	
	.PARAMETER SavePartial
		When executing a partial task - that is one covering a shorter timespan than the full interval - should the task remember doing so?
		If this parameter is not set, it will run the partial set again the next time the script is launched.
	
	.EXAMPLE
		PS C:\> Start-Task -Path "$env:AppData\powershell\tasks\MyTask.clixml" -Interval '00:30:00' -MaxHistory '90.00:00:00' -InitialHistory '30.00:00:00' -Partial
		
		Starts a task-tracking in "$env:AppData\powershell\tasks\MyTask.clixml" for a task processing entries in 30 minute intervals.
		It will go no further into the past than 90 days and during setup no further than 30.
		When reaching the current state, it will also process the last, partial timespan, but it will not remember doing so - the next time the script is run, it will try again.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Path,

		[Parameter(Mandatory = $true)]
		[Timespan]
		$Interval,

		[Parameter(Mandatory = $true)]
		[Timespan]
		$MaxHistory,

		[Parameter(Mandatory = $true)]
		[Timespan]
		$InitialHistory,

		[switch]
		$Partial,

		[switch]
		$SavePartial
	)

	$parent = Split-Path -Path $Path
	if (-not (Test-Path -Path $parent)) {
		$null = New-Item -Path $parent -ItemType Directory -Force
	}

	$script:taskConfig = [PSCustomObject]@{
		Path           = $Path
		Interval      = $Interval
		MaxHistory     = $MaxHistory
		InitialHistory = $InitialHistory
		Partial        = $Partial.ToBool()
		SavePartial    = $SavePartial.ToBool()
		# Flag to end after partial, lest it cycle indefinitely
		NoMore         = $false
	}

	if (Test-Path -Path $Path) { return }

	if ($InitialHistory.TotalMilliseconds -gt 0) { $InitialHistory = $InitialHistory.Negate() }

	$task = [PSCustomObject]@{
		Next        = (Get-Date).Add($InitialHistory)
		Last        = (Get-Date).Add($InitialHistory).Add($Interval.Negate())
		# These are documentation only:
		Interval   = $Interval
		Partial     = $Partial.ToBool()
		SavePartial = $Partial.ToBool()
	}
	$task | Export-Clixml -Path $Path
}
function Get-NextTask {
	<#
	.SYNOPSIS
		Provides the next segment to process.
	
	.DESCRIPTION
		Provides the next segment to process.
		Will return nothing if there is no more to be done.
	
	.EXAMPLE
		PS C:\> Get-NextTask
		
		Provides the next segment to process.
	#>
	[CmdletBinding()]
	param ()

	if ($script:taskConfig.NoMore) { return }

	$task = Import-Clixml -Path $script:taskConfig.Path
	$nextStart = $task.Next
	if ($nextStart -lt (Get-Date).Add($script:taskConfig.MaxHistory.Negate())) { $nextStart = (Get-Date).Add($script:taskConfig.MaxHistory.Negate()) }
	$nextEnd = $nextStart.Add($script:taskConfig.Interval)
	$isPartial = $false

	if ((Get-Date) -lt $nextEnd) {
		if (-not $script:taskConfig.Partial) { return }

		$script:taskConfig.NoMore = $true
		$isPartial = $true
		$nextEnd = Get-Date
	}

	[PSCustomObject]@{
		Start     = $nextStart
		End       = $nextEnd
		IsPartial = $isPartial
	}
}
function Update-Task {
	<#
	.SYNOPSIS
		Updates the cached task on disk.
	
	.DESCRIPTION
		Updates the cached task on disk.
		Ensures the script will pick up where it left off the last time around.
	
	.PARAMETER Task
		The Task information to write to disk.
		Object as returned by Get-NextTask
	
	.EXAMPLE
		PS C:\> Update-Task -Task $task

		Updates the cached task on disk, providing updated timestamps for the next iteration.
	#>
	[CmdletBinding()]
	param (
		$Task
	)

	$taskItem = Import-Clixml -Path $script:taskConfig.Path
	$taskItem.Last = $Task.Start
	$taskItem.Next = $Task.End

	if ($Task.IsPartial -and -not $script:taskConfig.SavePartial) {
		$taskItem.Next = $Task.Start
	}

	$taskItem | Export-Clixml -Path $script:taskConfig.Path
}
#endregion Functions

Start-Task -Path "$env:AppData\powershell\tasks\MyTask.clixml" -Interval '00:30:00' -MaxHistory '90.00:00:00' -InitialHistory '30.00:00:00' -Partial
while ($task = Get-NextTask) {
	<#
	Task:
	Start:     The starting timestamp
	End:       The expected end
	IsPartial: Whether this is a partial task - that is, we did not get a full Interval timeslot, but start where we left off and process everything until now.
	#>

	#TODO: Add business logic

	Update-Task -Task $task
}