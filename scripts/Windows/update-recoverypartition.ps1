#requires -RunAsAdministrator
#requires -Modules Storage

<#
.SYNOPSIS
	Shrinks the OS volume to recreate the recovery partition in larger.

.DESCRIPTION
	Shrinks the OS volume to recreate the recovery partition in larger.
	This script is intended to help fix issues with the recovery partition not being large enough.

.PARAMETER RecoveryPartitionSizeMB
	The size by which the recovery partition should be extended (in MB).
	Defaults to 250

.PARAMETER LogPath
	The path where the script should write its logs to.
	Folder will be created if needed.
	Defaults to: "C:\Logs\RecoveryPartitionCreator-$(Get-Date -Format 'yyyy-MM-dd').csv"
	Provide an empty string to disable logging.

.EXAMPLE
	PS C:\> .\update-recoverypartition.ps1

	Increases the size of the recovery partition by 250MB

.LINK
	https://support.microsoft.com/en-us/topic/kb5028997-instructions-to-manually-resize-your-partition-to-install-the-winre-update-400faa27-9343-461c-ada9-24c8229763bf
#>
[CmdletBinding()]
param (
	[int]
	$RecoveryPartitionSizeMB = 250,

	[AllowEmptyString()]
	[string]
	$LogPath = "C:\Logs\RecoveryPartitionCreator-$(Get-Date -Format 'yyyy-MM-dd').csv"
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Log -Message "Script Failed: $_"
	Enable-WinREAgent
	Stop-Log
	throw $_
}

#region Functions
function Start-Log {
	[CmdletBinding()]
	param (
		[AllowEmptyString()]
		[string]
		$Path
	)

	if (-not $Path) { return }

	$folder = Split-Path $Path
	if (-not (Test-Path $folder)) {
		$null = New-Item -Path $folder -ItemType Directory -Force
	}
	$script:logger = { Export-Csv -Path $Path }.GetSteppablePipeline()
	$script:logger.Begin($true)
}
function Write-Log {
	[CmdletBinding()]
	param (
		[ValidateSet('INFO', 'WARNING', 'ERROR')]
		[string]
		$Level = 'INFO',

		[string]
		$Message
	)
	if (-not $script:logger) { return }

	$msg = [PSCustomObject]@{
		Timestamp = Get-Date
		Level     = $Level
		Message   = $Message
	}
	$script:logger.Process($msg)
}
function Stop-Log {
	[CmdletBinding()]
	param (
		
	)
	if ($script:logger) {
		$script:logger.End()
	}
}

function Disable-WinREAgent {
	[CmdletBinding()]
	param ()

	Write-Log -Message 'Disabling Recovery Agent'
	try { $message = reagentc /disable }
	catch { $message = $_ }
	switch ($LASTEXITCODE) {
		0 { Write-Log -Message 'Success' }
		2 { Write-Log -Message 'Was already disabled' }
		default {
			if ($message -match 'is already disabled') { break }
			Write-Log -Level WARNING -Message "Failed to disable Recovery Agent: $message"
			throw "Failed to disable Recovery Agent: $message"
		}
	}
}
function Enable-WinREAgent {
	[CmdletBinding()]
	param ()

	Write-Log -Message 'Enabling Recovery Agent'
	try { $message = reagentc /enable }
	catch { $message = $_ }
	switch ($LASTEXITCODE) {
		0 { Write-Log -Message 'Success' }
		2 { Write-Log -Message 'Was already enabled' }
		default {
			if ($message -match 'is already enabled') { break }
			Write-Log -Level WARNING -Message "Failed to enable Recovery Agent: $message"
			throw "Failed to enable Recovery Agent: $message"
		}
	}
}
function Update-Volume {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$DriveLetter,

		[int]
		$SizeMB
	)

	if ($SizeMB -lt 0) {
		Write-Log -Message "Shrinking volume $DriveLetter by $SizeMB"
		$results = "SELECT VOLUME $DriveLetter", "shrink desired=$($SizeMB * -1)" | diskpart
		if ($LASTEXITCODE -eq 0) { Write-Log -Message "Shrinking volume $DriveLetter by $SizeMB - Success" }
		else {
			Write-Log -Level Warning -Message "Shrinking volume $DriveLetter by $SizeMB - Failed"
			foreach ($line in $results) {
				Write-Log -Message $line
			}
			Write-Error "Failed to shrink volume $DriveLetter by $SizeMB"
		}
	}
}

function Remove-RecoveryPartition {
	[CmdletBinding()]
	param ()

	Write-Log -Message 'Removing existing recovery partition if present'
	Get-Partition | Where-Object Type -EQ Recovery | Remove-Partition -Confirm:$false -ErrorAction Stop
	Write-Log -Message 'Removing existing recovery partition if present - success'
}
function New-RecoveryPartition {
	[CmdletBinding()]
	param (
		[int]
		$SizeMB
	)

	$osDisk = Get-Volume -DriveLetter ($env:SystemDrive -replace ':') | Get-Partition | Get-Disk
	if ($osDisk.PartitionStyle -eq 'GPT') {
		Write-Log -Message "Creating a recovery pertition (GPT)"
		$commands = @(
			"SEL DISK $($osDisk.DiskNumber)"
			'create partition primary id=de94bba4-06d1-4d40-a16a-bfd50179d6ac'
			'gpt attributes =0x8000000000000001'
		)
	}
	else {
		Write-Log -Message "Creating a recovery pertition (MBR)"
		$commands = @(
			"SEL DISK $($osDisk.DiskNumber)"
			'create partition primary id=27'
		)
	}
	$partitionsBefore = $osDisk | Get-Partition
	try { $message = $commands | diskpart }
	catch { $message = $_ }
	if ($LASTEXITCODE -gt 0) {
		Write-Log -Level ERROR -Message "Creating a recovery pertition - Failed: $message"
		throw "Creating a recovery pertition - Failed: $message"
	}
	Get-Partition | Where-Object UniqueId -NotIn $partitionsBefore.UniqueId | Format-Volume
	Write-Log -Message "Creating a recovery pertition - Success!"
}
#endregion Functions

Start-Log -Path $LogPath
Disable-WinREAgent
Update-Volume -DriveLetter ($env:SystemDrive -replace ':') -SizeMB (-1 * $RecoveryPartitionSizeMB) -ErrorAction Stop
Remove-RecoveryPartition
New-RecoveryPartition -SizeMB $RecoveryPartitionSizeMB
Enable-WinREAgent
Stop-Log