function Invoke-AsTask {
	<#
	.SYNOPSIS
		Executes a provided scriptblock as a scheduled task.
	
	.DESCRIPTION
		Executes a provided scriptblock as a scheduled task.
		Provides for collecting results and reporting success.
	
	.PARAMETER ScriptBlock
		The scriptblock to execute.
		Use "Write-Log" to send messages to the log.
		The result output will be returned.

	.PARAMETER ArgumentList
		List of arguments to pass to your scriptblock.
		Arguments are transported via json, limited to depth 5.
	
	.PARAMETER Name
		Name of the task, to better track event creation and completion.
	
	.PARAMETER Identity
		The windows identity to run this under.
		Defaults to the current user.
	
	.PARAMETER Password
		Password of the account running this, if needed.
	
	.PARAMETER Interactive
		Task should run in interactive mode (which assumes the user to be logged in already).
	
	.PARAMETER LogPath
		Where to write the logs.
		Defaults to C:\Temp
	
	.EXAMPLE
		PS C:\> Invoke-AsTask -Scriptblock $code -Identity SYSTEM

		Executes something as SYSTEM and returns the results

	.EXAMPLE
		PS C:\> Invoke-AsTask -Scriptblock $code

		Executes something as the current user and returns the results
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[scriptblock]
		$ScriptBlock,

		[object[]]
		$ArgumentList,

		[ValidateScript({
				if ($_ -notmatch "'") { return $true }
				throw "Name may not contain a single-quote in it. Value: $Name"
			})]
		[string]
		$Name = 'Unspecified',

		[string]
		$Identity = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name),

		[SecureString]
		$Password,

		[switch]
		$Interactive,

		[string]
		$LogPath = 'C:\Temp'
	)

	#region Wrapper ($wrapperScript)
	$wrapperScript = {
		#region Functions
		function Start-Log {
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[string]
				$Path
			)

			$script:_Logger = { Export-Csv -Path $Path }.GetSteppablePipeline()
			$script:_Logger.Begin($true) # $true = Pipeline INput wird erwartet
		}
		function Write-Log {
			[CmdletBinding()]
			param (
				[string]
				$Message,

				[ValidateSet('ERROR', 'WARNING', 'INFO', 'DEBUG')]
				[string]
				$Status = 'INFO',

				[string]
				$Target,

				[string[]]
				$Tags,

				[System.Management.Automation.ErrorRecord]
				$ErrorRecord
			)

			if ($ErrorRecord) {
				$Message = '{0} | {1}' -f $Message, $ErrorRecord

				if ($PSBoundParameters.Keys -notcontains 'Status') {
					$Status = 'ERROR'
				}
			}

			$messageText = '{0:HH:mm:ss} {1}' -f (Get-Date), $Message
			switch ($Status) {
				'INFO' { Write-Verbose $messageText }
				'WARNING' { Write-Warning $messageText }
				'ERROR' { Write-Warning $messageText }
			}

			if (-not $script:_Logger -and -not $script:_LoggingWarningShown) {
				Write-Warning "Logging not enabled, use Start-Log to configure logging!"
				$script:_LoggingWarningShown = $true
				return
			}

			$caller = (Get-PSCallStack)[1]

			$data = [PSCustomObject]@{
				Timestamp   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss.fff')
				Status      = $Status
				Message     = $Message
				Target      = $Target
				Tags        = $Tags -join ', '
				User        = $env:USERNAME
				Computer    = $env:COMPUTERNAME
				Command     = $caller.FunctionName
				Line        = $caller.ScriptLineNumber
				ScriptName  = $caller.Location
				ErrorRecord = $ErrorRecord
			}

			$script:_Logger.Process($data)
		}
		function Stop-Log {
			[CmdletBinding()]
			param ()

			if (-not $script:_Logger) {
				Write-Verbose "[Stop-Log] Logging not enabled, terminating function"
				return
			}

			$script:_Logger.End()
			$script:_Logger = $null
		}
		#endregion Functions

		$logPath = '%LOGPATH%'
		$taskIdentity = '%IDENTITY%'
		$payload = { '%PAYLOAD%' }
		$argumentData = @'
%ARGUMENTS%
'@ | ConvertFrom-Json
		$fullLogPath = Join-Path -Path $logPath -ChildPath "$taskIdentity.csv"
		$resultPath = Join-Path -Path $logPath -ChildPath "$taskIdentity.json"

		if (-not (Test-Path -Path $logPath)) {
			$null = New-Item -Path $logPath -ItemType Directory -Force
		}

		Start-Log -Path $fullLogPath
		Write-Log -Message "Starting task $taskIdentity"

		$result = [PSCustomObject]@{
			Output = $null
			Error  = $null
			Logs   = $null
		}
		try {
			if ($argumentData.Count -gt 0) { $result.Output = & $payload $argumentData.Arguments }
			else { $result.Output = & $payload }
			Write-Log -Message "Task completed successfully"
		}
		catch {
			Write-Log -Status ERROR -Message "Task failed" -ErrorRecord $_
			$result.Error = $_
		}
		finally {
			Write-Log -Message "Task execution concluded"
			Stop-Log
		}

		$result.Logs = Import-Csv -Path $fullLogPath
		$result | ConvertTo-Json -Depth 5 | Set-Content -Path $resultPath

		if ($result.Error) { throw $result.Error }
	}
	#endregion Wrapper

	$argumentData = @{
		Count = $ArgumentList.Count
		Arguments = $ArgumentList
	}
	$taskIdentity = "$Name-$([guid]::NewGuid())"
	$plaintextCode = $wrapperScript.ToString() -replace '%LOGPATH%', $LogPath -replace '%IDENTITY%', $taskIdentity -replace "'%PAYLOAD%'", $ScriptBlock.ToString() -replace '%ARGUMENTS%',($argumentData | ConvertTo-Json -Depth 5 -Compress)
	$bytes = [System.Text.Encoding]::Unicode.GetBytes($plaintextCode)
	$encodedCommand = [Convert]::ToBase64String($bytes)

	$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $encodedCommand"
	$principal = New-ScheduledTaskPrincipal -UserId $Identity -RunLevel Highest -LogonType Password
	if ($Interactive) { $principal.LogonType = 'Interactive' }

	$registerParam = @{
		TaskName = "PowerShell_System_$taskIdentity"
		Description = "PowerShell Task - $Name"
		Action = $action
		Principal = $principal
	}
	if ($Password) {
		$registerParam.User = $Identity
		$registerParam.Password = [PSCredential]::new("Whatever", $Password).GetNetworkCredential().Password
	}
	$task = Register-ScheduledTask @registerParam
	$task | Start-ScheduledTask
	try {
		$start = Get-Date

		Write-Progress -Activity "Waiting for Task to complete"
		while (($task | Get-ScheduledTask).State -ne "Ready") {
			Write-Progress -Activity "Waiting for Task to complete" -Status "Started $($start.ToString('HH:mm:ss')), running for $(((Get-Date) - $start).ToString('c'))" -PercentComplete 0
			Start-Sleep -Seconds 1
		}
	}
	finally {
		Write-Progress -Activity "Waiting for Task to complete" -Completed

		$info = $task | Get-ScheduledTaskInfo
		$currentTask = $task | Get-ScheduledTask
		if ($currentTask.State -ne 'Ready') { $currentTask | Stop-ScheduledTask }
		$task | Unregister-ScheduledTask -Confirm:$false

		$resultFile = Join-Path -Path $LogPath -ChildPath "$taskIdentity.json"
		$logsFile = Join-Path -Path $LogPath -ChildPath "$taskIdentity.csv"

		$result = [PSCustomObject]@{
			Success = $true
			Code = $info.LastTaskResult
			Logs = @()
			Error = $null
			Output = $null
		}

		if (Test-Path -Path $resultFile) {
			$data = Get-Content -Path $resultFile | ConvertFrom-Json
			Remove-Item -Path $resultFile
			$result.Logs = $data.Logs
			$result.Error = $data.Error
			$result.Output = $data.Output
			if ($data.Error) { $result.Success = $false }
			if (Test-Path -Path $logsFile) {
				Remove-Item -Path $logsFile
			}
		}
		else {
			if (Test-Path -Path $logsFile) {
				try { $result.Logs = Import-Csv -Path $logsFile }
				catch { }
				Remove-Item -Path $logsFile -ErrorAction SilentlyContinue
			}
			$result.Success = $false
		}

		if ($info.LastTaskResult -ne 0) { $result.Success = $false }

		$result
	}
}
