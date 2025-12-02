function Start-AuditLog {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Path
	)

	Stop-AuditLog
	$script:_auditLogger = { Set-Content -Path $Path }.GetSteppablePipeline()
	$script:_auditLogger.Begin($true)
}

function Write-AuditLog {
	[CmdletBinding()]
	param (
		[string]
		$Message
	)

	if (-not $script:_auditLogger) { return }
	$msg = '{0:yyyy-MM-dd HH:mm:ss.fff} - {1}' -f (Get-Date).ToUniversalTime(), $Message
	$script:_auditLogger.Process($msg)
}

function Stop-AuditLog {
	[CmdletBinding()]
	param ()

	if (-not $script:_auditLogger) { return }
	$script:_auditLogger.End()
	$script:_auditLogger = $null
}

function Invoke-AuditedCommand {
	[CmdletBinding()]
	param (
		[Scriptblock]
		$ScriptBlock,

		$ArgumentList,

		[hashtable]
		$Parameters,

		[string]
		$ExportPath,

		[switch]
		$Append
	)

	$divide = '================================================================================'

	$textCode = $ScriptBlock.ToString().Trim()
	foreach ($paramName in $Parameters.Keys) {
		$textCode = $textCode -replace "%$($paramName)%", $Parameters.$paramName
	}
	$newCode = [scriptblock]::Create($textCode)

	Write-AuditLog -Message $divide
	Write-AuditLog -Message $divide
	Write-AuditLog -Message "  Executing Command"
	foreach ($line in $textCode -split "`n") {
		Write-AuditLog -Message "    $line"
	}
	Write-AuditLog -Message $divide
	Write-AuditLog -Message "  Arguments: $($ArgumentList -join ' ')"
	
	$result = $null
	try {
		$result = & $newCode $ArgumentList
		Write-AuditLog -Message "  Success: True"
	}
	catch {
		Write-AuditLog -Message "  Success: False"
		Write-AuditLog -Message "  Error: $_"
		Write-AuditLog -Message $divide
		throw
	}
	Write-AuditLog -Message $divide
	Write-AuditLog -Message "  Output:"
	$result | ConvertTo-Csv -NoTypeInformation | ForEach-Object {
		Write-AuditLog -Message "    $_"
	}
	Write-AuditLog -Message $divide

	if ($ExportPath) {
		$result | Export-Csv -Path $ExportPath -Append:$Append
	}
}