function Export-SupportPackage {
	[CmdletBinding()]
	param ()

	$tempFolder = New-Item -Path $env:TEMP -Name "PS-Debug-$(Get-Random)"
	$error | Export-Clixml "$($tempFolder.FullName)\errors.clixml"
	Get-History | Export-Clixml "$($tempFolder.FullName)\history.clixml"
	ipconfig /all | Set-Content "$($tempFolder.FullName)\ipconfig.txt"
	$PSVersionTable | Export-Clixml "$($tempFolder.FullName)\psversion.clixml"
	Get-Module | Export-Clixml "$($tempFolder.FullName)\modules.clixml"
	Get-CimInstance Win32_ComputerSystem | Export-Clixml "$($tempFolder.FullName)\computersystem.clixml"
	Get-CimInstance Win32_OperatingSystem | Export-Clixml "$($tempFolder.FullName)\os.clixml"
	Get-ChildItem env: | Export-Clixml "$($tempFolder.FullName)\environment.clixml"
	[AppDomain]::CurrentDomain.GetAssemblies() | Select-Object Location, FullName | Export-Clixml "$($tempFolder.FullName)\assemblies.clixml"

	$debugFolder = Join-Path $env:APPDATA "PowerShell\debug\dumps"
	if (-not (Test-Path -Path $debugFolder)) {
		$null = New-Item -Path $debugFolder -ItemType Directory -Force
	}

	Compress-Archive -Path "$($tempFolder.FullName)\*" -DestinationPath "$debugFolder\Dump-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').zip"
	Remove-Item $tempFolder.FullName -Recurse -Force -ErrorAction Ignore

	# Logrotate
	Get-ChildItem -Path $debugFolder | Where-Object LastWriteTime -LT (Get-Date).AddDays(-60) | Remove-Item -ErrorAction SilentlyContinue
}
