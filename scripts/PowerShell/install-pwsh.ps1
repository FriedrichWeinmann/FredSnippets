<#
.SYNOPSIS
	Installs the latest version of PowerShell on the local computer.

.DESCRIPTION
	Installs the latest version of PowerShell on the local computer.
	Only supports windows computers.

	Will ignore preview or RC releases.

	Intended for use in Automation Accounts to bootstrap PowerShell 7 into hybrid workers.
	Note: Hybrid Workers will likely need to be rebooted before PowerShell will be detected.

 	To Install modules permanently into a Hybrid Worker, I strongly recommend using the Module "ModuleFast":

	Invoke-WebRequest bit.ly/modulefast -UseBasicParsing | Invoke-Expression
	Install-ModuleFast -Specification "ModuleName" -Destination "C:\Program Files\WindowsPowerShell\Modules"

.PARAMETER Type
	What architecture-version of windows to install PowerShell for.
	Supports: x64, x86 or arm64
	Defaults to: x64

.EXAMPLE
	PS C:\> install-pwsh.ps1

	Installs the 64bit version of PowerShell.
#>
[CmdletBinding()]
param (
	[ValidateSet('x64', 'x86', 'arm64')]
	[string]
	$Type = 'x64'
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	if ($setupPath) {
		Remove-Item -Path (Split-Path -Path $setupPath) -Force -Recurse
	}
	throw $_
}

#region Functions
function Get-PowerShellRelease {
	[CmdletBinding()]
	param (
		[ValidateSet('x64', 'x86', 'arm64')]
		[string]
		$Type = 'x64'
	)

	$release = Invoke-RestMethod 'https://api.github.com/repos/powershell/powershell/releases' | Write-Output | Where-Object tag_name -NotMatch 'preview|rc' | Select-Object -First 1
	$release.assets | Where-Object Name -match "win-$($Type)\.msi$"
}

function Install-PowerShellInstaller {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Url
	)

	Invoke-WebRequest -Uri $Url -OutFile "$env:TEMP\pwsh.msi"

	"$env:TEMP\pwsh.msi"
}

function Install-PowerShell {
	[CmdletBinding()]
	param (
		[string]
		$Path
	)

	Write-Host "msiexec.exe /i $Path /quiet"
	Start-Process msiexec.exe -ArgumentList @(
		'/i'
		$Path
		'/quiet'
	) -Wait
}
#endregion Functions

$asset = Get-PowerShellRelease -Type $Type
$setupPath = Install-PowerShellInstaller -Url $asset.browser_download_url
Install-PowerShell -Path $setupPath
Remove-Item -Path $setupPath -Force -Recurse
