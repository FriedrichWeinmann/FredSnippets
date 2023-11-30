<#
.SYNOPSIS
	A script to transfer modules from one repository to another while codesigning them.

.DESCRIPTION
	Script intended for use in a code-signing pipeline:
	It will scan source and destination repository and for each missing (or lower version) module will:
	- Download the module from the source repository
	- Sign all code from that module with the specified certificate retrieved from certificate store.
	- Publish the module to the destination store

	It supports all PowerShellGet versions.

.PARAMETER SourceRepository
	Name of the repository to download the unsigned modules from.
	Read access must be granted outside of this script.

.PARAMETER DestinationRepository
	Name of the repository to publish the signed modules to.

.PARAMETER Certificate
	Thumbprint or Subject Name of the certificate to use for signing.
	Certificate is retrieved from the certificate store (preferring current user over the machine store).
	Thumbprint is assumed over subject.
	When selecting by name, the certificate with the longest validity is chosen.

.PARAMETER TimestampServer
	The timestamp server - if any - to use for signing.
	If specified, modules are not only signed, but also have the time of signing verified.
	Including a timestamp ensures that code signed before revoking the certificate remains valid.

.PARAMETER SubFolder
	Only affect a specific subfolder, rather than signing the full module.

.PARAMETER AdmfContext
	Assumes the module being signed is the result of the Publish-AdmfContext command,
	a special kind of module designed to transport ADMF contexts via PowerShellGet

.PARAMETER ApiKey
	ApiKey to use for publishing signed modules.
	Optional when using PowerShellGet v3+, where authentication may be provided for when registering the repository.
	Required when not using the newer PowerShellGet versions, even if it is not used (e.g. when using Windows Authentication).

.PARAMETER UseGetV3
	Switch to using the commands of PowerShellGet v3 or later.
	By default, commands from PowerShellGet versions 1-2 are used (Find-Module, Save-Module, Publish-Module).
	Keep in mind that repositories are registered and maintained separately between versions and ensure the environment executing this script has the correct versions registered.

.EXAMPLE
	PS C:\> .\module-signing.ps1 -SourceRepository unsigned -DestinationRepository signed -Certificate 'CN=Contoso-Pwsh-Module' -TimestampServer timestamp.contoso.com -UseGetV3

	Retrieve all modules in the "unsigned" repository not yet available in the "signed" repository,
	then sign them using the 'CN=Contoso-Pwsh-Module' certificate, signing the timestamp using timestamp.contoso.com.
	Use PowerShellGet v3 to execute this workflow
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string]
	$SourceRepository,
    
	[Parameter(Mandatory = $true)]
	[string]
	$DestinationRepository,

	[Parameter(Mandatory = $true)]
	[string]
	$Certificate,

	[string]
	$TimestampServer,

	[string]
	$SubFolder,

	[switch]
	$AdmfContext,

	[string]
	$ApiKey,

	[switch]
	$UseGetV3
)

try { $config = Import-PowerShellDataFile -Path "$PSScriptRoot\signing.config.psd1" -ErrorAction Stop }
catch { $config = @{ } }

#region Functions
function New-TempFolder {
	[CmdletBinding()]
	param (
		[switch]
		$AddToModulePath
	)

	$path = Join-Path $env:TEMP "tempfolder-ps-$(Get-Random)"
	$null = New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop
	if ($AddToModulePath) {
		$env:PSModulePath = '{0};{1}' -f $Path, $env:PSModulePath
	}
	$path
}

function Remove-TempFolder {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Path
	)

	Remove-Item -Path $Path -Force -Recurse -ErrorAction Ignore
}

function Resolve-Certificate {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Name
	)
    
	$cert = Get-ChildItem -Path cert:\CurrentUser\My | Where-Object Thumbprint -EQ $Name
	if ($cert) { return $cert }
	$cert = Get-ChildItem -Path cert:\CurrentUser\My | Where-Object Subject -EQ $Name | Sort-Object NotAfter -Descending | Select-Object -First 1
	if ($cert) { return $cert }

	$cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object Thumbprint -EQ $Name
	if ($cert) { return $cert }
	$cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object Subject -EQ $Name | Sort-Object NotAfter -Descending | Select-Object -First 1
	if ($cert) { return $cert }

	throw "Certificate not found: $Name"
}

function Get-ModulesToSign {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$From,
        
		[Parameter(Mandatory = $true)]
		[string]
		$To,
        
		[AllowEmptyCollection()]
		[AllowNull()]
		[string[]]
		$Ignore,

		[switch]
		$UseGetV3
	)

	if (-not $Ignore) { $Ignore = @() }
	if ($UseGetV3) {
		$modulesFrom = Find-PSResource -Type Module -Repository $From | Where-Object Name -NotIn $Ignore
		$modulesTo = Find-PSResource -Type Module -Repository $To | Where-Object Name -NotIn $Ignore
	}
	else {
		$modulesFrom = Find-Module -Repository $From | Where-Object Name -NotIn $Ignore
		$modulesTo = Find-Module -Repository $To | Where-Object Name -NotIn $Ignore
	}
	foreach ($module in $modulesFrom) {
		if ($modulesTo | Where-Object { $_.Name -eq $module.Name -and $_.Version -eq $module.Version }) {
			continue
		}

		[PSCustomObject]@{
			Name    = $module.Name
			Version = $module.Version
			Path    = ''
		}
	}
}

function Save-ModuleCode {
	[CmdletBinding()]
	param (
		$Module,

		[string]
		$Repository,

		[string]
		$Path,

		[switch]
		$UseGetV3
	)

	$saveParam = @{
		Name       = $Module.Name
		Path       = $Path
		Repository = $Repository
	}
	if ($UseGetV3) { Save-PSResource @saveParam -Version $Module.Version }
	else { Save-Module @saveParam -RequiredVersion $Module.Version -Force }
	$Module.Path = '{0}\{1}\{2}' -f $Path, $Module.Name, $Module.Version
}

function Set-ModuleSignature {
	[CmdletBinding()]
	param (
		$Module,

		[AllowEmptyString()]
		[string]
		$SubFolder,

		[switch]
		$AdmfContext,

		[Parameter(Mandatory = $true)]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]
		$Certificate,

		[string]
		$TimestampServer
	)

	$signParam = @{
		Certificate = $Certificate
		Force       = $true
	}
	if ($TimestampServer) { $signParam.TimestampServer = $TimestampServer }

	$extensionsToSign = @(
		'.ps1'
		'.psm1'
		'.psd1'
		'.ps1xml'
		'.cs'
		'.dll'
	)

	$path = $Module.Path
	if ($SubFolder) { $path = Join-Path $Module.Path $SubFolder }
	if ($AdmfContext) {
		$path = Resolve-Path "$($Module.Path)\*\*" | Select-Object -First 1
	}

	Get-ChildItem -Path $path -Recurse -File | Where-Object Extension -In $extensionsToSign | Set-AuthenticodeSignature @signParam
	New-FileCatalog -CatalogVersion 2.0 -CatalogFilePath "$path\$($Module.Name).cat" -Path $path
	Set-AuthenticodeSignature @signParam -FilePath "$path\$($Module.Name).cat"
}

function Publish-ModuleCode {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		$Module,

		[Parameter(Mandatory = $true)]
		[string]
		$Repository,

		[AllowEmptyString()]
		[string]
		$ApiKey,

		[switch]
		$UseGetV3
	)

	$publishParam = @{
		Path = $Module.Path
		Repository = $Repository
	}
	if ($ApiKey) {
		if ($UseGetV3) { $publishParam.ApiKey = $ApiKey }
		else { $publishParam.NuGetApiKey = $ApiKey }
	}

	try {
		if ($UseGetV3) { Publish-PSResource @publishParam }
		else { Publish-Module @publishParam }
		Remove-Item -Path $Module.Path -Recurse -Force -ErrorAction Ignore
	}
 catch {
		Write-Warning "Failed to publish module $($Module.Name) ($($Module.Version)): $_"
	}
}
#endregion Functions

$tempFolder = New-TempFolder -AddToModulePath
$certificateObject = Resolve-Certificate -Name $Certificate
$modulesToSign = Get-ModulesToSign -From $SourceRepository -To $DestinationRepository -Ignore $config.ModulesToIgnore -UseGetV3:$UseGetV3
foreach ($module in $modulesToSign) {
	Save-ModuleCode -Module $module -Repository $SourceRepository -Path $tempFolder -UseGetV3:$UseGetV3
	Set-ModuleSignature -Module $module -Certificate $certificateObject -SubFolder $SubFolder -AdmfContext:$AdmfContext
	Publish-ModuleCode -Module $module -Repository $DestinationRepository -UseGetV3:$UseGetV3 -ApiKey $ApiKey
}
Remove-TempFolder -Path $tempFolder

<#
MIT License

Copyright (c) 2023 Friedrich Weinmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
#>