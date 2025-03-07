#requires -Modules EntraAuth
<#
.SYNOPSIS
	Grants scopes to a managed identity.

.DESCRIPTION
	Grants scopes to a managed identity.
	In case of ambiguous names provided, it will NOT assign scopes and instead error out, listing the options.

	In order for this script to work, an existing AEntraAuth connection to graph must exist.
	Use "Connect-EntraService" to connect.

	E.g.:
	Connect-EntraService -ClientID Graph -Scopes 'Application.Read.All', 'AppRoleAssignment.ReadWrite.All'

	Note: The effects of this command may require a few minutes to take effect and be recognized by the managed application.

.PARAMETER Identity
	Name or ID of the Identity to grant scopes to.
	In case of ambiguous names provided, it will NOT assign scopes and instead error out, listing the options.

.PARAMETER Scope
	The scopes to assign. Can be IDs or text label.
	E.g.: User.Read.All

.PARAMETER Resource
	The ID of the resource the scope belongs to.
	E.g.: 00000003-0000-0000-c000-000000000000 # Graph API

.EXAMPLE
	PS C:\> .\MSI-grant-scope.ps1 -Identity MyAutomationAccount -Scope User.Read.All -Resource 00000003-0000-0000-c000-000000000000

	Grants the "User.Read.All" graph scope to the identity of the "MyAutomationAccount" automation account.
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string]
	$Identity,

	[Parameter(Mandatory = $true)]
	[string[]]
	$Scope,

	[Parameter(Mandatory = $true)]
	[string]
	$Resource
)

if (-not (Get-EntraToken -Service Graph)) {
	Write-Warning "Not connected to graph yet! Run 'Connect-EntraService' to connect first. Scopes needed: Application.Read.All, AppRoleAssignment.ReadWrite.All"
	throw "Not connected to graph yet! Run 'Connect-EntraService' to connect first. Scopes needed: Application.Read.All, AppRoleAssignment.ReadWrite.All"
}

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

#region Functions
function Resolve-MsiIdentity {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Identity
	)

	if ($Identity -as [guid]) { return $Identity }

	$found = Invoke-EntraRequest servicePrincipals -Query @{
		'$filter' = "displayName eq '$Identity' and servicePrincipalType eq 'ManagedIdentity'"
	}

	if (-not $found) {
		throw "No Managed Identity with name $Identity found!"
	}
	if ($found.Count -gt 1) {
		Write-Warning "Ambiguous result! $($found.Count) managed identites found under the name $($Identity):"
		foreach ($item in $found) {
			Write-Warning "- ID: $($item.id) | AppID: $($item.AppId) (Created on: $($item.createdDateTime))"
		}
		throw "Ambiguous result! $($found.Count) managed identites found under the name $($Identity)"
	}
	$found.id
}

function Resolve-GraphApplicationScope {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$ResourceID,

		[Parameter(Mandatory = $true)]
		[string]
		$Scope,

		[Parameter(Mandatory = $true)]
		[ValidateSet('Application', 'Delegated')]
		[string]
		$Type,

		[switch]
		$AsName
	)

	if ($Scope -as [guid] -and -not $AsName) { return $Scope }

	if (-not $script:_appCache) { $script:_appCache = @{ } }
	if (-not $script:_appCache[$ResourceID]) {
		$script:_appCache[$ResourceID] = Invoke-EntraRequest -Path "servicePrincipals(appId='$ResourceID')?`$select=id,appId,displayName,appRoles,oauth2PermissionScopes,resourceSpecificApplicationPermissions"
	}

	if ($AsName) {
		if ($Type -eq 'Delegated') {
			$name = ($script:_appCache[$ResourceID].oauth2PermissionScopes | Where-Object Id -EQ $Scope).Value
			if (-not $name) { throw "$Type scope $Scope not found on resource $ResourceID" }
			return $name
		}
		else {
			$name = ($script:_appCache[$ResourceID].resourceSpecificApplicationPermissions | Where-Object Id -EQ $Scope).Value
			if (-not $name) { $name = ($script:_appCache[$ResourceID].appRoles | Where-Object Id -EQ $Scope).Value }
			if (-not $name) { throw "$Type scope $Scope not found on resource $ResourceID" }
			return $name
		}
	}
	else {
		if ($Type -eq 'Delegated') {
			$id = ($script:_appCache[$ResourceID].oauth2PermissionScopes | Where-Object Value -EQ $Scope).id
			if (-not $id) { throw "$Type scope $Scope not found on resource $ResourceID" }
			return $id
		}
		else {
			$id = ($script:_appCache[$ResourceID].resourceSpecificApplicationPermissions | Where-Object Value -EQ $Scope).id
			if (-not $id) { $id = ($script:_appCache[$ResourceID].appRoles | Where-Object Value -EQ $Scope).id }
			if (-not $id) { throw "$Type scope $Scope not found on resource $ResourceID" }
			return $id
		}
	}
}

function Resolve-GraphServicePrincipal {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$AppId
	)

	if (-not $script:_spnCache) { $script:_spnCache = @{ } }
	if ($script:_spnCache[$AppId]) { return $script:_spnCache[$AppId] }

	$script:_spnCache[$AppId] = Invoke-EntraRequest -Path "servicePrincipals(appId='$AppId')"
	$script:_spnCache[$AppId]
}

function New-GraphSpnAppRoleAssignment {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Identity,

		[Parameter(Mandatory = $true)]
		[string]
		$Resource,

		[Parameter(Mandatory = $true)]
		[string[]]
		$Scopes
	)

	$rolesAssigned = Invoke-EntraRequest -Path "servicePrincipals/$($Identity)/appRoleAssignments"
	$actualResourceId = (Resolve-GraphServicePrincipal -AppId $Resource).id

	foreach ($scope in $Scopes) {
		$grant = @{
			"principalId" = $Identity
			"resourceId"  = $actualResourceId
			"appRoleId"   = Resolve-GraphApplicationScope -ResourceID $Resource -Scope $scope -Type Application
		}
		if ($rolesAssigned | Where-Object {
				$_.resourceId -eq $grant.resourceId -and
				$_.appRoleId -eq $grant.appRoleId
			}) {
			Write-Verbose "Skipping scope $scope - already assigned to $Identity"
			continue
		}

		Write-Verbose "Assigning role $($grant.appRoleId) ($scope)) to $($Identity)"
		$null = Invoke-EntraRequest -Method POST -Path "servicePrincipals/$($Identity)/appRoleAssignments" -Body $grant -Header @{
			'content-type' = 'application/json'
		}
	}
}
#endregion Functions

$actualIdentity = Resolve-MsiIdentity -Identity $Identity
New-GraphSpnAppRoleAssignment -Id $actualIdentity -Resource $Resource -Scopes $Scope
