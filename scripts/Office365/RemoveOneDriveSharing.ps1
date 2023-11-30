#Requires -Modules MiniGraph
<#
.SYNOPSIS
	Clear all sharing permissions on a user's OneDrive

.DESCRIPTION
	Before running this script, use any of the suitable Connect-* Commands in the MiniGraph module to connect.

	Scopes needed for this script:
	- User.Read.All : To retrieve the user data from graph
	- Sites.ReadWrite.All : To modify permissions on Sharepoint
	As this would usually be used for administrative purposes, Application authentication is recommended.
	This in turn means the permissions are highly sensitive and wide in scope.

.PARAMETER Depth
	How deeply nested we should recurse through a user's OneDrive.
	Set it to a negative value to remove any depth limits.
	Defaults to: 2

.PARAMETER User
	The user to search.
	Will try to do them all if not specified.

.PARAMETER All
	Confirm you really want to process ALL users in your tenant.
#>

[CmdletBinding()]
Param(
	[int]
	$Depth = 2,
	
	[string[]]
	$User,

	[switch]
	$All
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

Set-GraphEndpoint -Type beta

#region Functions
function Resolve-GraphUser {
	[CmdletBinding()]
	param (
		[AllowEmptyCollection()]
		[AllowNull()]
		[string[]]
		$User
	)

	if (-not $User) {
		Invoke-GraphRequest -Query 'users?$select=id'
		return
	}

	foreach ($userName in $User) {
		Invoke-GraphRequest -Query "users/$($userName)?`$select=id"
	}
}

function Get-OneDriveRoot {
	[CmdletBinding()]
	param (
		[parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('id')]
		[string[]]
		$UserID,

		[switch]
		$AsPath
	)

	process {
		foreach ($user in $UserID) {
			if ($AsPath) {
				"users/$($user)/drive/root"
				continue
			}

			try { Invoke-GraphRequest -Query "users/$($user)/drive/root" -ErrorAction Stop }
			catch { Write-Warning "No drive root found for $user. User has possibly not been OneDrive provisioned | $_" }
		}
	}
}
function Get-OneDriveItem {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string[]]
		$Path,

		[switch]
		$Recurse,

		[int]
		$Depth,

		[switch]
		$SharedOnly
	)

	process {
		foreach ($oneDrivePath in $Path) {
			try { $children = Invoke-GraphRequest -Query "$oneDrivePath/children" }
			catch {
				Write-Warning "Path not found: $oneDrivePath | $_"
			}
			if ($SharedOnly) { $children | Where-Object Shared }
			else { $children }

			if (-not $Recurse) { continue }
			if (0 -eq $Depth) { continue }

			$queryRoot = $oneDrivePath -replace '^(.+?)/(.+?)/.+', '$1/$2/drive'

			foreach ($child in $children) {
				if (-not $child.Folder) { continue }

				Get-OneDriveItem -Path "$queryRoot/items/$($child.id)" -Recurse -Depth ($Depth - 1)
			}
		}
	}
}

function Remove-OneDriveSharingPermissions {
	[CmdletBinding()]
	Param(
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$UserId,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateNotNullOrEmpty()]
		[Alias('id')]
		[string]
		$ItemId
	)

	process {
		$basePath = "users/$($UserId)/drive/items/$($ItemId)/permissions"
		$permissions = Invoke-GraphRequest -Query $basePath

		foreach ($permission in $permissions) {
			if ($permission.inheritedFrom) { continue }
			if (-not $permission.Link) { continue }
			Write-Verbose "Clearing permission $($permission.Id) from $($ItemId) for user $($UserId)"
			$null = Invoke-GraphRequest -Method Delete -Query "$basePath/$($permission.id)"
		}
	}
}

#endregion Functions

if (-not $User -and -not $All) {
	throw "Use the -All parameter to really, truly clear all shared documents from all users in the tenant!"
}
Resolve-GraphUser -User $User -OutVariable graphUser |
	Get-OneDriveRoot -AsPath |
		Get-OneDriveItem -Recurse -Depth $Depth -SharedOnly |
			Remove-OneDriveSharingPermissions -UserId { $graphUser.id }