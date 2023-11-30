function Enable-RegistryAccess {
	[CmdletBinding()]
	param (
		[string]
		$Path
	)

	$rootPath = $Path -replace '^HKLM:\\'
	$changeData = @{
		Owner = $null
		NewRule = $null
	}

	Enable-Privilege -Privilege SeBackupPrivilege
	Enable-Privilege -Privilege SeRestorePrivilege
	Enable-Privilege -Privilege SeTakeOwnershipPrivilege

	if (-not $script:_registryAccess) {
		$script:_registryAccess = @{ }
	}

	$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().User

	# Step 1: Take Ownership
	$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rootPath, 'ReadWriteSubTree', 'QueryValues')
	$acl = $key.GetAccessControl()
	$changeData.Owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
	$acl.SetOwner($currentUser)
	$key.SetAccessControl($acl)
	$key.Close()

	# Step 2: Set Access Rights
	$rule = [System.Security.AccessControl.RegistryAccessRule]::new(
		$currentUser,
		[System.Security.AccessControl.RegistryRights]::FullControl,
		'Allow'
	)
	$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rootPath, 'ReadWriteSubTree', 'QueryValues')
	$acl = $key.GetAccessControl()
	$acl.AddAccessRule($rule)
	$key.SetAccessControl($acl)
	$key.Close()
	$changeData.NewRule = $rule

	$script:_registryAccess[$rootPath] = $changeData

	Disable-Privilege -Privilege SeBackupPrivilege
	Disable-Privilege -Privilege SeRestorePrivilege
	Disable-Privilege -Privilege SeTakeOwnershipPrivilege
}