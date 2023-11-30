function Disable-RegistryAccess {
	[CmdletBinding()]
	param (
		[string]
		$Path
	)

	$rootPath = $Path -replace '^HKLM:\\'

	Enable-Privilege -Privilege SeBackupPrivilege
	Enable-Privilege -Privilege SeRestorePrivilege
	Enable-Privilege -Privilege SeTakeOwnershipPrivilege

	if (-not $script:_registryAccess) {
		$script:_registryAccess = @{ }
	}
	$config = $script:_registryAccess[$rootPath]

	# Step 1: Remove new rule
	if ($config.NewRule) {
		$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rootPath, 'ReadWriteSubTree', 'QueryValues')
		$acl = $key.GetAccessControl()
		$acl.RemoveAccessRuleSpecific($config.NewRule)
		$key.SetAccessControl($acl)
		$key.Close()
	}

	# Step 2: Restore Ownership
	if ($config.Owner) {
		$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($rootPath, 'ReadWriteSubTree', 'QueryValues')
		$acl = $key.GetAccessControl()
		$acl.SetOwner($config.Owner)
		$key.SetAccessControl($acl)
		$key.Close()
	}

	$script:_registryAccess.Remove($rootPath)

	Disable-Privilege -Privilege SeBackupPrivilege
	Disable-Privilege -Privilege SeRestorePrivilege
	Disable-Privilege -Privilege SeTakeOwnershipPrivilege
}