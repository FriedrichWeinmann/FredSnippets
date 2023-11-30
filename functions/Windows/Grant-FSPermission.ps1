function Grant-FSPermission {
	<#
	.SYNOPSIS
		Helper tool to simplify file system permission assignments.
	
	.DESCRIPTION
		Helper tool to simplify file system permission assignments.
		Allows bulk-updating / assigning permissions.
	
	.PARAMETER Identity
		The identity to grant permissions to.
		May be a SID or a translatable NTAccount specification.
		Examples:
		S-1-1-0
		contoso\auditusers
		S-1-5-21-11111234567-112233445-9876543210-123456
	
	.PARAMETER Path
		Path to the file or folder to modify access on.
	
	.PARAMETER Right
		The rights to assign.
	
	.PARAMETER ChildrenOnly
		Whether only child-objects under the specified path should be affected by this setting
	
	.PARAMETER Inheritance
		What kind of child-objects should be affected?
		All, only files, only folders or none at all?
	
	.PARAMETER Deny
		Whether the access rule created should be a deny rule
	
	.EXAMPLE
		PS C:\> Grant-FSPermission -Path \\contoso\operations\profiles -Right FullControl -Identity contoso\FS-ProfileManagement

		Grants fullcontrol permissions over \\contoso\operations\profiles and all children to contoso\FS-ProfileManagement

	.EXAMPLE
		PS C:\> Grant-FSPermission -Path \\contoso\operations\profiles\mm -Right FullControl -Identity contoso\mm -ChildrenOnly

		Grants fullcontrol permissions over all items in \\contoso\operations\profiles to contoso\mm, without aaffectign the rights on the folder itself.

	.EXAMPLE
		PS C:\> Import-Csv .\data.csv | Grant-FSPermission -Right ChangePermissions

		Grants the right to change permissions to all path & identity pairs specified in the input file.
		This requires the data.csv input file to contain at least two columns: Path & Identity.
		Each column will be matched to the parameter of the exact same name (ignoring case).
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Identity,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[Alias('FullName')]
		[string[]]
		$Path,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
		[ValidateSet('Read', 'Write', 'Modify', 'FullControl', 'ChangePermissions')]
		[string]
		$Right,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[switch]
		$ChildrenOnly,

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[ValidateSet('All', 'Files', 'Folders', 'None')]
		[string]
		$Inheritance = 'All',

		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[switch]
		$Deny
	)

	begin {
		function Resolve-Principal {
			[CmdletBinding()]
			param (
				[string]
				$Identity
			)

			if ($Identity -as [System.Security.Principal.SecurityIdentifier]) {
				return $Identity -as [System.Security.Principal.SecurityIdentifier]
			}

			try { ([System.Security.Principal.NTAccount]$Identity).Translate([System.Security.Principal.SecurityIdentifier]) }
			catch { throw }
		}
	}
	process {
		try { $principal = Resolve-Principal -Identity $Identity -ErrorAction Stop }
		catch {
			Write-Error "Unable to resolve $Identity : $_"
			return
		}

		$rights = switch ($Right) {
			'Read' { [System.Security.AccessControl.FileSystemRights]::Read }
			'Write' { [System.Security.AccessControl.FileSystemRights]'Read, Write' }
			'Modify' { [System.Security.AccessControl.FileSystemRights]'Modify' }
			'FullControl' { [System.Security.AccessControl.FileSystemRights]'FullControl' }
			'ChangePermissions' { [System.Security.AccessControl.FileSystemRights]'Read, ReadPermissions, ChangePermissions' }
		}
		$propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
		if ($ChildrenOnly) { $propagationFlags = [System.Security.AccessControl.PropagationFlags]::InheritOnly }
		$inheritanceFlags = switch ($Inheritance) {
			'All' { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
			'Files' { [System.Security.AccessControl.InheritanceFlags]::ObjectInherit }
			'Folders' { [System.Security.AccessControl.InheritanceFlags]::ContainerInherit }
			'None' { [System.Security.AccessControl.InheritanceFlags]::None }
		}
		$type = 'Allow'
		if ($Deny) { $type = 'Deny' }

		foreach ($fsPath in $Path) {
			try { $acl = Get-Acl -Path $fsPath -ErrorAction Stop }
			catch {
				Write-Error "Error accessing permissions from $fsPath : $_"
				continue
			}
			$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($principal, $rights, $inheritanceFlags, $propagationFlags, $type)
			$acl.AddAccessRule($rule)
			try { $acl | Set-Acl -Path $fsPath }
			catch {
				Write-Error "Error writing permissions to $fsPath : $_"
				continue
			}
		}
	}
}