function Get-ServiceAccess {
	<#
	.SYNOPSIS
		Returns windows service security information from registry
	
	.DESCRIPTION
		Returns windows service security information from registry.
		This allows finding services that have been hidden from SCM through a deny rule.

		Triggered by this thread on Twitter:
		https://twitter.com/Alh4zr3d/status/1580925761996828672
		Where a simple one-liner was able to hide malicious services from an admin by setting deny rules to the service sddl
	
	.PARAMETER Computername
		Computer to scan
		Defaults to: localhost
	
	.PARAMETER Credential
		Credentials to use for the scan
	
	.EXAMPLE
		PS C:\> Get-ServiceAccess

		Returns service information from the local computer

	.EXAMPLE
		PS C:\> Get-ServiceAccess -ComputerName server1, server2, server3

		Returns service information from server1, server2 and server3
	#>
	[Cmdletbinding()]
	param (
		[string[]]
		$Computername = $env:COMPUTERNAME,

		[PSCredential]
		$Credential
	)

	begin {
		$scriptblock = {
			$startTypes = @{
				'-1' = 'Unknown'
				0    = 'Boot'
				1    = 'System'
				2    = 'Automatic'
				3    = 'Manual'
				4    = 'Disabled'
			}

			$serviceNodes = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services'
			foreach ($serviceNode in $serviceNodes) {
				$props = Get-ItemProperty -Path $serviceNode.PSPath
				$start = $props.Start
				if ($null -eq $start) { $start = '-1' }
				$data = @{
					ComputerName = $env:COMPUTERNAME
					Name         = $serviceNode.PSChildName
					Image        = $props.ImagePath
					Account      = $props.ObjectName
					StartType    = $startTypes[$start]
					Privileges   = $props.RequiredPrivileges
					Sddl         = ''
					AccessRules  = $null
					HasDenyRule  = $false
				}

				if (Test-Path -Path "$($serviceNode.PSPath)\Security") {
					$secProp = Get-ItemProperty -Path "$($serviceNode.PSPath)\Security"
					if ($secProp.Security) {
						$data.Sddl = (Invoke-CimMethod -ClassName Win32_SecurityDescriptorHelper -MethodName BinarySDToSDDL -Arguments @{ BinarySD = $secProp.Security }).SDDL
						$acl = [System.Security.AccessControl.RegistrySecurity]::new()
						$acl.SetSecurityDescriptorBinaryForm($secProp.Security)
						$data.AccessRules = $acl.Access
						$data.HasDenyRule = ($acl.Access | Where-Object AccessControlType -EQ 'Deny') -as [bool]
					}
				}
				[PSCustomObject]$data
			}
		}
	}

	process {
		$param = @{
			ComputerName = $Computername
		}
		if ($Credential) { $param.Credential = $Credential }
		Invoke-Command @param -ScriptBlock $scriptblock
	}
}