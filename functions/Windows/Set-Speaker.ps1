function Set-Speaker {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipelineByPropertyName = $true)]
		[string]
		$ComputerName,

		[PSCredential]
		$Credential,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ID,

		[string]
		$DisplayName,

		[string]
		$Description
	)

	begin {
		#region Scriptblock
		$scriptblock = {
			param (
				$Data
			)
			foreach ($command in $Data.Commands) {
				Set-Item -Path "function:\$($command.Name)" -Value $command.Definition
			}
			$ID = $Data.ID
			$DisplayName = $Data.DisplayName
			$Description = $Data.Description

			# Enable-Privilege -Privilege SeRestorePrivilege
			# Enable-Privilege -Privilege SeBackupPrivilege
			$rootKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
			$speakerRoot = Join-Path -Path $rootKey -ChildPath $ID
			if (-not (Test-Path -Path $speakerRoot)) {
				Write-Error "Speaker not found: $ID"
				return
			}

			$propertyRoot = Join-Path -Path $speakerRoot -ChildPath Properties
			Enable-RegistryAccess -Path $propertyRoot
			$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(($propertyRoot -replace '^HKLM:\\'), $true)
			try {
				if ($DisplayName) {
					$key.SetValue('{a45c254e-df1c-4efd-8020-67d146a850e0},2', $DisplayName)
				}
				if ($Description) {
					$key.SetValue('{b3f8fa53-0004-438e-9003-51a46e139bfc},26', $Description)
				}
			}
			finally {
				$key.Close()
				Disable-RegistryAccess -Path $propertyRoot
			}
		}
		#endregion Scriptblock
	}
	process {
		$param = @{
			ArgumentList = @{
				ID          = $ID
				DisplayName = $DisplayName
				Description = $Description
				Commands = @(
					Get-Command Enable-Privilege
					Get-Command Disable-Privilege
					Get-Command Enable-RegistryAccess
					Get-Command Disable-RegistryAccess
				)
			}
		}
		if ($ComputerName) { $param.ComputerName = $ComputerName }
		if ($Credential) { $param.Credential = $Credential }

		Invoke-Command @param -ScriptBlock $scriptblock
	}
}