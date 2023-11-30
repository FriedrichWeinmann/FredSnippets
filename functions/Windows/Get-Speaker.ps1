function Get-Speaker {
	[CmdletBinding()]
	param (
		[string[]]
		$ComputerName,

		[PSCredential]
		$Credential,

		[string]
		$Name = '*',

		[ValidateSet('Enabled', 'Removed', 'Disconnected', 'All')]
		[string[]]
		$Type = @('Enabled', 'Disconnected')
	)

	begin {
		#region Code
		$scriptblock = {
			param (
				$Data
			)

			$Name = $Data.Name
			$Type = $Data.Type

			$rootKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"
		
			:main foreach ($speakerRoot in Get-ChildItem -Path $rootKey) {
				$rootProperties = Get-ItemProperty -LiteralPath $speakerRoot.PSPath
				$properties = Get-ItemProperty -LiteralPath "$($speakerRoot.PSPath)\Properties"
				if ($properties.'{a45c254e-df1c-4efd-8020-67d146a850e0},2' -notlike $Name) { continue }

				if ($Type -notcontains 'All') {
					switch ($rootProperties.DeviceState) {
						1 { if ($Type -notcontains 'Enabled') { continue main } }
						4 { if ($Type -notcontains 'Removed') { continue main } }
						8 { if ($Type -notcontains 'Disconnected') { continue main } }
						default { continue main }
					}
				}
				$state = switch ($rootProperties.DeviceState) {
					1 { 'Enabled' }
					4 { 'Removed' }
					8 { 'Disconnected' }
					default { "Unknown ($_)" }
				}
				[PSCustomObject]@{
					ID            = $speakerRoot.PSChildName
					State         = $state
				
					# Resolved Properties
					Name          = $properties.'{b3f8fa53-0004-438e-9003-51a46e139bfc},6'
					DisplayName   = $properties.'{a45c254e-df1c-4efd-8020-67d146a850e0},2'
					Description   = $properties.'{b3f8fa53-0004-438e-9003-51a46e139bfc},26'
					Driver        = $properties.'{a8b865dd-2e3d-4094-ad97-e593a70c75d6},5'
					DriverDetails = $properties.'{83da6326-97a6-4088-9453-a1923f573b29},3'

					# All Data
					Properties    = $properties
					ComputerName  = $env:COMPUTERNAME
				}
			}
		}
		#endregion Code
	}
	process {

		$param = @{
			ArgumentList = @{
				Name = $Name
				Type = $Type
			}
		}
		if ($ComputerName) { $param.ComputerName = $ComputerName }
		if ($Credential) { $param.Credential = $Credential }
		$results = Invoke-Command @param -ScriptBlock $scriptblock
		$results
	}
}