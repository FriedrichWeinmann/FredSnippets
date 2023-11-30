function Add-PrivateKeyRights {
	<#
	.SYNOPSIS
		Adds rights to the private key of a certificate.
	
	.DESCRIPTION
		Adds rights to the private key of a certificate.
		Useful for automating service account access to a system certificate.
	
	.PARAMETER Thumbprint
		Thumbprint of the specific certificate to modify.
	
	.PARAMETER SubjectName
		Subject name of the certificate to modify.
		If more than one certificate share the same subject, the one with the latest expiration will be modified.
	
	.PARAMETER FriendlyName
		FriendlyName of the certificate to modify.
		If more than one certificate share the same friendly name, the one with the latest expiration will be modified.

	.PARAMETER KeyUsage
		Only certificates that include all required usages are considered.
		E.g.: 'Client Authentication' or 'Server Authentication'
		Used in combination with filtering by subject name or friendly name.

	.PARAMETER Issuer
		Only certificates by the specified CA will be considered.
		Used in combination with filtering by subject name or friendly name.
	
	.PARAMETER Scope
		Whether to look for the certificate in the System store or the current user's store.
		Defaults to the system store.
	
	.PARAMETER Identity
		Identity of the account to grant permissions to.
		Accepts either SID or NT Account notation.
	
	.PARAMETER Right
		What rights to grant.
		Defaults to "Read"
	
	.EXAMPLE
		PS C:\> Add-PrivateKeyRights -SubjectName 'CN=TeamsTest' -Identity 'S-1-5-20'

		Selects the latest certificate with the subject "CN=TeamsTest" and grants read access to the local network service.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ThumbPrint')]
		[string]
		$Thumbprint,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Subject')]
		[string]
		$SubjectName,

		[Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'FriendlyName')]
		[string]
		$FriendlyName,

		[Parameter(ParameterSetName = 'Subject')]
		[Parameter(ParameterSetName = 'FriendlyName')]
		[string[]]
		$KeyUsage,

		[Parameter(ParameterSetName = 'Subject')]
		[Parameter(ParameterSetName = 'FriendlyName')]
		$Issuer,

		[ValidateSet('System', 'User')]
		[string]
		$Scope = 'System',

		[Parameter(Mandatory = $true)]
		[string]
		$Identity,

		[System.Security.AccessControl.FileSystemRights]
		$Right = [System.Security.AccessControl.FileSystemRights]::Read
	)

	begin {
		#region Functions
		function Resolve-Certificate {
			[OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
			[CmdletBinding()]
			param (
				[AllowEmptyString()]
				[string]
				$Thumbprint,

				[AllowEmptyString()]
				[string]
				$SubjectName,

				[AllowEmptyString()]
				[string]
				$FriendlyName,

				[ValidateSet('System', 'User')]
				[string]
				$Scope,

				[string[]]
				$KeyUsage,

				[string]
				$Issuer
			)

			$rootPath = switch ($Scope) {
				'User' { 'Cert:\CurrentUser\My' }
				default { 'Cert:\LocalMachine\My' }
			}

			if ($Thumbprint) {
				try { Get-Item -Path "$rootPath\$Thumbprint" -ErrorAction Stop }
				catch { throw "Certificate not found! $Thumbprint" }
				return
			}

			if ($SubjectName) {
				$cert = Get-ChildItem -Path $rootPath | Where-Object {
					if ($_.Subject -ne $SubjectName) { return $false }
					if ($Issuer -and $_.Issuer -eq $Issuer) { return $false }
					if ($KeyUsage) {
						foreach ($usage in $KeyUsage) {
							if ($usage -notin $_.EnhancedKeyUsageList.FriendlyName) { return $false }
						}
					}

					$true
				} | Sort-Object NotAfter -Descending | Select-Object -First 1
				if (-not $cert) { throw "Certificate not found! $SubjectName" }
				return $cert
			}

			if ($FriendlyName) {
				$cert = Get-ChildItem -Path $rootPath | Where-Object {
					if ($_.FriendlyName -EQ $FriendlyName) { return $false }
					if ($Issuer -and $_.Issuer -eq $Issuer) { return $false }
					if ($KeyUsage) {
						foreach ($usage in $KeyUsage) {
							if ($usage -notin $_.EnhancedKeyUsageList.FriendlyName) { return $false }
						}
					}

					$true
				} | Sort-Object NotAfter -Descending | Select-Object -First 1
				if (-not $cert) { throw "Certificate not found! $FriendlyName" }
				return $cert
			}

			throw "Neither Thumbprint, Subject nor FriendlyName were specified, unable to resolve certificate!"
		}
		
		function Resolve-Identity {
			[OutputType([System.Security.Principal.SecurityIdentifier])]
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[string]
				$Name
			)

			$sid = $Name -as [System.Security.Principal.SecurityIdentifier]
			if ($sid) { return $sid }

			$ntAccount = [System.Security.Principal.NTAccount]$Name
			try { $ntAccount.Translate([System.Security.Principal.SecurityIdentifier]) }
			catch { throw "Unable to resolve Identity $Name" }
		}
		
		function Add-CertAccessRule {
			[CmdletBinding()]
			param (
				[Parameter(Mandatory = $true)]
				[System.Security.Cryptography.X509Certificates.X509Certificate2]
				$Certificate,

				[Parameter(Mandatory = $true)]
				[System.Security.Principal.IdentityReference]
				$Identity,

				[Parameter(Mandatory = $true)]
				[System.Security.AccessControl.FileSystemRights]
				$Right,

				[ValidateSet('System', 'User')]
				[string]
				$Scope = 'System'
			)
			process {
				try { $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) }
				catch { throw "Failed to access private key of $($Certificate.Thumbprint) (Has Private Key: $($Certificate.HasPrivateKey)): $_" }

				$rootPath = switch ($Scope) {
					'User' { "$env:USERPROFILE\AppData\Roaming\Microsoft\Crypto\Keys" }
					default { "$env:ALLUSERSPROFILE\Microsoft\Crypto\Keys" }
				}

				$keyPath = Join-Path -Path $rootPath -ChildPath $privateKey.Key.UniqueName
				if (-not (Test-Path -path $keyPath)) {
					$keyRoot = Split-Path $rootPath
					$keyPath = Get-ChildItem -Path $keyRoot -Recurse | Where-Object Name -EQ $privateKey.Key.UniqueName | Select-Object -First 1 -ExpandProperty FullName
				}

				try { $acl = Get-Acl -Path $keyPath -ErrorAction Stop }
				catch { throw "Failed to access key permissions of $($Certificate.Thumbprint): $_" }

				$accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
					$Identity,
					$Right,
					'Allow'
				)
				$acl.AddAccessRule($accessRule)

				try { $acl | Set-Acl -Path $keyPath -ErrorAction Stop }
				catch { throw "Failed to write key permissions of $($Certificate.Thumbprint): $_" }
			}
		}
		#endregion Functions
	}
	process {
		trap {
			Write-Error $_
			return
		}

		$cert = Resolve-Certificate -Thumbprint $Thumbprint -SubjectName $SubjectName -FriendlyName $FriendlyName -Scope $Scope -KeyUsage $KeyUsage -Issuer $Issuer
		$identityObject = Resolve-Identity -Name $Identity
		Add-CertAccessRule -Certificate $cert -Identity $identityObject -Right $Right
	}
}