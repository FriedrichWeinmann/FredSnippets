function Set-LdapObject {
	<#
	.SYNOPSIS
		Modifies attributes on an LDAP object.

	.DESCRIPTION
		Binds to an LDAP object and applies requested replace, add, remove, and clear operations through System.DirectoryServices.DirectoryEntry.
		All queued changes are committed together by calling SetInfo.

	.PARAMETER Identity
		The LDAP path or distinguished name of the object to modify.

	.PARAMETER Replace
		A hashtable whose keys are LDAP attribute names and whose values replace the current attribute values.
		A null value clears the attribute.

	.PARAMETER Add
		A hashtable whose values are appended to the named multivalued LDAP attributes.

	.PARAMETER Remove
		A hashtable whose values are removed from the named multivalued LDAP attributes.

	.PARAMETER Clear
		One or more LDAP attribute names whose values are cleared.

	.PARAMETER Server
		The domain controller or LDAP server to which the function binds.

	.PARAMETER Credential
		The credential used for the LDAP bind. The current session credentials are used when this parameter is omitted.

	.EXAMPLE
		PS C:\> Set-LdapObject -Identity 'CN=Alice,OU=Users,DC=contoso,DC=com' -Replace @{ 'msDS-SupportedEncryptionTypes' = 24 } -Server dc01.contoso.com

		Sets the user's supported Kerberos encryption type value to 24 through the specified domain controller.

	.EXAMPLE
		PS C:\> Set-LdapObject -Identity $userDn -Add @{ proxyAddresses = 'smtp:alias@contoso.com' } -Remove @{ memberOf = $groupDn } -Clear description

		Appends a proxy address, removes a group value, and clears the description attribute in one commit.
	#>
	[CmdletBinding(SupportsShouldProcess = $true)]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Identity,

		[Parameter()]
		[hashtable]
		$Replace,

		[Parameter()]
		[hashtable]
		$Add,

		[Parameter()]
		[hashtable]
		$Remove,

		[Parameter()]
		[string[]]
		$Clear,
		
		[string]
		$Server,
		
		[PSCredential]
		$Credential
	)

	begin {
		#region Function
		function New-DirectoryEntry {
			<#
        .SYNOPSIS
            Generates a new directoryy entry object.
        
        .DESCRIPTION
            Generates a new directoryy entry object.
        
        .PARAMETER Path
            The LDAP path to bind to.
        
        .PARAMETER Server
            The server to connect to.
        
        .PARAMETER Credential
            The credentials to use for the connection.
        
        .EXAMPLE
            PS C:\> New-DirectoryEntry

            Creates a directory entry in the default context.

        .EXAMPLE
            PS C:\> New-DirectoryEntry -Server dc1.contoso.com -Credential $cred

            Creates a directory entry in the default context of the target server.
            The connection is established to just that server using the specified credentials.
    #>
			[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
			[CmdletBinding()]
			param (
				[string]
				$Path,
		
				[AllowEmptyString()]
				[string]
				$Server,
		
				[PSCredential]
				[AllowNull()]
				$Credential
			)
	
			if (-not $Path) { $resolvedPath = '' }
			elseif ($Path -like 'LDAP://*') { $resolvedPath = $Path }
			elseif ($Path -notlike '*=*') { $resolvedPath = 'LDAP://DC={0}' -f ($Path -split '\.' -join ',DC=') }
			else { $resolvedPath = "LDAP://$($Path)" }
	
			if ($Server -and ($resolvedPath -notlike "LDAP://$($Server)/*")) {
				$resolvedPath = ('LDAP://{0}/{1}' -f $Server, $resolvedPath.Replace('LDAP://', '')).Trim('/')
			}
	
			if (($null -eq $Credential) -or ($Credential -eq [PSCredential]::Empty)) {
				if ($resolvedPath) { New-Object System.DirectoryServices.DirectoryEntry($resolvedPath) }
				else {
					$entry = New-Object System.DirectoryServices.DirectoryEntry
					New-Object System.DirectoryServices.DirectoryEntry(('LDAP://{0}' -f $entry.distinguishedName[0]))
				}
			}
			else {
				if ($resolvedPath) { New-Object System.DirectoryServices.DirectoryEntry($resolvedPath, $Credential.UserName, $Credential.GetNetworkCredential().Password) }
				else { New-Object System.DirectoryServices.DirectoryEntry(('LDAP://DC={0}' -f ($env:USERDNSDOMAIN -split '\.' -join ',DC=')), $Credential.UserName, $Credential.GetNetworkCredential().Password) }
			}
		}
		#endregion Function
		
		$adsOp = @{
			Clear  = 1
			Update = 2
			Append = 3
			Delete = 4
		}
	}

	process {
		$param = @{}
		if ($Server) { $param.Server = $Server }
		if ($Credential) { $param.Credential = $Credential }

		try {
			$entry = New-DirectoryEntry @param -Path $Identity
			$null = $entry.NativeObject
		}
		catch {
			throw "Failed to acces LDAP object '$Identity': $_"
		}

		if (-not $PSCmdlet.ShouldProcess($Identity, 'Modify LDAP attributes')) { return }

		#region Replace
		foreach ($attribute in $Replace.Keys) {
			$value = $Replace[$attribute]

			if ($null -eq $value) {
				$entry.PutEx(
					$adsOp.Clear,
					$attribute,
					$null
				)
			}
			elseif ($value -is [array]) {
				$entry.PutEx(
					$adsOp.Update,
					$attribute,
					@($value)
				)
			}
			else {
				$entry.Put($attribute, $value)
			}
		}
		#endregion Replace

		#region Add
		foreach ($attribute in $Add.Keys) {
			$entry.PutEx(
				$adsOp.Append,
				$attribute,
				@($Add[$attribute])
			)
		}
		#endregion Add

		#region Remove
		foreach ($attribute in $Remove.Keys) {
			$entry.PutEx(
				$adsOp.Delete,
				$attribute,
				@($Remove[$attribute])
			)
		}
		#endregion Remove

		#region Clear
		foreach ($attribute in $Clear) {
			$entry.PutEx(
				$adsOp.Clear,
				$attribute,
				$null
			)
		}
		#endregion Clear

		try { $entry.SetInfo() }
		catch { throw "Error updating '$Identity': $_" }
	}
}
