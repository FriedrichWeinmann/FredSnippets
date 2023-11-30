function Update-UserGroupMembership {
	<#
	.SYNOPSIS
		Refresh the group memberships of a user without requiring logout and logon.
	
	.DESCRIPTION
		Refresh the group memberships of a user without requiring logout and logon.
	
	.PARAMETER ComputerName
		The name of the computer the user is logged onto.
	
	.PARAMETER Credential
		Credentials to use for the operation.
		The target computer requires local admin rights.
	
	.PARAMETER UserName
		The NT Account name of the user for which to refresh the group memberships.
		E.g.: contoso\MMustermann
	
	.EXAMPLE
		PS C:\> Update-UserGroupMembership -ComputerName JeaAdminHost -UserName 'contoso\Administrator'

		Refreshes the group memberships of the "Administrator" user on the computer JeaAdminHost
	
	.EXAMPLE
		PS C:\> Update-UserGroupMembership -ComputerName JeaAdminHost -UserName SYSTEM

		Refreshes the group memberships of the SYSTEM account (= Computer Account) on the computer JeaAdminHost
	#>
	[CmdletBinding()]
	param (
		[string]
		$ComputerName,

		[PSCredential]
		$Credential,

		[string]
		$UserName
	)

	# Schritt 1: Aufgabe Erstellen
	# Aktion, Principal, Name
	$action = New-ScheduledTaskAction -Execute klist -Argument purge
	$principal = New-ScheduledTaskPrincipal -UserId $UserName -LogonType Interactive
	$task = New-ScheduledTask -Action $action -Principal $principal
	$name = "GroupMembershipUpdate-$(Get-Random)"
	$param = @{
		CimSession = $ComputerName
		TaskName = $name
	}
	if ($Credential) { $param.Credential = $Credential }
	try { $null = $task | Register-ScheduledTask @param -ErrorAction Stop }
	catch {
		Write-Warning "Failed to update user groupmembership: $_"
		throw
	}

	# Schritt 2: Aufgabe Starten
	Start-ScheduledTask @param
	Start-Sleep -Seconds 3

	# Schritt 3: Aufgabe Löschen
	Unregister-ScheduledTask @param -Confirm:$false
}