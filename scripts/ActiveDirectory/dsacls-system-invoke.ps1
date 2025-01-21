<#
.SYNOPSIS
	Assigns rights to the Deleted Objects container.

.DESCRIPTION
	Assigns rights to the Deleted Objects container.
	Actual rights assignment happens via PSRemoting on a target DC (the PDCEmulator by default) as SYSTEM account.
	In order to act as SYSTEM account, a temporary scheduled task will be created, executed and deleted.

.PARAMETER Server
	The domain or server to execute against.
	If no specific server was picked, it will instead automatically choose the PDC Emulator.

.PARAMETER Credential
	The credentials to use for the PS Remoting.
	By default, it will use the current user with Windows Authentication.

.PARAMETER Rights
	The rights to apply.
	Each right specified must be a hashtable with the following keys:
	- Identity: SamAccountName of the principal to assign rights to. Usually a group name.
	- Type: Local or Builtin.
	  - Local: The Identity is assumed to be a regular entity in the target domain.
	  - Builtin: The Identity is a builtin principal, such as the "Administrators" group.
	- Rights: The actual rights to grant. Same properties as exist on the [System.DirectoryServices.ActiveDirectoryRights] enumeration.

.PARAMETER LocalLogPath
	Path local to the domain controller executed against that should be used for temporary logging.
	Specify the full path to the file, not only to a folder!
	If specified, this script will return a result object for each server/domain specified, detailing the success of each action.
	If the logfile could not be written or read, the return result will report a failure.

.EXAMPLE
	PS C:\> .\dsacls-system-invoke.ps1 -Server contoso.com -Rights @{Identity='Domain Admins'; Type = 'Local'; Rights = 'GenericAll' }

	Grants the domain admins in the domain contoso.com full control over the Deleted Objects container.

.EXAMPLE
	PS C:\> .\dsacls-system-invoke.ps1 -Server contoso.com -Credential $cred -Rights $rights -LocalLogPath c:\temp\dsacls.log

	Grants the rights defined in $rights to the Deleted Objects container in contoso.com.
	It uses the credentials provided for the connection and will try to report the result, not leaving a file on the DC selected.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string[]]
    $Server,

    [pscredential]
    $Credential,

    [hashtable[]]
    $Rights = @(
        @{ Identity = 'Administrators'; Type = 'Builtin'; Rights = 'ReadControl', 'ReadProperty', 'GenericExecute' },
        @{ Identity = 'Necromancers'; Type = 'Local'; Rights = 'CreateChild', 'ListChildren', 'ReadProperty', 'WriteProperty' }
    ),

    [string]
    $LocalLogPath
)

$ErrorActionPreference = 'Stop'
trap {
    Write-Warning "Script failed: $_"
    throw $_
}

#region Remote Code
$code = {
    param ($Data)
    <#
	Data <Hashtable>:
	- Path <string>: DN To Object to modify
	- Permissions <object[]>: Permissions to apply (objects as returned by Resolve-ADPermission)
    - LocalLogPath <string>: Path where logs should be written (if any)
	#>

    #region Functions
    function Invoke-SystemCommand {
        <#
		.SYNOPSIS
			Execute a scriptblock as SYSTEM by setting up a temporary scheduled task.

		.DESCRIPTION
			Execute a scriptblock as SYSTEM by setting up a temporary scheduled task.

		.PARAMETER Name
			The name of the task

		.PARAMETER Scriptblock
			The code to run

		.PARAMETER Mode
			Whether to run it right away (instant) or after the next reboot (OnBoot).
			Default: Instant

		.PARAMETER Wait
			Wait for the task to complete.
			Only applicable in "Instant" mode.

		.PARAMETER Timeout
			Timeout how long we are willing to wait for the task to complete.
			Only applicable in combination with "-Wait"

		.EXAMPLE
			PS C:\> Invoke-SystemCommand -Name 'WhoAmI' -ScriptBlock { whoami | Set-Content C:\temp\whoami.txt }

			Executes the scriptblock as system
		#>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory = $true)]
            [ValidateScript({
                    if ($_ -notmatch "'") { return $true }
                    throw "Name may not contain a single-quote in it. Value: $Name"
                })]
            [string]
            $Name,

            [Parameter(Mandatory = $true)]
            [string]
            $Scriptblock,

            [ValidateSet('Instant', 'OnBoot')]
            [string]
            $Mode = 'Instant',

            [switch]
            $Wait,

            [timespan]
            $Timeout = '00:00:30',

            [string]
            $ComputerName
        )

        begin {
            $param = @{ }
            if ($ComputerName) { $param = @{ CimSession = $ComputerName } }
        }
        process {
            if ($Mode -eq 'OnBoot') { $Scriptblock = "Unregister-ScheduledTask -TaskName 'PowerShell_System_$Name' -Confirm:`$false", $Scriptblock -join "`n`n" }
            $bytes = [System.Text.Encoding]::Unicode.GetBytes($Scriptblock)
            $encodedCommand = [Convert]::ToBase64String($bytes)

            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -EncodedCommand $encodedCommand"
            $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest -LogonType Password
            switch ($Mode) {
                'Instant' { $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) }
                'OnBoot' { $trigger = New-ScheduledTaskTrigger -AtStartup }
            }
            $task = Register-ScheduledTask @param -TaskName "PowerShell_System_$Name" -Description "PowerShell Task - $Name" -Action $action -Trigger $trigger -Principal $principal
            if ($Mode -eq 'Instant') {
                $task | Start-ScheduledTask @param
                if (-not $Wait) {
                    Start-Sleep -Seconds 1
                }
                else {
                    $limit = (Get-Date).Add($Timeout)
                    while (($task | Get-ScheduledTask @param).State -ne "Ready") {
                        if ($limit -lt (Get-Date)) {
                            $task | Unregister-ScheduledTask @param -Confirm:$false
                            throw "Task execution exceeded time limit ($Timeout)"
                        }
                        Start-Sleep -Milliseconds 250
                    }
                }
                $task | Unregister-ScheduledTask @param -Confirm:$false
            }
        }
    }
    #endregion Functions

    $systemCode = { dsacls '%path%' /g '%grant%' }.ToString()
    if ($Data.LocalLogPath) {
        $systemCode = {
            '----------------------------------------------------' >> '%logpath%'
            'Updating %path%: %grant%' + " | $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'))" >> '%logpath%'
            ' ' >> '%logpath%'
            dsacls '%path%' /g '%grant%' >> '%logpath%'
            ' ' >> '%logpath%'
            "Exitcode: $LASTEXITCODE" >> '%logpath%'
            '====================================================' >> '%logpath%'
        }.ToString() -replace '%logpath%', ($Data.LocalLogPath -replace "'", "''")
    }

    foreach ($permission in $Data.Permissions) {
        $effectiveCode = $systemCode -replace '%path%', ($Data.Path -replace "'", "''") -replace '%grant%', ($permission.DsAclsParameter -replace "'", "''")
        Invoke-SystemCommand -Name "dsacls-$(Get-Random)" -Wait -Scriptblock ([Scriptblock]::Create($effectiveCode))
    }

    if (-not $Data.LocalLogPath) { return }

    try { $result = Get-Content -Path $Data.LocalLogPath -ErrorAction Stop }
    catch {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Success      = $false
            Error        = 'Logfile not found'
            SuccessCount = -1
            ErrorCount   = -1
            Log          = $null
        }
        return
    }

    Remove-Item -Path $Data.LocalLogPath -Force -ErrorAction Ignore

    $exitcodes = $result | Where-Object { $_ -match '^Exitcode:' }
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        Success      = @($exitcodes).Where{ $_ -ne 'Exitcode: 0' }.Count -eq 0
        Error        = ''
        SuccessCount = @($exitcodes).Where{ $_ -eq 'Exitcode: 0' }.Count
        ErrorCount   = @($exitcodes).Where{ $_ -ne 'Exitcode: 0' }.Count
        Log          = $result -join "`n"
    }
}
#endregion Remote Code

#region Functions
function Resolve-ADTarget {
    [CmdletBinding()]
    param (
        [string]
        $Server,

        [PSCredential]
        $Credential
    )

    $param = @{ Server = $Server }
    if ($Credential) { $param.Credential = $Credential }

    $domain = Get-ADDomain @param
    $targetServer = $domain.PDCEmulator
    if ($Server -in $domain.ReplicaDirectoryServers) {
        $targetServer = $Server
    }

    [PSCustomObject]@{
        Domain      = $domain
        Server      = $targetServer
        Credential  = $Credential
        NetBIOSName = $domain.NetBIOSName
    }
}

function Resolve-ADPermission {
    [CmdletBinding()]
    param (
        $Target,

        [hashtable]
        $Right
    )

    $name = '{0}\{1}' -f $Target.NetBIOSName, $Right.Identity
    if ($Right.Type -eq 'Builtin') { $name = "builtin\$($Right.Identity)" }

    $dsaclsRights = foreach ($permission in $Right.Rights) {
        switch ($permission) {
            GenericRead { 'GR' }
            GenericExecute { 'GE' }
            GenericWrite { 'GW' }
            GenericAll { 'GA' }
            Delete { 'SD' }
            DeleteChild { 'DC' }
            DeleteTree { 'DT' }
            ReadControl { 'RC' }
            WriteDACL { 'WD' }
            WriteOwner { 'WO' }
            ListChildren { 'LC' }
            CreateChild { 'CC' }
            ReadProperty { 'RP' }
            WriteProperty { 'WP' }
            AccessSystemSecurity { 'CA' }
            default { throw "Unsupported right: $permission!" }
        }
    }

    [PSCustomObject]@{
        Name            = $name
        Rights          = $Right.Rights
        DsAclsRight     = $dsaclsRights -join ''
        DsAclsParameter = '{0}:{1}' -f $name, ($dsaclsRights -join '')
    }
}

function Update-DeletedObjectsPermission {
    [CmdletBinding()]
    param (
        $Target,

        [scriptblock]
        $Code,

        $Permissions,

        [AllowEmptyString()]
        [string]
        $LocalLogPath
    )

    $param = @{
        ComputerName = $Target.Server
        ScriptBlock  = $Code
    }
    if ($Target.Credential) { $param.Credential = $Target.Credential }

    $data = @{
        Path         = $Target.Domain.DeletedObjectsContainer
        Permissions  = $Permissions
        LocalLogPath = $LocalLogPath
    }

    Invoke-Command @param -ArgumentList $data
}
#endregion Functions

foreach ($targetServer in $Server) {
    $targetData = Resolve-ADTarget -Server $targetServer -Credential $Credential
    $permissions = foreach ($right in $Rights) {
        Resolve-ADPermission -Target $targetData -Right $right
    }
    Update-DeletedObjectsPermission -Target $targetData -Code $code -Permissions $permissions -LocalLogPath $LocalLogPath
}