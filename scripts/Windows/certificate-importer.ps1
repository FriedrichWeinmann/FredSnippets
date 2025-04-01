<#
.SYNOPSIS
	Schedules a certificate import on next boot.

.DESCRIPTION
	Schedules a certificate import on next boot.
	This is intended as part of a final preparation for SYSPREP.
	Once the sysprepped machine boots again, it will then import the certificate specified.

	By default, "sysprep /generalize" will destroy any certificates in the machine store, by disassociating private key from public key.
	This script allows preparing a certificate for reimport during the next boot.

	The scheduled task created this way will remove itself after completing its task.

	In order for this script to work successfully, it requires a password-protected PFX file and a txt file containing the password.
	Both files must be placed in the same folder and share the same name, except for the file extension.
	E.g.:
	C:\contoso\ipsec-cert.pfx
	C:\contoso\ipsec-cert.txt

.PARAMETER Path
	Path to the folder in which the certificate is placed.

.PARAMETER Name
	Name of both certificate & password file (without the extension).

.PARAMETER Delete
	Whether to delete certificate & password file after importing.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]
    $Path,

    [Parameter(Mandatory = $true)]
    [string]
    $Name,

    [switch]
    $Delete
)

$taskName = "CERTIMPORT-$(Get-Random)"

$code = {
    $name = '%NAME%'
    $path = '%PATH%'
    $delete = $%DELETE%
    $taskName = '%TASK%'

    $certPath = Join-Path -Path $path -ChildPath "$name.pfx"
    $passwordPath = Join-Path -Path $path -ChildPath "$name.txt"

    Import-PfxCertificate -FilePath $certPath -Password (Get-Content -Path $PasswordPath | ConvertTo-SecureString -AsPlainText -Force) -CertStoreLocation Cert:\LocalMachine\My
    Unregister-ScheduledTask -TaskName $taskName -ErrorAction Ignore -Confirm:$false -TaskPath '\'

    if ($delete) {
        Remove-Item -Path $certPath
        Remove-Item -Path $passwordPath
    }
}.ToString() -replace '%NAME%', ($Name -replace "'", "_") -replace '%Path%', ($Path -replace "'", "_") -replace '%DELETE%', "$Delete" -replace '%TASK%', $taskName

$bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
$encodedCommand = [Convert]::ToBase64String($bytes)
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-ExecutionPolicy ByPass -EncodedCommand $encodedCommand"
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description 'Imports a certificate into the machine store'
$task | Register-ScheduledTask -TaskName $taskName -Force