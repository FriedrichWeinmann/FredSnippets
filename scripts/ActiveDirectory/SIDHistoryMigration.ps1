<#
.SYNOPSIS
	Migration Script that will transfer SIDs to SIDHistory.

.DESCRIPTION
	Migration Script that will transfer SIDs to SIDHistory.
	This script will take all principals from a source OU root and migrate them to the destination domain.
	It will assume there is a destination target with the same SamAccountName as in the source.

	Either run as Domain Admin from the destination domain or provide destination  credentials.
	This script requires PowerShell remoting to the destination server.

	If you provide only the domain names for the server parameters, it will use the PDC Emulators for specific server targeting.

	In order for this script to work, some prerequisites must be met:

	- The credentials used for both sides must be direct members of the Domain Admins group. No "Equivalent permissions" or anything like that.
	- There must be a trust between the domains, at least the source domain must trust the destination domain.
	- The principal being migrated must be of the same type (user to user, domain-local group to domain-local group, ...)
	- The DCs in both domains must have "Account Management" auditing enabled
	- The source domain must have a group named "<sourcedomain NetBIOSName>$$$". E.g.: "CONTOSO$$$"
	- The destination Domain must be able to reach the source domain.

.PARAMETER SourceOU
	The path under which we search for principals to SID-migrate.

.PARAMETER SourceServer
	The domain / dc to migrate from.
	Resolves to the PDC Emulator if only the domain DNS name is specified.

.PARAMETER SourceCredential
	The credentials to use for the migration.
	Must be a direct member of the Domain Admins group.

.PARAMETER DestinationServer
	The domain / dc to migrate to.
	Resolves to the PDC Emulator if only the domain DNS name is specified.

.PARAMETER DestinationCredential
	The credentials to use for the migration.
	Must be a direct member of the Domain Admins group.
	If not specified, the account running the script must be a direct member of the Domain Admins group on the destination domain.

.PARAMETER Filter
	The LDAP filter used to select principals to migrate.
	By default, all principals with a SID will be migrated, but could be constrained to only select groups or users or based on name patterns.

.PARAMETER LogPath
	Where to log the entire execution of the script.
	Defaults to a timestamped CSV file in the same path as the script.

.EXAMPLE
	PS C:\> .\SIDHistoryMigration.ps1 -SourceOU 'OU=Users,OU=Company,DC=fabrikam,DC=org' -SourceServer fabrikam.org -SourceCredential $sourceCred -DestinationServer contoso.com -DestinationCredential $destCred

	Migrates the SID History of all principals under OU=Users,OU=Company,DC=fabrikam,DC=org from fabrikam.org to contoso.com.
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string]
	$SourceOU,

	[Parameter(Mandatory = $true)]
	[string]
	$SourceServer,

	[Parameter(Mandatory = $true)]
	[PSCredential]
	$SourceCredential,

	[Parameter(Mandatory = $true)]
	[string]
	$DestinationServer,

	[PSCredential]
	$DestinationCredential,

	[string]
	$Filter = '(objectSID=*)',

	[string]
	$LogPath = "$PSScriptRoot\SID-History-$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').csv"
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Log -Status Error -Message "Script Failed: $_"
	Stop-Log
	throw $_
}
Start-Log -Path $LogPath

#region Functions
function Start-Log {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Path
	)

	$parent = Split-Path -Path $Path
	if (-not (Test-Path $parent)) {
		throw "Path not found: $Path - ensure at least the folder exists"
	}

	$script:logging_command = { Export-Csv -Path $Path -Delimiter ";" }.GetSteppablePipeline()

	# $true = Expecting Pipeline Input
	$script:logging_command.Begin($true)
}
function Write-Log {
	[CmdletBinding()]
	param (
		[string]
		$Message,

		[ValidateSet('Info', 'Warning', 'Error', 'Debug')]
		[string]
		$Status,

		[string]
		$Source
	)

	if (-not $script:logging_command) { return }

	$data = [PSCustomObject]@{
		Timestamp = Get-Date
		Message   = $Message
		Status    = $Status
		Source    = $Source
	}

	$script:logging_command.Process($data)
}
function Stop-Log {
	[CmdletBinding()]
	param (
		
	)
	if (-not $script:logging_command) { return }

	$script:logging_command.End()
}

function Get-MigrationPrincipal {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Server,

		[PSCredential]
		$Credential,

		[Parameter(Mandatory = $true)]
		[string]
		$SearchBase,

		[Parameter(Mandatory = $true)]
		[string]
		$LdapFilter
	)

	$param = @{
		Server     = $Server
		SearchBase = $SearchBase
		LdapFilter = $LdapFilter
		Properties = 'SamAccountName'
	}
	if ($Credential) { $param.Credential = $Credential }

	Get-ADObject @param | ForEach-Object SamAccountName
}

function Import-ADPrincipalSID {
	<#
	.SYNOPSIS
		Copies the SID from a principal in one domain into the SID history of a principal in another.
	
	.DESCRIPTION
		Copies the SID from a principal in one domain into the SID history of a principal in another.

		In order for this to work, some prerequisites must be met:

		- The credentials used for both sides must be direct members of the Domain Admins group. No "Equivalent permissions" or anything like that.
		- There must be a trust between the domains, at least the source domain must trust the destination domain.
		- The principal being migrated must be of the same type (user to user, domain-local group to domain-local group, ...)
		- The DCs in both domains must have "Account Management" auditing enabled
		- The source domain must have a group named "<sourcedomain NetBIOSName>$$$". E.g.: "CONTOSO$$$"
		- The destination Domain must be able to reach the source domain.

		This tool uses PowerShell remoting to connect to the destination DC to execute its task (as it must be executed on a domain controller).
		This defaults to the PDC Emulator if a domain name is offered to the -Server parameter.
	
	.PARAMETER Server
		The destination domain (or a DC from it)
	
	.PARAMETER FromServer
		The source domain (or a DC from it)
	
	.PARAMETER FromCredential
		Credentials to use to connect to the source domain.
		Must be a direct Domain Admins member in the source domain.
	
	.PARAMETER Credential
		Credentials to use to connect to the destination domain.
		Must be a direct Domain Admins member in the destination domain.
		Uses the current account by default (which then must be a domain admin)
	
	.PARAMETER Identity
		Sam Account Name of the principal (user/group/...) in the destination domain.
	
	.PARAMETER OldIdentity
		Sam Account Name of the principal (user/group/...) in the source domain.
	
	.EXAMPLE
		PS C:\> Import-ADPrincipalSID -Server contoso.com -FromServer fabrikam.org -FromCredential $cred -Identity mm -OldIdentity mm
		
		Migrates the SID & SID History of the account "mm" from fabrikam.org to contoso.com

	.EXAMPLE
		PS C:\> Import-Csv .\users-to-migrate.csv | Import-ADPrincipalSID -Server contoso.com -FromServer fabrikam.org -FromCredential $cred

		Migrates all users in "users-to-migrate.csv" from fabrikam.org to contoso.com.
		The CSV must have two columns, "Identity" and "OldIdentity".

	.EXAMPLE
		PS C:\> Get-Content .\users-to-migrate.txt | Import-ADPrincipalSID -Server contoso.com -FromServer fabrikam.org -FromCredential $cred

		Migrates all users in "users-to-migrate.txt" from fabrikam.org to contoso.com.
		All users in the text file must have the same SAMAccountName in both domains.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Server,

		[Parameter(Mandatory = $true)]
		[string]
		$FromServer,

		[Parameter(Mandatory = $true)]
		[PSCredential]
		$FromCredential,

		[PSCredential]
		$Credential,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$Identity,

		[Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$OldIdentity
	)
	begin {
		#region Remote Scriptblocks
		$sourceCode = {

			#region Code
			$source = @'
using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace DSApi {
    public static class Native
    {
        [DllImport("Ntdsapi.dll", SetLastError = true)]
        public static extern int DsBind(
            string DomainControllerName,
            string DnsDomainName,
            out IntPtr Connection
        );

        [DllImport("Ntdsapi.dll", SetLastError = true)]
        public static extern int DsUnBind(
            IntPtr Connection
        );

        [DllImport("Ntdsapi.dll", SetLastError = true)]
        public static extern int DsBindWithCred(
            string DomainControllerName,
            string DnsDomainName,
            IntPtr AuthHandle,
            out IntPtr Connection
        );

        [DllImport("Ntdsapi.dll", SetLastError = true)]
        public static extern int DsMakePasswordCredentials(
            string User,
            string Domain,
            string Password,
            out IntPtr AuthHandle
        );

        [DllImport("Ntdsapi.dll", SetLastError = true)]
        public static extern int DsFreePasswordCredentials(
            IntPtr AuthHandle
        );

        [DllImport("Ntdsapi.dll", SetLastError = true)]
        public static extern int DsAddSidHistory(
            IntPtr SessionHandle,
            uint Flags,
            string SrcDomain,
            string SrcPrincipal,
            string SrcDomainController,
            IntPtr SrcCredentialHandle,
            string DstDomain,
            string DstPrincipal
        );
    }

    public class DSSession : IDisposable
    {
        public PSCredential Credential;

        private IntPtr _Session;
        private IntPtr _Credential;

        public void Authenticate()
        {
            if (null == Credential)
                throw new ArgumentException("No Credentials provided to authenticate with!");

            if (IntPtr.Zero != _Session)
                Native.DsUnBind(_Session);
            if (IntPtr.Zero != _Credential)
                Native.DsFreePasswordCredentials(_Credential);

            string user = Credential.UserName;
            string domain = Environment.GetEnvironmentVariable("UserDNSDomain");
            if (Regex.IsMatch(user, "^\\w+\\\\\\w+$"))
            {
                string[] parts = user.Split('\\');
                domain = parts[0];
                user = parts[1];
            }

            int result = Native.DsMakePasswordCredentials(user, domain, Credential.GetNetworkCredential().Password, out _Credential);
            if (result != 0)
                throw new Win32Exception(result);
        }

        public void Connect(string DnsDomainName, string DomainControllerName)
        {
            if (_Session != IntPtr.Zero)
                Native.DsUnBind(_Session);

            int result = Native.DsBindWithCred(DomainControllerName, DnsDomainName, _Credential, out _Session);
            if (result != 0)
                throw new Win32Exception(result);
        }

        public IntPtr GetSessionPointer()
        {
            return _Session;
        }

        public IntPtr GetCredentialPointer()
        {
            return _Credential;
        }

        public void Dispose()
        {
            if (IntPtr.Zero != _Session)
                Native.DsUnBind(_Session);
            if (IntPtr.Zero != _Credential)
                Native.DsFreePasswordCredentials(_Credential);
        }
    }

    public static class DirectoryTools
    {
        public static void ImportSIDHistory(DSSession SourceSession, DSSession DestinationSession, string SourceDomain, string SourceDC, string SourcePrincipal, string DestinationDomain, string DestinationPrincipal)
        {
            int result = Native.DsAddSidHistory(
                DestinationSession.GetSessionPointer(),
                0,
                SourceDomain,
                SourcePrincipal,
                SourceDC,
                SourceSession.GetCredentialPointer(),
                DestinationDomain,
                DestinationPrincipal
            );
            if (result != 0)
                throw new Win32Exception(result);
        }
    }
}
'@
			Add-Type -TypeDefinition $source
			#endregion Code
		}
		$code = {
			param (
				$FromDomain,
				$FromServer,
				$ToDomain,
				$FromIdentity,
				$ToIdentity
			)
        
			$result = [PSCustomObject]@{
				FromDomain   = $FromDomain
				ToDomain     = $ToDomain
				FromIdentity = $FromIdentity
				ToIdentity   = $ToIdentity
				Success      = $true
				Message      = ''
				Error        = $null
			}
			try {
				$srcSession = [DSApi.DSSession]::new()
				$srcSession.Credential = $fromCred
				$srcSession.Authenticate()
			}
			catch {
				$result.Success = $false
				$result.Error = $_
				$result.Message = 'Error connecting to source domain. Ensure the credentials provided are valid and the domain can be reached!'
				$result
				return
			}

			$dstSession = [DSApi.DSSession]::new()
			$dstSession.Connect($ToDomain, "")
			try { [DSApi.DirectoryTools]::ImportSIDHistory($srcSession, $dstSession, $FromDomain, $FromServer, $FromIdentity, $ToDomain, $ToIdentity) }
			catch {
				$result.Success = $false
				$result.Error = $_
				$result.Message = 'Failed to perform SID History import. Ensure both accounts are direct members in the domain admins, both identities are of the same type, both domains have "Account Management" auditing enabled for their domain controllers and the source domain has a group named <NetBIOSDomainName>$$$ (e.g.: "CONTOSO$$$").'
			}
			$srcSession.Dispose()
			$dstSession.Dispose()
			$result
		}
		#endregion Remote Scriptblocks

		#region Resolve Domains, Servers and perform prep
		# Target Domain & Server
		$param = @{ Server = $Server }
		if ($Credential) { $param.Credential = $Credential }

		$domain = Get-ADDomain @param
		if ($domain.DnsRoot -eq $Server) { $Server = $domain.PdcEmulator }

		# Source Domain & Server
		$oldParam = @{ Server = $FromServer }
		if ($FromCredential) { $oldParam.Credential = $FromCredential }
		$oldDomain = Get-ADDomain @oldParam
		$oldServer = $FromServer
		if ($FromServer -in $oldDomain.DnsRoot, $oldDomain.NetBIOSDomainName) { $oldServer = $oldDomain.PDCEmulator }

		# PSRemoting Session
		$remoteParam = @{ ComputerName = $Server }
		if ($Credential) { $remoteParam.Credential = $Credential }
		try { $pssession = New-PSSession @remoteParam -ErrorAction Stop }
		catch {
			Write-Warning "Failed to connect to destination domain controller $Server : $_"
			throw
		}
		Invoke-Command -Session $pssession -ScriptBlock $sourceCode

		Invoke-Command -Session $pssession -ScriptBlock { $script:fromCred = $using:FromCredential }
		#endregion Resolve Domains, Servers and perform prep
	}
	process {
		Invoke-Command -Session $pssession -ScriptBlock $code -ArgumentList @(
			$oldDomain.DnsRoot
			$oldServer
			$domain.DnsRoot
			$OldIdentity
			$Identity
		)
	}
	end {
		Remove-PSSession -Session $pssession
	}
}

function Write-MigrationPrincipalLog {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		$InputObject
	)
	process {
		$param = @{
			Status = 'Info'
			Message = 'Successfully migrated {0} from {1} to {2}.' -f $InputObject.FromIdentity, $InputObject.FromDomain, $InputObject.ToDomain
		}
		if (-not $InputObject.Success) {
			$param = @{
				Status = 'Warning'
				Message = 'Failed to migrate {0} from {1} to {2}: {3} | {4}' -f $InputObject.FromIdentity, $InputObject.FromDomain, $InputObject.ToDomain, $InputObject.Message, $InputObject.Error
			}
		}

		Write-Log @param
	}
}
#endregion Functions

Get-MigrationPrincipal -Server $SourceServer -Credential $SourceCredential -SearchBase $SourceOU -LdapFilter $Filter |
	Import-ADPrincipalSID -Server $DestinationServer -Credential $DestinationCredential -FromServer $SourceServer -FromCredential $SourceCredential |
		Write-MigrationPrincipalLog

Stop-Log