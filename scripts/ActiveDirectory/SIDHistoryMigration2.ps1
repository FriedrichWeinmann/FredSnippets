#requires -Modules ActiveDirectory
<#
.SYNOPSIS
	Migration Script that will transfer SIDs to SIDHistory.

.DESCRIPTION
	Migration Script that will transfer SIDs to SIDHistory.
	This script will take a single specified principal and migrate them to the destination domain.

	If you provide only the domain names for the server parameters, it will use the PDC Emulators for specific server targeting.

	In order for this script to work, some prerequisites must be met:

	- The credentials used for both sides must be direct members of the Domain Admins group. No "Equivalent permissions" or anything like that.
	- There must be a trust between the domains, at least the source domain must trust the destination domain.
	- The principal being migrated must be of the same type (user to user, domain-local group to domain-local group, ...)
	- The DCs in both domains must have "Account Management" auditing enabled
	- The source domain must have a group named "<sourcedomain NetBIOSName>$$$". E.g.: "CONTOSO$$$"
	- The destination Domain must be able to reach the source domain.

.PARAMETER From
	The source domain/dc to migrate from.

.PARAMETER FromCredential
	The credentials to use to connect to the source domain.

.PARAMETER To
	The destination domain/dc to migrate to.

.PARAMETER ToCredential
	The credentials to use to connect to the destination domain.

.PARAMETER FromIdentity
	SamAccountName of the AD object to migrate the SID from.

.PARAMETER ToIdentity
	SamAccountName of the target AD object that should take in the SID as SIDHistory entry.

.EXAMPLE
	PS C:\> .\SIDHistoryMigration2.ps1 -From fabrikam.org -FromCredential $credFrom -To contoso.com -ToCredential $credTo -FromIdentity max -ToIdentity max

	Migrates the SID History of max from fabrikam.org to contoso.com.
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $true)]
	[string]
	$From,
	
	[Parameter(Mandatory = $true)]
	[PSCredential]
	$FromCredential,
	
	[Parameter(Mandatory = $true)]
	[string]
	$To,
	
	[Parameter(Mandatory = $true)]
	[PSCredential]
	$ToCredential,
	
	[Parameter(Mandatory = $true)]
	[string]
	$FromIdentity,
	
	[Parameter(Mandatory = $true)]
	[string]
	$ToIdentity
)

$ErrorActionPreference = 'Stop'
trap {
	Write-Warning "Script failed: $_"
	throw $_
}

#region Source Code
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
		public string Domain;
		public string Server;

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
			
			Domain = DnsDomainName;
			Server = DomainControllerName;
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
        public static void ImportSIDHistory(DSSession SourceSession, DSSession DestinationSession, string SourcePrincipal, string DestinationPrincipal)
        {
            int result = Native.DsAddSidHistory(
                DestinationSession.GetSessionPointer(),
                0,
                SourceSession.Domain,
                SourcePrincipal,
                SourceSession.Server,
                SourceSession.GetCredentialPointer(),
                DestinationSession.Domain,
                DestinationPrincipal
            );
            if (result != 0)
                throw new Win32Exception(result);
        }
    }
}
'@
try { Add-Type -TypeDefinition $source }
catch { }
#endregion Source Code

#region Functions
function New-DSSession {
	[OutputType([DSApi.DSSession])]
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Server,
		
		[Parameter(Mandatory = $true)]
		[PSCredential]
		$Credential
	)

	$domain = Get-ADDomain -Server $Server -Credential $Credential -ErrorAction Stop
	if ($Server -in $domain.ReplicaDirectoryServers) { $dc = $Server }
	else { $dc = $domain.PdcEmulator }

	$session = [DSApi.DSSession]::new()
	$session.Credential = $Credential
	$session.Connect($domain.DnsRoot, $dc)
	$session
}

function Copy-SidHistory {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[DSApi.DSSession]
		$From,

		[Parameter(Mandatory = $true)]
		[DSApi.DSSession]
		$To,

		[Parameter(Mandatory = $true)]
		[string]
		$FromIdentity,

		[AllowEmptyString()]
		[string]
		$ToIdentity
	)
	if (-not $ToIdentity) { $ToIdentity = $FromIdentity }

	try {
		[DSApi.DirectoryTools]::ImportSIDHistory($From, $To, $FromIdentity, $ToIdentity)
	}
	catch {
		Write-Warning "$_"
		throw "Failed to perform SID History import. Ensure both accounts have sufficient rights, both identities are of the same type, both domains have `"Account Management`" auditing enabled for their domain controllers and the source domain has a group named <NetBIOSDomainName>`$`$`$ (e.g.: `"CONTOSO`$`$`$`"). $_"
	}
}
#endregion Functions

$fromSession = New-DSSession -Server $From -Credential $FromCredential
$toSession = New-DSSession -Server $To -Credential $ToCredential
Copy-SidHistory -From $fromSession -To $toSession -FromIdentity $FromIdentity -ToIdentity $ToIdentity
