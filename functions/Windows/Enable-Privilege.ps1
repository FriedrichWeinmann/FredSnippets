function Enable-Privilege {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[ValidateSet('SeAssignPrimaryTokenPrivilege','SeAuditPrivilege','SeBackupPrivilege','SeChangeNotifyPrivilege','SeCreateGlobalPrivilege','SeCreatePagefilePrivilege','SeCreatePermanentPrivilege','SeCreateSymbolicLinkPrivilege','SeCreateTokenPrivilege','SeDebugPrivilege','SeDelegateSessionUserImpersonatePrivilege','SeEnableDelegationPrivilege','SeImpersonatePrivilege','SeIncreaseBasePriorityPrivilege','SeIncreaseQuotaPrivilege','SeIncreaseWorkingSetPrivilege','SeLoadDriverPrivilege','SeLockMemoryPrivilege','SeMachineAccountPrivilege','SeManageVolumePrivilege','SeProfileSingleProcessPrivilege','SeRelabelPrivilege','SeRemoteShutdownPrivilege','SeRestorePrivilege','SeSecurityPrivilege','SeShutdownPrivilege','SeSyncAgentPrivilege','SeSystemEnvironmentPrivilege','SeSystemProfilePrivilege','SeSystemtimePrivilege','SeTakeOwnershipPrivilege','SeTcbPrivilege','SeTimeZonePrivilege','SeTrustedCredManAccessPrivilege','SeUndockPrivilege','SeUnsolicitedInputPrivilege')]
		[string]
		$Privilege
	)
	begin {
		#region Source Code
		$source = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TokPriv1Luid
{
	public int Count;
	public long Luid;
	public int Attr;
}

public static class Advapi32
{
	[DllImport("advapi32.dll", SetLastError=true)]
	public static extern bool OpenProcessToken(
		IntPtr ProcessHandle, 
		int DesiredAccess,
		ref IntPtr TokenHandle);
		
	[DllImport("advapi32.dll", SetLastError=true)]
	public static extern bool LookupPrivilegeValue(
		string lpSystemName,
		string lpName,
		ref long lpLuid);
		
	[DllImport("advapi32.dll", SetLastError = true)]
	public static extern bool AdjustTokenPrivileges(
		IntPtr TokenHandle,
		bool DisableAllPrivileges,
		ref TokPriv1Luid NewState,
		int BufferLength,
		IntPtr PreviousState,
		IntPtr ReturnLength);
		
}

public static class Kernel32
{
	[DllImport("kernel32.dll")]
	public static extern uint GetLastError();
}

[Flags()]
public enum TokenAccess
{
	AssignPrimary = 0x0001,
    Duplicate = 0x0002,
    Impersonate = 0x0004,
    Query = 0x0008,
    QuerySource = 0x0010,
    AdjustPrivileges = 0x0020,
    AdjustGroups = 0x0040,
    AdjustDefault = 0x0080,
    AdjustSessionID = 0x0100,
    StandardRightsRead = 0x00020000,
	StandardRightsRequired = 0x000F0000,
    Read = StandardRightsRead | Query,
	ModifyRights = Query | AdjustPrivileges,
    FullControl = AssignPrimary | Duplicate | Impersonate | Query | QuerySource | AdjustPrivileges | AdjustGroups | AdjustDefault | AdjustSessionID | StandardRightsRead | StandardRightsRequired
}
"@
		Add-Type -TypeDefinition $source -ErrorAction Ignore
		#endregion Source Code	
	}
	process {


		$ProcHandle = (Get-Process -Id $pid).Handle
		
		$hTokenHandle = [IntPtr]::Zero
		$null = [Advapi32]::OpenProcessToken($ProcHandle, [TokenAccess]::ModifyRights, [ref]$hTokenHandle)
			
		$TokPriv1Luid = [TokPriv1Luid]::new()
		$TokPriv1Luid.Count = 1
		$TokPriv1Luid.Attr = 0x00000002 # SE_PRIVILEGE_ENABLED
				
		$LuidVal = $Null
		$null = [Advapi32]::LookupPrivilegeValue($null, $Privilege, [ref]$LuidVal)
		$TokPriv1Luid.Luid = $LuidVal
				
		$null = [Advapi32]::AdjustTokenPrivileges($hTokenHandle, $False, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero)
	}
}