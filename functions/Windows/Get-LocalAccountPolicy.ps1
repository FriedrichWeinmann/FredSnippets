function Get-LocalAccountPolicy {
	<#
	.SYNOPSIS
		Uses the Windows API to retrieve the effective local account policy.
	
	.DESCRIPTION
		Uses the Windows API to retrieve the effective local account policy.
		In opposite to "net accounts", this is not dependent on localization.
	
	.PARAMETER ComputerName
		The computer for which to retrieve the information.
		Defaults to localhost.
	
	.EXAMPLE
		PS C:\> Get-LocalAccountPolicy
		
		Retrieves the account policy of the local computer.
	#>
	[CmdletBinding()]
	param (
		[string[]]
		$ComputerName = $env:COMPUTERNAME
	)
	begin {
		#region Code
		$code = @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Accounts
{
	public static class Native
	{
		[DllImport("NetApi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		public static extern int NetUserModalsGet(string servername, uint level, ref IntPtr bufptr);

		public static USER_MODALS_INFO_0 GetPasswordSetting(string ComputerName)
		{
			IntPtr temp = IntPtr.Zero;
			NetUserModalsGet(ComputerName, 0, ref temp);
			return Marshal.PtrToStructure<USER_MODALS_INFO_0>(temp);
		}

		public static USER_MODALS_INFO_1 GetServerRole(string ComputerName)
		{
			IntPtr temp = IntPtr.Zero;
			NetUserModalsGet(ComputerName, 1, ref temp);
			return Marshal.PtrToStructure<USER_MODALS_INFO_1>(temp);
		}

		public static USER_MODALS_INFO_2 GetDomainInfo(string ComputerName)
		{
			IntPtr temp = IntPtr.Zero;
			NetUserModalsGet(ComputerName, 2, ref temp);
			return Marshal.PtrToStructure<USER_MODALS_INFO_2>(temp);
		}

		public static USER_MODALS_INFO_3 GetAccountLockout(string ComputerName)
		{
			IntPtr temp = IntPtr.Zero;
			NetUserModalsGet(ComputerName, 3, ref temp);
			return Marshal.PtrToStructure<USER_MODALS_INFO_3>(temp);
		}
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct USER_MODALS_INFO_0
	{
	    public uint usrmod0_min_passwd_len;
	    public uint usrmod0_max_passwd_age;
	    public uint usrmod0_min_passwd_age;
	    public uint usrmod0_force_logoff;
	    public uint usrmod0_password_hist_len;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct USER_MODALS_INFO_1
	{
	    public uint usrmod1_role;
	    public string usrmod1_primary;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct USER_MODALS_INFO_2
	{
	    public string usrmod2_domain_name;
	    public IntPtr usrmod2_domain_id;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct USER_MODALS_INFO_3
	{
	    public uint usrmod3_lockout_duration;
	    public uint usrmod3_lockout_observation_window;
	    public uint usrmod3_lockout_threshold;
	}

	public class AccountPolicy
	{
		public TimeSpan LockoutDuration => new TimeSpan(0,0, (int)Info3.usrmod3_lockout_duration);
		public TimeSpan LockoutObservation => new TimeSpan(0,0, (int)Info3.usrmod3_lockout_observation_window);
		public int LockoutThreshold => (int)Info3.usrmod3_lockout_threshold;

		public string DomainName => Info2.usrmod2_domain_name;
		public SecurityIdentifier DomainSid => new SecurityIdentifier(Info2.usrmod2_domain_id);

		public string DomainController => Info1.usrmod1_primary;

		public int MinPasswordLength => (int)Info0.usrmod0_min_passwd_len;
		public TimeSpan MinPasswordAge => new TimeSpan(0,0,(int)Info0.usrmod0_min_passwd_age);
		public TimeSpan MaxPasswordAge => new TimeSpan(0,0,(int)Info0.usrmod0_max_passwd_age);
		public TimeSpan ForcedLogoffGrace => new TimeSpan(0,0,(int)Info0.usrmod0_force_logoff);
		public int PasswordHistory => (int)Info0.usrmod0_password_hist_len;

		private USER_MODALS_INFO_0 Info0;
		private USER_MODALS_INFO_1 Info1;
		private USER_MODALS_INFO_2 Info2;
		private USER_MODALS_INFO_3 Info3;

		public AccountPolicy(string ComputerName)
		{
			Info0 = Native.GetPasswordSetting(ComputerName);
			Info1 = Native.GetServerRole(ComputerName);
			Info2 = Native.GetDomainInfo(ComputerName);
			Info3 = Native.GetAccountLockout(ComputerName);
		}
	}
}
'@
		Add-Type $code -ErrorAction SilentlyContinue
		#endregion Code
	}
	process {
		foreach ($computer in $ComputerName) {
			[Accounts.AccountPolicy]$computer
		}
	}
}