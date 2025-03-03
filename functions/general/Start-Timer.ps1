function Start-Timer {
	<#
	.SYNOPSIS
		Creates a timer that will alarm the user after it has expired.
	
	.DESCRIPTION
		Creates a timer that will alarm the user after it has expired.
		Provides both visual and sound warnings.
		Also provides a progress bar with a time remaining display.
	
	.PARAMETER Duration
		The time to wait.
	
	.PARAMETER Message
		What to wait for.
	
	.PARAMETER AlarmCount
		How often to give warning.
	
	.PARAMETER NoProgress
		Disables progress bar.
	
	.PARAMETER AlarmInterval
		In what time interval to write warnings and send sound.
	
	.PARAMETER RandomInterval
		Randomizes the interval between two signal sounds.
	
	.PARAMETER MinFrequency
		The minimum frequency of the beeps.
		Must be at least one lower than MaxFrequency.
		Increase delta to play random frequency sounds on each beep.
	
	.PARAMETER MaxFrequency
		The maximum frequency of the beeps.
		Must be at least one higher than MaxFrequency.
		Increase delta to play random frequency sounds on each beep.
	
	.PARAMETER DisableScreensaver
		Disables the screensaver while the timer is pending.
		This only works on Windows and has the command pretend to be a video & backup application, preventing untimely activation of a screensaver.
	
	.EXAMPLE
		PS C:\> timer 00:03:00 Tea
		
		After 3 minutes give warning that the tea is ready.
#>
	[Alias('timer')]
	[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
	[CmdletBinding()]
	param (
		[Parameter(Position = 0, Mandatory = $true)]
		[Alias('Seconds')]
		[timespan]
		$Duration,
		
		[Parameter(Position = 1, Mandatory = $true)]
		$Message,
		
		[Parameter(Position = 2)]
		[int]
		$AlarmCount = 25,
		
		[switch]
		$NoProgress,
		
		[int]
		$AlarmInterval = 250,
		
		[switch]
		$RandomInterval,
		
		[int]
		$MinFrequency = 2999,
		
		[int]
		$MaxFrequency = 3000,
		
		[switch]
		$DisableScreensaver
	)
	
	begin {
		#region C# Stuff
		$source = @'
using System;
using System.Runtime.InteropServices;

namespace Screensaver
{
	public static class Disabler
	{
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern ExecutionState SetThreadExecutionState(ExecutionState asFlags);

		/// <summary>
        /// Tell the system, that something really, really important is happening here and screensaver would ruin the day
        /// </summary>
        public static void DisableScreensaver()
        {
            SetThreadExecutionState(ExecutionState.DisplayRequired);
            SetThreadExecutionState(ExecutionState.SystemRequired | ExecutionState.AwayModeRequired | ExecutionState.Continuous);
        }
        /// <summary>
        /// Tell the system, that the screensaver may now be safely deployed again.
        /// </summary>
        public static void EnableScreensaver()
        {
            SetThreadExecutionState(ExecutionState.Continuous);
        }
	}

	/// <summary>
    /// The state of the current console
    /// </summary>
    [Flags]
    public enum ExecutionState : uint
    {
        /// <summary>
        /// Critical system resources are in use. Used for backups
        /// </summary>
        SystemRequired = 1,

        /// <summary>
        /// Display must not be turned off. Used when running video software
        /// </summary>
        DisplayRequired = 2,

        /// <summary>
        /// There's an actual user around
        /// </summary>
        UserPresent = 4,

        /// <summary>
        /// User must be away
        /// </summary>
        AwayModeRequired = 0x40,

        /// <summary>
        /// Something is happening for some time still
        /// </summary>
        Continuous = 0x80000000
    }
}
'@
		try { Add-Type -TypeDefinition $source }
		catch {
			<# Do nothing, code already loaded#>
		}
		#endregion C#-Stuff

		$start = Get-Date
		$end = $start.Add($Duration)
		# Allow conveniently specifying absolute times for the day after
		if ($end -lt $start) { $end = $end.AddDays(1) }
		
		function Get-FriendlyTime {
			[CmdletBinding()]
			param (
				[int]
				$Seconds
			)
			
			$tempSeconds = $Seconds
			$strings = @()
			if ($tempSeconds -gt 3599) {
				[int]$count = [math]::Floor(($tempSeconds / 3600))
				$strings += "{0}h" -f $count
				$tempSeconds = $tempSeconds - ($count * 3600)
			}
			
			if ($tempSeconds -gt 59) {
				[int]$count = [math]::Floor(($tempSeconds / 60))
				$strings += "{0}m" -f $count
				$tempSeconds = $tempSeconds - ($count * 60)
			}
			
			$strings += "{0}s" -f $tempSeconds
			
			$strings -join " "
		}
	}
	process {
		if (-not $NoProgress) {
			Write-Progress -Activity "Waiting for $Message" -Status "Starting" -PercentComplete 0
		}
		
		while ($end -gt (Get-Date)) {
			Start-Sleep -Milliseconds 500
			if ($DisableScreensaver) { [Screensaver.Disabler]::DisableScreensaver() }
			
			if (-not $NoProgress) {
				$friendlyTime = Get-FriendlyTime -Seconds ($end - (Get-Date)).TotalSeconds
				[int]$percent = ((Get-Date) - $start).TotalSeconds / ($end - $start).TotalSeconds * 100
				Write-Progress -Activity "Waiting for $Message" -Status "Time remaining: $($friendlyTime)" -PercentComplete ([System.Math]::Min($percent, 100))
			}
		}
		
		if (-not $NoProgress) {
			Write-Progress -Activity "Waiting for $Message" -Completed
		}
		
		$countAlarm = 0
		while ($countAlarm -lt $AlarmCount) {
			Write-Host "($countAlarm) ### $($Message)"
			if ($DisableScreensaver) { [Screensaver.Disabler]::DisableScreensaver() }
			[System.Console]::Beep((Get-Random -Minimum $MinFrequency -Maximum $MaxFrequency), $AlarmInterval)
			if ($RandomInterval) { Start-Sleep -Milliseconds (Get-Random -Minimum $AlarmInterval -Maximum ($AlarmInterval * 2)) }
			else { Start-Sleep -Milliseconds $AlarmInterval }
			$countAlarm++
		}
	}
}
