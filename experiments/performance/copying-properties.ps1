<#
The basic idea is to check relative performance in different scenarios, when copying properties from one object to another.
Imagine a situation where you want to update a cache but cannot just blanket replace everything, because the new data might not contain all entries.

Proposed Approaches:
- Iterate over a specific list of properties in a loop
- Iterate over all properties on the object
- Use PowerShell Classes and property iteration
- Use C# Classes and property iteration

Prerequisites:
- Module "PSModuleDevelopment" to run tests
#>

#region Functions
function New-RandomObject {
	[CmdletBinding()]
	param (
		[int]
		$PropertyCount = 5,

		[int]
		$FillPercent = 100
	)

	$container = @{}

	foreach ($id in 1..$PropertyCount) {
		$value = $null
		$roll = Get-Random -Minimum 1 -Maximum 100
		if ($roll -lt $FillPercent) { $value = $roll }
		$container["Property$id"] = $value
	}

	[PSCustomObject]$container
}
#endregion Functions

#region Types
Add-Type -TypeDefinition @'
using System;
using System.Management.Automation;

namespace Demo
{
	public static class CSPropCopy
	{
		public static void Copy(PSObject From, PSObject To)
		{
			foreach (PSPropertyInfo member in To.Properties)
				if (From.Properties[member.Name] != null)
					member.Value = From.Properties[member.Name].Value;
		}
	}
}
'@

class PropCopy {
	static [void]Copy($From, $To) {
		foreach ($property in $To.PSObject.Properties) {
			if ($null -ne $From.($property.Name)) { $To.($property.Name) = $From.($property.Name)}
		}
	}
}
#endregion Types

#region Measuring Code
$methodScriptDirect = {
	foreach ($id in 1..$count) {
		if ($update."Property$id") { $origin."Property$id" = $update."Property$id"}
	}
}
$methodScriptEnum = {
	foreach ($property in $origin.PSObject.Properties) {
		if ($null -ne $update.($property.Name)) { $origin.($property.Name) = $update.($property.Name)}
	}
}
$methodPSClass = {
	[PropCopy]::Copy($update, $origin)
}
$methodCSClass = {
	[Demo.CSPropCopy]::Copy($update, $origin)
}
#endregion Measuring Code

# Testset 1: 5 / 100
$count = 5
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 100

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
ScriptEnum   1                00:00:00.0000246
CSClass      1.04471544715447 00:00:00.0000257
ScriptDirect 1.17886178861789 00:00:00.0000290
PSClass      1.78861788617886 00:00:00.0000440

PS 5.1:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000168
ScriptEnum   2.85119047619048 00:00:00.0000479
PSClass      3.35714285714286 00:00:00.0000564
ScriptDirect 3.95833333333333 00:00:00.0000665
#>

# Testset 2: 10 / 100
$count = 10
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 100

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000175
ScriptEnum   1.40571428571429 00:00:00.0000246
ScriptDirect 1.42857142857143 00:00:00.0000250
PSClass      1.75428571428571 00:00:00.0000307

PS 5.1:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000179
ScriptDirect 2.94413407821229 00:00:00.0000527
PSClass      3.0391061452514  00:00:00.0000544
ScriptEnum   3.6536312849162  00:00:00.0000654
#>

# Testset 3: 10 / 75
$count = 10
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 75

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000161
ScriptDirect 1.25465838509317 00:00:00.0000202
ScriptEnum   1.27950310559006 00:00:00.0000206
PSClass      1.50931677018634 00:00:00.0000243

PS 5.1:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000150
PSClass      2.7              00:00:00.0000405
ScriptDirect 3.01333333333333 00:00:00.0000452
ScriptEnum   3.32             00:00:00.0000498
#>

# Testset 4: 10 / 25
$count = 10
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 25

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
ScriptDirect 1                00:00:00.0000115
CSClass      1.4              00:00:00.0000161
ScriptEnum   1.43478260869565 00:00:00.0000165
PSClass      1.80869565217391 00:00:00.0000208

PS 5.1:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000151
ScriptDirect 1.74172185430464 00:00:00.0000263
PSClass      2.29139072847682 00:00:00.0000346
ScriptEnum   2.45033112582781 00:00:00.0000370
#>

<#
Analysis:
C# as a platform proves to remain the most efficient for purely in-memory operations.
However, looping through a definite list of properties is likely cheaper.

You should use PowerShell 7.5.
#>

# Testset 5: 100 / 100
$count = 100
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 100

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000584
ScriptEnum   9.72431506849315 00:00:00.0005679
PSClass      10.2791095890411 00:00:00.0006003
ScriptDirect 540.667808219178 00:00:00.0315750

PS 5.1:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000680
PSClass      13.6073529411765 00:00:00.0009253
ScriptEnum   14.9647058823529 00:00:00.0010176
ScriptDirect 15.2294117647059 00:00:00.0010356
#>

<#
Analysis:
The C# solution sees _significant_ gains when increasing the size of a single operation.
This demonstrates, that a significant part of the overall processing cost with the C#-based solution is the script portion calling it.
Otherwise, a factor 4 increase* in duration with a factor 10 increase in dataset size cannot be explained.

*Compared to Testset 2, which used 10 properties with a 100% Update rate.

There IS however a major data anomaly: In PowerShell 7, directly iterating over all properties directly is inexplicably more expensive.
#>

# Testset 6: 100 / 100
$methodScriptDirect2 = {
	foreach ($id in 1..$count) {
		$prop = "Property$id"
		if ($update.$prop) { $origin.$prop = $update.$prop }
	}
}
$count = 100
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 100

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect2
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000486
PSClass      7.96502057613169 00:00:00.0003871
ScriptDirect 9.52469135802469 00:00:00.0004629
ScriptEnum   9.76337448559671 00:00:00.0004745
#>
#-> It was not a matter of looping, but of building the strings!

# Testset 7: 100 / 100
$methodScriptDirect3 = {
	foreach ($id in 1..$count) {
		$prop = "Property$id"
		if ($update."Property$id") { $origin.$prop = $update.$prop }
	}
}
$count = 100
$origin = New-RandomObject -PropertyCount $count
$update = New-RandomObject -PropertyCount $count -FillPercent 100

Measure-PSMDCommand -Iterations 1000 -TestSet @{
	ScriptDirect = $methodScriptDirect3
	ScriptEnum = $methodScriptEnum
	PSClass = $methodPSClass
	CSClass = $methodCSClass
}
<#
PS 7.5:
Name         Efficiency       Average
----         ----------       -------
CSClass      1                00:00:00.0000562
PSClass      7.83985765124555 00:00:00.0004406
ScriptEnum   9.32384341637011 00:00:00.0005240
ScriptDirect 511.581850533808 00:00:00.0287509
#>
#-> Don't dynamically calculate property-names in if-conditions when writing for PowerShell 7
#-> More research into "WHY?!" needed.
#-> C# still wins.

<#
Important Note:
The purpose for this research was NOT to say "C# is best, abandon POwerShell".
Far from it!
C# has a clear advantage when doing things _strictly_ within the memory of your own process.
If you spend most of your time waiting for network responses, there is absolutely no advantage!
Indeed, in case of many client libraries, response processing of network requests makes it _less_ efficient than PowerShell.

Also, speed is only one metric, and depending on priority not the most important one by far.
How much time do you spend writing the code? How many dependencies did it take to make the same thing happen PowerShell did in one line?

It's a "The Right Tool For The Right Job" kind of discussion.
#>