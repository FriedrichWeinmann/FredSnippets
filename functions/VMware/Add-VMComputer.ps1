function Add-VMComputer {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Name,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Domain,

		[Parameter(Mandatory = $true)]
		[pscredential]
		$VMCredential,
		
		[Parameter(Mandatory = $true)]
		[pscredential]
		$JoinCred,

		[string]
		$OU
	)

	$code = {
		$userName = '%USER%'
		$secretEncoded = '%SECRET%'
		$domain = '%DOMAIN%'
		$ou = '%OU%'

		$secret = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($secretEncoded))
		$credential = [PSCredential]::new(
			$userName,
			($secret | ConvertTo-SecureString -AsPlainText -Force)
		)

		$joinParam = @{
			Credential = $credential
			DomainName = $domain
			Force = $true
			Restart = $true
		}
		if ($ou) { $joinParam.OUPath = $ou }

		Add-Computer @joinParam
	}

	$vm = Get-VM -Name $Name -ErrorAction Stop
	$secretEncoded = [convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($JoinCred.GetNetworkCredential().Password))
	$commandText = $code.ToString() -replace '%USER%', $JoinCred.UserName -replace '%SECRET%', $secretEncoded -replace '%DOMAIN%',$Domain -replace '%OU%',($OU -replace "'","''")

	Invoke-VMScript -VM $vm -ScriptText $commandText -ScriptType Powershell -GuestCredential $VMCredential
}
