Set-PSFTaskEngineCache -Module profile -Name Tenants -Lifetime '1d' -Collector { Get-AzTenant }
Register-PSFTaskEngineTask -Name profile.tenant -ScriptBlock {
	$null = Get-PSFTaskEngineCache -Module profile -Name Tenants
} -Once
Register-PSFTeppScriptblock -Name AZ.Tenant -ScriptBlock {
	(Get-PSFTaskEngineCache -Module profile -Name Tenants).DefaultDomain
}
Register-PSFTeppArgumentCompleter -Command Set-AzContext -Parameter Tenant -Name AZ.Tenant
  
Register-PSFTeppScriptblock -Name Az.SubScription -ScriptBlock {
	$param = @{ }
	if (-not $fakeBoundParameters.Tenant) {
		$param.TenantId = (Get-AzContext).Tenant.Id
	}
	else {
		$tenantID = @((Get-PSFTaskEngineCache -Module profile -Name Tenants | Where-Object DefaultDomain -EQ $fakeBoundParameters.Tenant))[0].Id
		if (-not $tenantID) { return " " }
		$param.TenantID = $tenantID
	}
	foreach ($subscription in Get-AzSubscription @param ) {
		@{ Text = $subscription.Id; ToolTip = $subscription.Name }
	}
}
Register-PSFTeppArgumentCompleter -Command Set-AzContext -Parameter Subscription -Name AZ.Subscription