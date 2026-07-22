function ConvertTo-TabCompletion {
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		$InputObject,

		[string]
		$WordToComplete
	)
	process {
		$text = $InputObject.Text
		if ($InputObject -is [string]) { $text = $InputObject }

		if (-not $text) { return }
		if ($text -notlike "$($wordToComplete.Trim('''"'))*") { return }

		$tooltip = $text
		if ($InputObject.ToolTip) { $tooltip = $InputObject.Tooltip }

		$insertText = $text
		if ($text -match '\s') { $insertText = "'$text'" }

		[System.Management.Automation.CompletionResult]::new(
			$insertText,
			$text,
			'ParameterValue',
			$tooltip # Tooltip
		)
	}
}
