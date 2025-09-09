function Publish-TextFile {
	<#
	.SYNOPSIS
		Upload text as if it were a text file upload.
	
	.DESCRIPTION
		Upload text as if it were a text file upload.
		Does not actually require a file, enabling file uploads in file-less contexts.
	
	.PARAMETER Name
		Name of the file to upload.
		Can be anything.
	
	.PARAMETER Content
		Actual Text content to upload.
	
	.PARAMETER Url
		The Url to push the content to.
	
	.PARAMETER Headers
		Headers to include with the POST.
		Many APIs will require some authentication headers.
	
	.EXAMPLE
		PS C:\> Publish-TextFile -Name users.csv -Content $text -Headers $token.GetHeader() -Url $url

		Uploads the content of $text as "users.csv"
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Name,

		[Parameter(Mandatory = $true)]
		[string[]]
		$Content,

		[Parameter(Mandatory = $true)]
		[string]
		$Url,

		[hashtable]
		$Headers = @{}
	)

	$lineFeed = "`r`n"
	$actualContent = $Content -split "`n" | ForEach-Object { $_.Trim("`r") }
	$boundary = [System.Guid]::NewGuid().ToString()

	$bodyLines = @(
		"--$boundary"
		"Content-Disposition: form-data; name=`"file`"; filename=`"$Name`""
		"Content-Type: application/octet-stream$lineFeed"
		($actualContent -join $lineFeed)
		"--$boundary--$lineFeed"
	) -join $lineFeed

	Invoke-RestMethod -Uri $Url -Method Post -ContentType "multipart/form-data; boundary=`"$boundary`"" -Body $bodyLines -Headers $Headers
}
