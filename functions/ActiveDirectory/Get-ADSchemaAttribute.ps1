function Get-ADSchemaAttribute {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$ObjectClass,

		[string]
		$Server,

		[pscredential]
		$Credential,

		[Parameter(DontShow = $true)]
		[string]
		$OriginalClass,

		[Parameter(DontShow = $true)]
		[hashtable]
		$AttributeMap = @{},

		[Parameter(DontShow = $true)]
		[hashtable]
		$Attributes = @{}
	)

	if (-not $OriginalClass) {
		$OriginalClass = $ObjectClass
	}

	$adParam = @{}
	if ($Server) { $adParam.Server = $Server }
	if ($Credential) { $adParam.Credential = $Credential }

	$rootDSE = Get-ADRootDSE @adParam
	$schemaClass = Get-ADObject @adParam -LdapFilter "(ldapDisplayName=$ObjectClass)" -SearchBase $rootDSE.schemaNamingContext -Properties *

	if ($AttributeMap.Count -lt 1) {
		foreach ($attribute in Get-ADObject @adParam -LdapFilter "(objectClass=attributeSchema)" -SearchBase $rootDSE.schemaNamingContext -Properties *) {
			$AttributeMap[$attribute.ldapDisplayName] = $attribute
		}
	}

	$myAttributes = @{}

	foreach ($attributeName in $schemaClass.mayContain) {
		if ($Attributes[$attributeName]) { continue }
		$Attributes[$attributeName] = $attributeName

		[PSCustomObject]@{
			Class = $OriginalClass
			Type = 'MayContain'
			Attribute = $attributeName
			From = $schemaClass.ldapDisplayName

			ClassObject = $schemaClass
			AttributeObject = $attributeMap[$attributeName]
		}
	}
	foreach ($attributeName in $schemaClass.mustContain) {
		if ($Attributes[$attributeName]) { continue }
		$Attributes[$attributeName] = $attributeName

		[PSCustomObject]@{
			Class = $OriginalClass
			Type = 'MustContain'
			Attribute = $attributeName
			From = $schemaClass.ldapDisplayName

			ClassObject = $schemaClass
			AttributeObject = $attributeMap[$attributeName]
		}
	}
	foreach ($attributeName in $schemaClass.systemMayContain) {
		if ($Attributes[$attributeName]) { continue }
		$Attributes[$attributeName] = $attributeName

		[PSCustomObject]@{
			Class = $OriginalClass
			Type = 'SystemMayContain'
			Attribute = $attributeName
			From = $schemaClass.ldapDisplayName

			ClassObject = $schemaClass
			AttributeObject = $attributeMap[$attributeName]
		}
	}

	foreach ($auxClass in $schemaClass.auxiliaryClass) {
		Get-SchemaAttribute @adParam -ObjectClass $auxClass -OriginalClass $OriginalClass -AttributeMap $AttributeMap -Attributes $Attributes
	}
	foreach ($auxClass in $schemaClass.systemAuxiliaryClass) {
		Get-SchemaAttribute @adParam -ObjectClass $auxClass -OriginalClass $OriginalClass -AttributeMap $AttributeMap -Attributes $Attributes
	}
	if ($schemaClass.subClassOf -and $schemaClass.subClassOf -ne $ObjectClass) {
		Get-SchemaAttribute @adParam -ObjectClass $schemaClass.subClassOf -OriginalClass $OriginalClass -AttributeMap $AttributeMap -Attributes $Attributes
	}
}
