Set-StrictMode -Version latest

Enum ComRights {
	None = 0
	Execute = 1
	ExecuteLocal = 2
	ExecuteRemote = 4
	ActivateLocal = 8
	ActivateRemote = 0x10
}

<#
[System.Security.AccessControl.AceFlags]
Enum AceFlags {
	ObjectInherit = 1
	ContainerInherit = 2
	NoPropagateInherit = 4
	InheritOnly = 8
	Inherited = 0x10
}
#>
New-Variable -Name NtAdministrators `
             -Description 'Builtin Administrators Group' `
             -Option ReadOnly `
             -Value ([System.Security.Principal.NTAccount]::new('BUILTIN', 'Administrators'))
New-Variable -Name AuthenticatedUsers `
             -Description 'Authenticated Users Group' `
             -Option ReadOnly `
             -Value ([System.Security.Principal.NTAccount]::new('NT AUTHORITY', 'Authenticated Users'))
<#
.Synopsis
	Temporarily own registry keys and access their ACLs.
.DESCRIPTION
	The function retrieves a registry key's ACL and temporarily swaps its owner during a scriptblock call.
.EXAMPLE
	Example of how to use this cmdlet
.EXAMPLE
	Another example of how to use this cmdlet
#>
function Invoke-AsOwner {
	[CmdletBinding()]
	[Alias()]
	[OutputType([System.Security.AccessControl.CommonObjectSecurity])]
	Param(
		# Key Registry key to provide ACL.
		[Parameter( ParameterSetName='RegistryKey'
		          , Mandatory=$true
		          , ValueFromPipeline=$true
		          )]
		[Microsoft.Win32.RegistryKey]
		$Key,

		# Key Path of registry key to provide ACL.
		[Parameter( ParameterSetName='RegistryPath'
		          , Mandatory=$true
		          , ValueFromPipeline=$true
		          )]
		[ValidateScript({Test-Path -LiteralPath $_})]
		[string]
		$KeyPath,

		# ScriptBlock <[Microsoft.Win32.RegistryKey],[System.Security.AccessControl.CommonObjectSecurity]> scriptblock called to alter temporarily owned key and ACL.
		[Parameter(Mandatory=$true)]
		[System.Management.Automation.ScriptBlock]
		$ScriptBlock,

		# Owner Temporary key owner during invocation. Default: current user.
		[Parameter()]
		[System.Security.Principal.IdentityReference]
		$Owner=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
	)

	Begin {
		$priv = Get-Privilege
		$priv0 = Get-Privilege
		$priv.Enable([Pscx.Interop.TokenPrivilege]::Restore)
		Set-Privilege -Privileges $priv
	} Process {
		Write-Debug -Message ('Bound Parameters:{0}' -f (Out-String -InputObject $PSBoundParameters))
		Write-Debug -Message ('Parameter Set: {0}' -f $PsCmdlet.ParameterSetName)
		switch ($PsCmdlet.ParameterSetName) {
			'RegistryKey' {}
			'RegistryPath' { $Key = Get-Item -LiteralPath $KeyPath }
			Default { throw [System.ArgumentException]::new('ParameterSetName {0} does not exist' -f $PsCmdlet.ParameterSetName) }
		}
		$acl = $Key.GetAccessControl()
		$backup = $Key.GetAccessControl()
		$original = $acl.GetOwner([System.Security.Principal.NTAccount])
		$acl.SetOwner($Owner)
		& $ScriptBlock -Key $Key -Acl $acl
		try {
			$Key.SetAccessControl($acl)
		} catch [System.Management.Automation.MethodInvocationException] {
			if ($_.Exception.InnerException -is [System.UnauthorizedAccessException]) {
				$Key = Get-RegistryKey -Key $Key
				$Key.SetAccessControl($acl)
			} else {
				throw
			}
		}
		$acl.SetOwner($original)
		$Key.SetAccessControl($acl)
		$acl
	} End {
		Set-Privilege -Privileges $priv0
	}
}

function Get-SecurityDescriptor {
	[CmdletBinding(DefaultParameterSetName='ByPath', HelpUri='http://go.microsoft.com/fwlink/?LinkID=113305')]
	[OutputType([System.Security.AccessControl.CommonObjectSecurity])]
	param(
		[Parameter(ParameterSetName='ByPath', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[ValidateNotNullOrEmpty()]
		[string[]]
		${Path},

		[Parameter(ParameterSetName='ByInputObject', Mandatory=$true)]
		[psobject]
		${InputObject},

		[Parameter(ParameterSetName='ByLiteralPath', ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Alias('PSPath')]
		[ValidateNotNullOrEmpty()]
		[string[]]
		${LiteralPath},

		[System.Security.AccessControl.AccessControlSections]
		$AccessControlSections=[System.Security.AccessControl.AccessControlSections]::All -band -bnot [System.Security.AccessControl.AccessControlSections]::Audit,

		[switch]
		${Audit},

		[switch]
		${AllCentralAccessPolicies},

		[string]
		${Filter},

		[string[]]
		${Include},

		[string[]]
		${Exclude})

	begin {
		if ($Audit) {
			$AccessControlSections = $AccessControlSections -bor [System.Security.AccessControl.AccessControlSections]::Audit
		}
		'AccessControlSections','AllCentralAccessPolicies','Audit' | % {
			[void]$PSBoundParameters.Remove($_)
		}
	} process {
		@(switch ($PSCmdlet.ParameterSetName) {
			'ByInputObject' { $InputObject }
			{$_ -in 'ByPath','ByLiteralPath'} { Get-Item @PSBoundParameters }
			Default {}
		}) | % { $_.GetAccessControl($AccessControlSections) }
    # TODO extend PrivilegeNotHeldException with error message recommending run as Administrator
	} end {
	}
}
<#

.ForwardHelpTargetName Microsoft.PowerShell.Security\Get-Acl
.ForwardHelpCategory Cmdlet

#>

<#
.Synopsis
	Returns writable registry key.
.DESCRIPTION
	Reopens registry key in writable mode that accepts security descriptor changes.
.EXAMPLE
	Example of how to use this cmdlet
.EXAMPLE
	Another example of how to use this cmdlet
#>
filter Get-RegistryKey {
	[CmdletBinding()]
	[Alias()]
	[OutputType([Microsoft.Win32.RegistryKey])]
	Param(
		# Key Registry key.
		[Alias('InputObject')]
		[Parameter( ParameterSetName='RegistryKey'
		          , Mandatory=$true
		          , ValueFromPipeline=$true
		          )]
		[Microsoft.Win32.RegistryKey]
		$Key,

		# ReadOnly Restrict returned key's access to read-only.
		[switch]
		$ReadOnly
	)
	$root,$subkey = $Key.Name.Split('\',2)
	$root = $root.Split('_',2)[1].Replace('_','')
	Write-Verbose -Message ('Accessing root {0} subkey {1}' -f $root,$subkey)
	$Key = [Microsoft.Win32.Registry]::$root
	if ($subkey) {
		$Key = $Key.OpenSubKey($subkey, !$ReadOnly)
	}
	$Key
}

<#
.Synopsis
	Modify DACL on a Security Descriptor.
.DESCRIPTION
	Modifies an input Security Descriptor according to -Modification and a supplied Access rule and outputs the resulting Security Descriptor.
.EXAMPLE
	$sd = [System.Security.AccessControl.RegistrySecurity]::new() `
	| Edit-DACL -Modification Add `
	            -Trustee ([System.Security.Principal.NTAccount]::new('NT SERVICE','TrustedInstaller')) `
	            -AccessMask ([System.Security.AccessControl.RegistryRights]::FullControl) `
	| Edit-DACL -Modification Add `
	            -Trustee ([System.Security.Principal.NTAccount]::new('BUILTIN','Administrators')) `
	            -AccessMask ([System.Security.AccessControl.RegistryRights]::FullControl)
#>
function Edit-DACL {
	[CmdletBinding()]
	[Alias()]
	[OutputType([System.Security.AccessControl.CommonObjectSecurity])]
	Param(
		# InputObject Security descriptor to edit.
		[Parameter( Mandatory=$true
		          , ValueFromPipeline=$true
		          )]
		[Alias('SecurityDescriptor')]
		[System.Security.AccessControl.CommonObjectSecurity]
		$InputObject,

		# Modification Type of DACL change. The documentation http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.accesscontrolmodification.aspx explains each possibility.
		[System.Security.AccessControl.AccessControlModification]
		$Modification,

		# AccessRule AccessRule object.
		[Parameter( ParameterSetName='RuleObject'
		          , ValueFromPipeline=$true
		          )]
		[System.Security.AccessControl.AccessRule]
		$AccessRule,

		# Trustee Subject of an access rule.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.Principal.IdentityReference]
		$Trustee=[System.Security.Principal.WindowsIdentity]::GetCurrent().User,

		# AccessMask Bitwise combination of enumeration values for rights drawn from the security descriptor's type. For the correct enumeration, lookup documentation for the accessMask parameter of your security descriptor's AccessRuleFactory method.
		[Parameter( ParameterSetName='RuleComponents'
		          , Mandatory=$true
		          )]
		[System.Int32]
		$AccessMask,

		# IsInherited Designate the rule as inherited.
		[Parameter(ParameterSetName='RuleComponents')]
		[switch]
		$IsInherited,

		# InheritanceFlags A bitwise combination of flags specifying inheritance for descendants.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.AccessControl.InheritanceFlags]
		$InheritanceFlags=[System.Security.AccessControl.InheritanceFlags]::None,

		# PropagationFlags A bitwise combination of inheritance modifiers.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.AccessControl.PropagationFlags]
		$PropagationFlags=[System.Security.AccessControl.PropagationFlags]::None,

		# Type Access type.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.AccessControl.AccessControlType]
		$Type=[System.Security.AccessControl.AccessControlType]::Allow
	)

	Begin {
		New-Variable -Name modified
	} Process {
		if (!$PSBoundParameters.ContainsKey('AccessRule')) {
			switch ($PSCmdlet.ParameterSetName) {
				'RuleObject' {}
				'RuleComponents' {
					$AccessRule = $InputObject.AccessRuleFactory($Trustee, $AccessMask, $IsInherited, $InheritanceFlags, $PropagationFlags, $Type)
				}
				Default { throw [System.ArgumentException]::new('ParameterSetName {0} does not exist' -f $PsCmdlet.ParameterSetName) }
			}
		}

		if (!$InputObject.ModifyAccessRule($Modification, $AccessRule, [ref]$modified)) {
			Write-Error -Message 'Unable to modify access rule' `
			            -Category InvalidOperation `
			            -CategoryReason 'Operation failed' `
			            -TargetObject @{InputObject=$InputObject; AccessRule=$AccessRule}
		}
		$InputObject
	} End {
	}
}

<#
.Synopsis
	Modify SACL on a Security Descriptor.
.DESCRIPTION
	Modifies an input Security Descriptor according to -Modification and a supplied Audit rule and outputs the resulting Security Descriptor.
.EXAMPLE
	$sd = [System.Security.AccessControl.RegistrySecurity]::new() `
	| Edit-SACL -Modification Add `
	            -Trustee ([System.Security.Principal.NTAccount]::new('NT SERVICE','TrustedInstaller')) `
	            -AccessMask ([System.Security.AccessControl.RegistryRights]::FullControl) `
	| Edit-SACL -Modification Add `
	            -Trustee ([System.Security.Principal.NTAccount]::new('BUILTIN','Administrators')) `
	            -AccessMask ([System.Security.AccessControl.RegistryRights]::FullControl)
.EXAMPLE
	Another example of how to use this cmdlet
#>
function Edit-SACL {
	[CmdletBinding()]
	[Alias()]
	[OutputType([System.Security.AccessControl.CommonObjectSecurity])]
	Param(
		# InputObject Security descriptor to edit.
		[Parameter( Mandatory=$true
		          , ValueFromPipeline=$true
		          )]
		[Alias('SecurityDescriptor')]
		[System.Security.AccessControl.CommonObjectSecurity]
		$InputObject,

		# Modification Type of SACL change. The documentation http://msdn.microsoft.com/en-us/library/system.security.accesscontrol.accesscontrolmodification.aspx explains each possibility.
		[System.Security.AccessControl.AccessControlModification]
		$Modification,

		# AuditRule AuditRule object.
		[Parameter( ParameterSetName='RuleObject'
		          , ValueFromPipeline=$true
		          )]
		[System.Security.AccessControl.AuditRule]
		$AuditRule,

		# Trustee Subject of an audit rule.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.Principal.IdentityReference]
		$Trustee=$AuthenticatedUsers,

		# AccessMask Bitwise combination of enumeration values for rights drawn from the security descriptor's type. For the correct enumeration, lookup documentation for the accessMask parameter of your security descriptor's AuditRuleFactory method.
		[Parameter( ParameterSetName='RuleComponents'
		          , Mandatory=$true
		          )]
		[System.Int32]
		$AccessMask,

		# IsInherited Designate the rule as inherited.
		[Parameter(ParameterSetName='RuleComponents')]
		[switch]
		$IsInherited,

		# InheritanceFlags A bitwise combination of flags specifying inheritance for descendants.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.AccessControl.InheritanceFlags]
		$InheritanceFlags=[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,

		# PropagationFlags A bitwise combination of inheritance modifiers.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.AccessControl.PropagationFlags]
		$PropagationFlags=[System.Security.AccessControl.PropagationFlags]::None,

		# AuditFlags Bitwise combination of access outcomes to audit.
		[Parameter(ParameterSetName='RuleComponents')]
		[System.Security.AccessControl.AuditFlags]
		$AuditFlags=[System.Security.AccessControl.AuditFlags]::Success
	)

	Begin {
		New-Variable -Name modified
	} Process {
		if (!$PSBoundParameters.ContainsKey('AuditRule')) {
			switch ($PSCmdlet.ParameterSetName) {
				'RuleObject' {}
				'RuleComponents' {
					$AuditRule = $InputObject.AuditRuleFactory($Trustee, $AccessMask, $IsInherited, $InheritanceFlags, $PropagationFlags, $AuditFlags)
				}
				Default { throw [System.ArgumentException]::new('ParameterSetName {0} does not exist' -f $PsCmdlet.ParameterSetName) }
			}
		}

		if (!$InputObject.ModifyAuditRule($Modification, $AuditRule, [ref]$modified)) {
			Write-Error -Message 'Unable to modify audit rule' `
			            -Category InvalidOperation `
			            -CategoryReason 'Operation failed' `
			            -TargetObject @{InputObject=$InputObject; AuditRule=$AuditRule}
		}
		$InputObject
	} End {
	}
}

<#
.Synopsis
	Edit security descriptor.
.DESCRIPTION
	Modifies owner, primary group, discretionary access control list, system access control list specified in a security descriptor. Windows has some issues mapping identity references to Security Identifiers: if errors emerge setting an access control list, try providing list subjects as [System.Security.Principal.SecurityIdentifier].
.EXAMPLE
	$sd = Edit-SecurityDescriptor -InputObject [System.Security.AccessControl.RegistrySecurity]::new() `
	                              -Owner ([System.Security.Principal.NTAccount]::new('BUILTIN','Administrator')) `
	                              -Group ([System.Security.Principal.NTAccount]::new('BUILTIN','Administrators'))
#>
# TODO handle exception from unmappable identity references (IdentityNotMappedException?)
function Edit-SecurityDescriptor {
	[CmdletBinding()]
	[Alias()]
	[OutputType([System.Security.AccessControl.CommonObjectSecurity])]
	Param(
		# InputObject Security descriptor to edit.
		[Parameter( Mandatory=$true
		          , ValueFromPipeline=$true
		          )]
		[Alias('SecurityDescriptor')]
		[System.Security.AccessControl.CommonObjectSecurity]
		$InputObject,

		# Owner User or group.
		[System.Security.Principal.IdentityReference]
		$Owner,

		# Group Primary group.
		[System.Security.Principal.IdentityReference]
		$Group,

		# Dacl Discretionary ACL. [System.Security.Principal.SecurityIdentifier] identity references are more robust against errors.
		$Dacl,

		# Sacl System ACL. [System.Security.Principal.SecurityIdentifier] identity references are more robust against errors.
		$Sacl
	)
	Begin {
		New-Variable -Name modified
	} Process {
		if ($null -ne $Owner) {
			$InputObject.SetOwner($Owner)
		}
		if ($null -ne $Group) {
			$InputObject.SetGroup($Group)
		}
		if ($null -ne $Dacl) {
			if (!$InputObject.ModifyAccessRule([System.Security.AccessControl.AccessControlModification]::Set, $Dacl[0], [ref]$modified)) {
				Write-Error -Message 'Unable to set access rule' `
				            -Category InvalidOperation `
				            -CategoryReason 'Operation failed' `
				            -TargetObject @{InputObject=$InputObject; AccessRule=$Dacl[0]}
			}
			$Dacl | Select-Object -Skip 1 | % {
				#Write-Debug -Message ('Access Rule{0}' -f (Out-String -InputObject $_))
				if (!$InputObject.ModifyAccessRule([System.Security.AccessControl.AccessControlModification]::Add, $_, [ref]$modified)) {
					Write-Error -Message 'Unable to add access rule' `
					            -Category InvalidOperation `
					            -CategoryReason 'Operation failed' `
					            -TargetObject @{InputObject=$InputObject; AccessRule=$_}
				}
			}
		}
		if ($null -ne $Sacl) {
			if (!$InputObject.ModifyAuditRule([System.Security.AccessControl.AccessControlModification]::Set, $Sacl[0], [ref]$modified)) {
				Write-Error -Message 'Unable to set audit rule' `
				            -Category InvalidOperation `
				            -CategoryReason 'Operation failed' `
				            -TargetObject @{InputObject=$InputObject; AuditRule=$Sacl[0]}
			}
			$Sacl | Select-Object -Skip 1 | % {
				if (!$InputObject.ModifyAuditRule([System.Security.AccessControl.AccessControlModification]::Add, $_, [ref]$modified)) {
					Write-Error -Message 'Unable to add audit rule' `
					            -Category InvalidOperation `
					            -CategoryReason 'Operation failed' `
					            -TargetObject @{InputObject=$InputObject; AuditRule=$_}
				}
			}
		}
		$InputObject
	}
}

<#
.Synopsis
	Get identity references to accounts.
.DESCRIPTION
	Gets Identity References by well-known type and (where applicable) domain identifier, fully-qualified NT Account name, or a provided identity reference (returned as NtAccount). By default, returns current user.
.EXAMPLE
	Get-IdentityReference
.EXAMPLE
	Get-IdentityReference -WellKnownType WorldSid
.EXAMPLE
	Get-IdentityReference -NtName Everyone
.EXAMPLE
	Get-IdentityReference -IdentityReference ([System.Security.Principal.NTAccount]::new('Everyone'))
#>
filter Get-IdentityReference {
	[CmdletBinding()]
	[Alias()]
	[OutputType([System.Security.Principal.IdentityReference])]
	Param(
		# WellKnownType Well-known SID type.
		[Parameter( ParameterSetName='WellKnown'
		          , Mandatory=$true
		          , ValueFromPipeline=$true
		          , ValueFromPipelineByPropertyName=$true
		          )]
		[System.Security.Principal.WellKnownSidType]
		$WellKnownType,

		# DomainIdentifier Domain identity reference. Only domain-specific accounts require this. Otherwise, it's ignored. See documentation of System.Security.Principal.WellKnownSidType http://msdn.microsoft.com/en-us/library/system.security.principal.wellknownsidtype.aspx for a list of those accounts. Default: current user's domain.
		[Parameter( ParameterSetName='WellKnown'
		          , ValueFromPipelineByPropertyName=$true
		          )]
		[System.Security.Principal.IdentityReference]
		$DomainIdentifier=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid,

		# NtName Fully-qualified NT account name. If account belongs to a domain, domain\name. Some accounts, like Everyone, lack a domain, so the bare name suffices.
		[Parameter( ParameterSetName='NtName'
		          , Mandatory=$true
		          , ValueFromPipeline=$true
		          , ValueFromPipelineByPropertyName=$true
		          )]
		[System.String]
		$NtName,

		# IdentityReference An identity reference object. Defaults to current user.
		[Parameter( ParameterSetName='ID'
		          , ValueFromPipeline=$true
		          , ValueFromPipelineByPropertyName=$true
		          )]
		[System.Security.Principal.IdentityReference]
		$IdentityReference=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
	)

	switch ($PsCmdlet.ParameterSetName) {
		'WellKnown' { [System.Security.Principal.SecurityIdentifier]::new($WellKnownType,$DomainIdentifier).Translate([System.Security.Principal.NTAccount]) }
		'NtName' { [System.Security.Principal.NTAccount]::new($NtName) }
		'ID' { $IdentityReference.Translate([System.Security.Principal.NTAccount]) }
		Default { throw [System.ArgumentException]::new('ParameterSetName {0} does not exist' -f $PsCmdlet.ParameterSetName) }
	}
}

function New-DComAce {
	[CmdletBinding()]
	[Alias()]
	#[OutputType([System.Security.Principal.IdentityReference])]
	param(
		[Parameter(Mandatory=$true)]
		[System.Security.Principal.IdentityReference] 
		$IdRef,
 
		[string] 
		$ComputerName = '.',

		# AccessMask Bitwise combination of COM access rights.
		[Parameter(Mandatory=$true)]
		[ComRights]
		$AccessMask = [ComRights]::Execute -bor [ComRights]::ExecuteLocal -bor [ComRights]::ActivateLocal,

		# AceFlags A bitwise combination of flags specifying inheritance and auditing.
		[System.Security.AccessControl.AceFlags]
		$AceFlags = [System.Security.AccessControl.AceFlags]::ContainerInherit -bor [System.Security.AccessControl.AceFlags]::ObjectInherit,

		# Type Access type.
		[System.Security.AccessControl.AccessControlType]
		$Type=[System.Security.AccessControl.AccessControlType]::Allow
	)
 
	#Create the Trusteee Object
	#Win32_SID Key String SID String AccountName String ReferencedDomainName
	#Associated with Win32_Account Key String Name Key String Domain
	#Win32_Trustee UInt8Array SID String SIDString
	$Trustee = ([WMIClass]('\\{0}\root\cimv2:Win32_Trustee"' -f $ComputerName)).CreateInstance()
	$Domain,$Name = $IdRef.Translate([System.Security.Principal.NTAccount]).Value.Split('\', 2)
 
	#Get the SID for the found account.
	$accountSID = [WMI]('\\{0}\root\cimv2:Win32_SID.SID=''{1}''' -f $ComputerName,$IdRef.Translate([securityidentifier]).Value)
 
	#Setup Trusteee object
	$Trustee.Domain = $Domain
	$Trustee.Name = $Name
	$Trustee.SID = $accountSID.BinaryRepresentation
 
	#Create ACE (Access Control List) object.
	$ACE = ([WMIClass]('\\{0}\root\cimv2:Win32_ACE' -f $ComputerName)).CreateInstance()
 
	#Setup the rest of the ACE.
	$ACE.AccessMask = $AccessMask
	$ACE.AceFlags = $AceFlags
	$ACE.AceType = $Type
	$ACE.Trustee = $Trustee
	$ACE
}