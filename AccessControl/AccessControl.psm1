Set-StrictMode -Version latest

Enum ComAccessMask {
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
	'AccessControlSections','AllCentralAccessPolicies' | % {
		$PSBoundParameters.Remove($_)
	}
	} process {
	@(switch ($x) {
		'ByInputObject' { $InputObject }
		{$_ -in 'ByPath','ByLiteralPath'} { Get-Item @PSBoundParameters }
		Default {}
	}) | % { $_.GetAccessControl($AccessControlSections) }
	} end {
		@(switch ($x) {
			'ByInputObject' { $InputObject }
			{$_ -in 'ByPath','ByLiteralPath'} { Get-Item @PSBoundParameters }
			Default {}
		}) | % { $_.GetAccessControl($AccessControlSections) }
	}
}
<#

.ForwardHelpTargetName Microsoft.PowerShell.Security\Get-Acl
.ForwardHelpCategory Cmdlet

#>

function Set-SecurityDescriptor {
	[CmdletBinding(DefaultParameterSetName='ByPath', SupportsShouldProcess=$true, ConfirmImpact='Medium', SupportsTransactions=$true, HelpUri='http://go.microsoft.com/fwlink/?LinkID=113389')]
	param(
		[Parameter(ParameterSetName='ByPath', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
		[string[]]
		${Path},

		[Parameter(ParameterSetName='ByInputObject', Mandatory=$true, Position=0, ValueFromPipelineByPropertyName=$true)]
		[psobject]
		${InputObject},

		[Parameter(ParameterSetName='ByLiteralPath', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
		[Alias('PSPath')]
		[string[]]
		${LiteralPath},

		[Parameter(ParameterSetName='ByInputObject', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
		[Parameter(ParameterSetName='ByLiteralPath', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
		[Parameter(ParameterSetName='ByPath', Mandatory=$true, Position=1, ValueFromPipeline=$true)]
		[System.Object]
		${AclObject},

		[Parameter(ParameterSetName='ByPath', Position=2, ValueFromPipelineByPropertyName=$true)]
		[Parameter(ParameterSetName='ByLiteralPath', Position=2, ValueFromPipelineByPropertyName=$true)]
		[string]
		${CentralAccessPolicy},

		[Parameter(ParameterSetName='ByPath')]
		[Parameter(ParameterSetName='ByLiteralPath')]
		[switch]
		${ClearCentralAccessPolicy},

		[switch]
		${Passthru},

		[string]
		${Filter},

		[string[]]
		${Include},

		[string[]]
		${Exclude})

	begin
	{
		$outBuffer = $null
		if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
		{
			$PSBoundParameters['OutBuffer'] = 1
		}
		$wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Microsoft.PowerShell.Security\Set-Acl', [System.Management.Automation.CommandTypes]::Cmdlet)
		$scriptCmd = {& $wrappedCmd @PSBoundParameters }
		$steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
		$steppablePipeline.Begin($PSCmdlet)
	}

	process
	{
		$steppablePipeline.Process($_)
	}

	end
	{
		$steppablePipeline.End()
	}
}
<#

.ForwardHelpTargetName Microsoft.PowerShell.Security\Set-Acl
.ForwardHelpCategory Cmdlet

#>

<#
.Synopsis
	Returns writable registry key.
.DESCRIPTION
	Long description
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