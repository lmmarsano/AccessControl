#
# This is a PowerShell Unit Test file.
# You need a unit test framework such as Pester to run PowerShell Unit tests. 
# You can download Pester from http://go.microsoft.com/fwlink/?LinkID=534084
#
Set-StrictMode -Version latest
#region Before All
$ModuleName = [io.path]::GetFileName($PSScriptRoot)
Import-Module "$PSScriptRoot\$ModuleName.psd1" -Scope Local -Force
$TestKeyPath = 'registry::HKEY_CURRENT_USER\SOFTWARE\Test'
$TrustedInstaller = [System.Security.Principal.NTAccount]::new('NT SERVICE','TrustedInstaller')
$Administrators = [System.Security.Principal.NTAccount]::new('BUILTIN','Administrators')
#endregion
#Before Each Context
$bec = {
	$TestKey = New-Item -Path $TestKeyPath
	$acl = $TestKey.GetAccessControl() #[System.Security.AccessControl.AccessControlSections]::None
	$acl.SetOwner($TrustedInstaller)
	$priv = Get-Privilege
	$priv0 = Get-Privilege
	$priv.Enable([Pscx.Interop.TokenPrivilege]::Restore)
	try {
		Set-Privilege -Privileges $priv
		$TestKey.SetAccessControl($acl)
	} finally {
		Set-Privilege -Privileges $priv0
	}
}
#After Each Context
$aec = {
	Remove-Item -LiteralPath $TestKeyPath
}
Describe "Invoke-AsOwner" {
	Context "Function Exists" {
		BeforeAll {
			. $bec
			$params = [string[]]::new(2)
			$retval = Invoke-AsOwner -Key $TestKey `
						-ScriptBlock {
				Param(
					[Microsoft.Win32.RegistryKey]$Key
				, [System.Security.AccessControl.RegistrySecurity]$Acl
				)
				$params[0] = $Key.ToString()
				Write-Debug -Message ('ScriptBlock Parameters:{0}' -f (Out-String -InputObject $PSBoundParameters))
			}
			Invoke-AsOwner -KeyPath $TestKeyPath `
			               -ScriptBlock {
				Param(
				  [Microsoft.Win32.RegistryKey]$Key
				, [System.Security.AccessControl.RegistrySecurity]$Acl
				)
				$params[1] = $Key.ToString()
				Write-Debug -Message ('ScriptBlock Parameters:{0}' -f (Out-String -InputObject $PSBoundParameters))
			}
			$function = Get-Command -Name Invoke-AsOwner
		}
		AfterAll {
			. $aec
		}
		It "Returns values of type System.Security.AccessControl" {
			Should -ActualValue $retval `
			       -BeOfType `
			       -ExpectedType System.Security.AccessControl.CommonObjectSecurity
		}
		It 'Returns Key''s ACL' {
			Should -ActualValue $TestKey.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All) `
			       -Be `
			       -ExpectedValue $retval.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
		}
		It 'Restores Owner' {
			Should -ActualValue $TestKey.GetAccessControl().GetOwner([System.Security.Principal.NTAccount]) `
			       -Be `
			       -ExpectedValue $TrustedInstaller
		}
		'Key','KeyPath','ScriptBlock' | % {
			$key = $_
			It ('Accepts Parameter {0}' -f $key) {
			Should -ActualValue $function.Parameters.ContainsKey($key) `
			       -Be `
			       -ExpectedValue $true
			}
		}
		It 'Treats key and its path alike' {
			Should -ActualValue $params[0] `
			       -Be `
			       -ExpectedValue $params[1]
		}
	}
	Context 'ScriptBlock' {
		BeforeAll {
			. $bec
			$oldAccess = Out-String -InputObject $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
			Invoke-AsOwner -Key $TestKey `
						-ScriptBlock {
				Param(
				  [Microsoft.Win32.RegistryKey]$Key
				, [System.Security.AccessControl.RegistrySecurity]$Acl
				)
				Write-Debug -Message ('ScriptBlock Parameters:{0}' -f (Out-String -InputObject $PSBoundParameters))
				Set-Variable -Scope 1 -Name sbparam -Value $PSBoundParameters
				Set-Variable -Scope 1 -Name tempOwner -Value $Acl.GetOwner([System.Security.Principal.NTAccount])
				$Acl.AddAccessRule(
					[System.Security.AccessControl.RegistryAccessRule]::new(
					  $Administrators #$TrustedInstaller
					, [System.Security.AccessControl.RegistryRights]::FullControl
					, [System.Security.AccessControl.AccessControlType]::Allow
					)
				)
				Write-Debug -Message ('New access rules:{0}' -f (Out-String -InputObject $Acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])))
			}
		}
		AfterAll { . $aec }
		'Key','Acl' | % {
			$key = $_
			It ('Receives {0} parameter' -f $key) {
				Should -ActualValue $sbparam.ContainsKey($key) -Be -ExpectedValue $true
			}
		}
		It 'Receives ACL with temporary owner' {
			Should -ActualValue $tempOwner `
			       -Be `
			       -ExpectedValue ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Translate([System.Security.Principal.NTAccount]))
		}
		It 'Can change object security' {
			Should -ActualValue (Out-String -InputObject $TestKey.GetAccessControl().GetAccessRules($true, $false, [System.Security.Principal.NTAccount])) `
			       -Not -Be `
			       -ExpectedValue $oldAccess
		}
	}
}
Describe 'Get-SecurityDescriptor' {
	Context 'Function' {
		BeforeAll {
			$funcInfo = Get-Command -Name Get-SecurityDescriptor
			$sd = Get-SecurityDescriptor -LiteralPath registry::HKEY_CURRENT_USER\SOFTWARE -AccessControlSections Owner
		}
		It 'Returns values of type System.Security.AccessControl.CommonObjectSecurity' {
			Should -ActualValue (($funcInfo.OutputType | % { $_.Name }) -contains 'System.Security.AccessControl.CommonObjectSecurity') `
			       -Be `
			       -ExpectedValue $true
		}
		It 'Accepts parameter AccessControlSections' {
			Should -ActualValue $funcInfo.Parameters.AccessControlSections.ParameterType `
			       -Be `
			       -ExpectedValue ([System.Security.AccessControl.AccessControlSections])
		}
		It 'Restricts sections to AccessControlSections' {
			Should -ActualValue $sd.GetGroup([System.Security.Principal.NTAccount]) `
			       -BeExactly `
			       -ExpectedValue $null
		}
	}
}
Describe 'Edit-DACL' {
	Context 'Function' {
		BeforeAll {
			$funcInfo = Get-Command -Name Edit-DACL
			$sd = [System.Security.AccessControl.RegistrySecurity]::new()
			$oldDacl = $sd.GetAccessRules($true, $false, [System.Security.Principal.NTAccount])
			$newDacl = Edit-DACL -InputObject $sd -Modification Add -Trustee $TrustedInstaller -AccessMask ([System.Security.AccessControl.RegistryRights]::FullControl) `
			| % { $_.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]) }
		}
		It 'Returns values of type System.Security.AccessControl.CommonObjectSecurity' {
			Should -ActualValue (($funcInfo.OutputType | % { $_.Name }) -contains 'System.Security.AccessControl.CommonObjectSecurity') `
			       -Be `
			       -ExpectedValue $true
		}
		@{InputObject=[System.Security.AccessControl.CommonObjectSecurity]
		  Modification=[System.Security.AccessControl.AccessControlModification]
		  AccessRule=[System.Security.AccessControl.AccessRule]
		  Trustee=[System.Security.Principal.IdentityReference]
		  AccessMask=[System.Int32]
		  IsInherited=[switch]
		  InheritanceFlags=[System.Security.AccessControl.InheritanceFlags]
		  PropagationFlags=[System.Security.AccessControl.PropagationFlags]
		  Type=[System.Security.AccessControl.AccessControlType]
		}.GetEnumerator() | % {
			$item = $_
			It ('Accepts parameter {0}' -f $item.Key) {
				Should -ActualValue $funcInfo.Parameters.($item.Key).ParameterType `
				       -Be `
				       -ExpectedValue $item.Value
			}
		}
		It 'Modifies discretionary access control list' {
			Should -ActualValue (Out-String -InputObject $newDacl) `
			       -Not -Be `
			       -ExpectedValue (Out-String -InputObject $oldDacl)
		}
	}
}
Describe 'Edit-SACL' {
	Context 'Function' {
		BeforeAll {
			$funcInfo = Get-Command -Name Edit-SACL
			$sd = [System.Security.AccessControl.RegistrySecurity]::new()
			$oldSACL = $sd.GetAuditRules($true, $false, [System.Security.Principal.NTAccount])
			$newSACL = Edit-SACL -InputObject $sd -Modification Add -Trustee $TrustedInstaller -AccessMask ([System.Security.AccessControl.RegistryRights]::FullControl) `
			| % { $_.GetAuditRules($true, $false, [System.Security.Principal.NTAccount]) }
		}
		It 'Returns values of type System.Security.AccessControl.CommonObjectSecurity' {
			Should -ActualValue (($funcInfo.OutputType | % { $_.Name }) -contains 'System.Security.AccessControl.CommonObjectSecurity') `
			       -Be `
			       -ExpectedValue $true
		}
		@{InputObject=[System.Security.AccessControl.CommonObjectSecurity]
		  Modification=[System.Security.AccessControl.AccessControlModification]
		  AuditRule=[System.Security.AccessControl.AuditRule]
		  Trustee=[System.Security.Principal.IdentityReference]
		  AccessMask=[System.Int32]
		  IsInherited=[switch]
		  InheritanceFlags=[System.Security.AccessControl.InheritanceFlags]
		  PropagationFlags=[System.Security.AccessControl.PropagationFlags]
		  AuditFlags=[System.Security.AccessControl.AuditFlags]
		}.GetEnumerator() | % {
			$item = $_
			It ('Accepts parameter {0}' -f $item.Key) {
				Should -ActualValue $funcInfo.Parameters.($item.Key).ParameterType `
				       -Be `
				       -ExpectedValue $item.Value
			}
		}
		It 'Modifies system access control list' {
			Should -ActualValue (Out-String -InputObject $newSACL) `
			       -Not -Be `
			       -ExpectedValue (Out-String -InputObject $oldSACL)
		}
	}
}
Describe 'Edit-SecurityDescriptor' {
	Context 'Function' {
		BeforeAll {
			$TestKey = New-Item -Path $TestKeyPath
			$funcInfo = Get-Command -Name Edit-SecurityDescriptor
			$self = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Translate([System.Security.Principal.NTAccount])
			$dacl = $TestKey | % { $_.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access).GetAccessRules($true,$true,[System.Security.Principal.NTAccount]) }
			$everyone = [System.Security.Principal.NTAccount]::new('Everyone')
			$sd = [System.Security.AccessControl.RegistrySecurity]::new()
			$oldDacl = $sd.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])
			$oldSacl = $sd.GetAuditRules($true,$true,[System.Security.Principal.NTAccount])
			$sd = Edit-SecurityDescriptor -InputObject $sd -Owner $self -Group $everyone -Dacl $dacl -Sacl $sd.AuditRuleFactory($self,[System.Security.AccessControl.RegistryRights]::WriteKey,$false,[System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,[System.Security.AccessControl.PropagationFlags]::None,[System.Security.AccessControl.AuditFlags]::Success)
		}
		AfterAll { . $aec }
		It 'Returns values of type System.Security.AccessControl.CommonObjectSecurity' {
			Should -ActualValue (($funcInfo.OutputType | % { $_.Name }) -contains 'System.Security.AccessControl.CommonObjectSecurity') `
			       -Be `
			       -ExpectedValue $true
		}
		@{InputObject=[System.Security.AccessControl.CommonObjectSecurity]
		  Owner=[System.Security.Principal.IdentityReference]
		  Group=[System.Security.Principal.IdentityReference]
		  Dacl=[System.Object]
		  Sacl=[System.Object]
		}.GetEnumerator() | % {
			$item = $_
			It ('Accepts parameter {0}' -f $item.Key) {
				Should -ActualValue $funcInfo.Parameters.($item.Key).ParameterType `
				       -Be `
				       -ExpectedValue $item.Value
			}
		}
		It 'Modifies owner' {
			Should -ActualValue $sd.GetOwner([System.Security.Principal.NTAccount]) `
			       -Be `
			       -ExpectedValue $self
		}
		It 'Modifies primary group' {
			Should -ActualValue $sd.GetGroup([System.Security.Principal.NTAccount]) `
			       -Be `
			       -ExpectedValue $everyone
		}
		It 'Modifies access' {
			Should -ActualValue (Out-String -InputObject $sd.GetAccessRules($true,$true,[System.Security.Principal.NTAccount])) `
			       -Not -Be `
			       -ExpectedValue (Out-String -InputObject $OldDacl)
		}
		It 'Modifies audit' {
			Should -ActualValue (Out-String -InputObject $sd.GetAuditRules($true,$true,[System.Security.Principal.NTAccount])) `
			       -Not -Be `
			       -ExpectedValue (Out-String -InputObject $OldSacl)
		}
	}
}
Describe 'Get-IdentityReference' {
	Context 'Function' {
		BeforeAll {
			$funcInfo = Get-Command -Name Get-IdentityReference
			$self = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Translate([System.Security.Principal.NTAccount])
			$default = Get-IdentityReference
			$everyone = [System.Security.Principal.NTAccount]::new('Everyone')
			$wellknown = Get-IdentityReference -WellKnownType ([System.Security.Principal.WellKnownSidType]::WorldSid)
			$nt = Get-IdentityReference -NtName 'Everyone'
			$idref = Get-IdentityReference -IdentityReference $everyone
		}
		It 'Returns values of type System.Security.Principal.IdentityReference' {
			Should -ActualValue (($funcInfo.OutputType | % { $_.Name }) -contains 'System.Security.Principal.IdentityReference') `
			       -Be `
			       -ExpectedValue $true
		}
		@{WellKnownType=[System.Security.Principal.WellKnownSidType]
		  DomainIdentifier=[System.Security.Principal.IdentityReference]
		  NtName=[System.String]
		  IdentityReference=[System.Security.Principal.IdentityReference]
		}.GetEnumerator() | % {
			$item = $_
			It ('Accepts parameter {0}' -f $item.Key) {
				Should -ActualValue $funcInfo.Parameters.($item.Key).ParameterType `
				       -Be `
				       -ExpectedValue $item.Value
			}
		}
		It 'Gets current user by default' {
			Should -ActualValue $default `
			       -Be `
			       -ExpectedValue $self
		}
		It 'Gets by well-known type' {
			Should -ActualValue $wellknown `
			       -Be `
			       -ExpectedValue $everyone
		}
		It 'Gets by NT name' {
			Should -ActualValue $nt `
			       -Be `
			       -ExpectedValue $everyone
		}
		It 'Gets by identity reference' {
			Should -ActualValue $idref `
			       -Be `
			       -ExpectedValue $everyone
		}
	}
}