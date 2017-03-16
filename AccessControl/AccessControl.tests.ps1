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
			$function = Get-Item -LiteralPath function:\Invoke-AsOwner
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
					  [System.Security.Principal.NTAccount]::new('BUILTIN','Administrators') #$TrustedInstaller
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