$ErrorActionPreference = 'Stop'
$privatePath = $env:PM_PRIVATE_ACL_PATH
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$inheritance = [System.Security.AccessControl.InheritanceFlags]::None
if ($env:PM_PRIVATE_ACL_DIRECTORY -eq '1') {
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $inheritance = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
} else {
    $acl = [System.Security.AccessControl.FileSecurity]::new()
}
$acl.SetAccessRuleProtection($true, $false)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.SetAccessRule($rule)
# Use the Windows PowerShell .NET Framework APIs directly. A parent pwsh
# process can supply a PSModulePath whose modules cannot load in powershell.exe.
if ($env:PM_PRIVATE_ACL_DIRECTORY -eq '1') {
    [System.IO.Directory]::SetAccessControl($privatePath, $acl)
    $actual = [System.IO.Directory]::GetAccessControl($privatePath)
} else {
    [System.IO.File]::SetAccessControl($privatePath, $acl)
    $actual = [System.IO.File]::GetAccessControl($privatePath)
}
$rules = @($actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
if (-not $actual.AreAccessRulesProtected -or $rules.Count -ne 1) {
    throw 'Private ACL verification failed: unexpected access rules'
}
$actualRule = $rules[0]
if ($actualRule.IdentityReference.Value -ne $sid.Value -or
    $actualRule.IsInherited -or
    $actualRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    $actualRule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
    $actualRule.InheritanceFlags -ne $inheritance -or
    $actualRule.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
    throw 'Private ACL verification failed: unexpected principal or rights'
}
