param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'

try {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        exit 2
    }

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $ownerSid = $identity.User
    if ($null -eq $ownerSid) {
        exit 3
    }

    $isDirectory = $item.PSIsContainer
    if ($isDirectory) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $acl = New-Object System.Security.AccessControl.FileSecurity
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }

    $acl.SetOwner($ownerSid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $ownerSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
    if ($isDirectory) {
        [System.IO.Directory]::SetAccessControl($item.FullName, $acl)
        $verified = [System.IO.Directory]::GetAccessControl($item.FullName)
    } else {
        [System.IO.File]::SetAccessControl($item.FullName, $acl)
        $verified = [System.IO.File]::GetAccessControl($item.FullName)
    }
    $verifiedOwnerSid = $verified.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not $verified.AreAccessRulesProtected -or $verifiedOwnerSid -ne $ownerSid.Value) {
        exit 4
    }
    $rules = @($verified.GetAccessRules(
        $true,
        $true,
        [System.Security.Principal.SecurityIdentifier]
    ))
    if ($rules.Count -ne 1) {
        exit 5
    }

    $actual = $rules[0]
    if ($actual.IdentityReference.Value -ne $ownerSid.Value -or
        $actual.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        $actual.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl -or
        $actual.IsInherited) {
        exit 6
    }

    $expectedInheritance = if ($isDirectory) {
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [System.Security.AccessControl.InheritanceFlags]::None
    }
    if ($actual.InheritanceFlags -ne $expectedInheritance -or
        $actual.PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) {
        exit 7
    }

    [Console]::Out.WriteLine('PRIVATE')
    exit 0
} catch {
    exit 8
}
